/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.runsupport

import java.io.{ PrintStream, PrintWriter, StringWriter }

import scala.util.Properties

object Logger {
  case class Level(value: Int, name: String, label: String) {
    override def toString = name
  }

  object Level {
    val Debug = Level(1, "debug", Label.debug)
    val Info = Level(2, "info", Label.info)
    val Warn = Level(3, "warn", Label.warn)
    val Error = Level(4, "error", Label.error)

    val levels = Seq(Debug, Info, Warn, Error)

    def apply(): Option[Level] = {
      val logLevel = Properties.propOrElse("play.run.log.level", "info")
      apply(logLevel)
    }
    def apply(value: Int): Option[Level] = levels find (_.value == value)
    def apply(name: String): Option[Level] = levels find (_.name == name)
  }

  object Label {
    val debug = "[debug] "
    val info = "[info] "
    val warn = "[" + Colors.yellow("warn") + "] "
    val error = "[" + Colors.red("error") + "] "
    val success = "[" + Colors.green("success") + "] "
  }

  val NewLine = sys.props("line.separator")

  def apply(): Logger = {
    new Logger(Level().getOrElse(Level.Info))
  }

  def apply(level: Level): Logger = new Logger(level)
  def apply(level: String): Logger = new Logger(Level(level).getOrElse(Level.Info))
}

class Logger(out: PrintStream, logLevel: Logger.Level) extends LoggerProxy {
  import Logger._

  def this(logLevel: Logger.Level) = this(System.out, logLevel)

  def level: Logger.Level = logLevel

  def verbose(message: => String): Unit = debug(message)
  def debug(message: => String): Unit = log(Level.Debug, message)
  def info(message: => String): Unit = log(Level.Info, message)
  def warn(message: => String): Unit = log(Level.Warn, message)
  def error(message: => String): Unit = log(Level.Error, message)

  def trace(t: => Throwable): Unit = {
    val stackTrace = new StringWriter
    t.printStackTrace(new PrintWriter(stackTrace))
    log(Level.Error, stackTrace.toString)
  }

  def success(message: => String): Unit = printLog(Label.success, message)

  def log(level: Level, message: => String): Unit = {
    if (level.value >= logLevel.value) printLog(level.label, message)
  }

  def log(level: String, message: => String): Unit = {
    for (logLevel <- Logger.Level(level)) log(logLevel, message)
  }

  def printLog(label: String, message: String, separator: String = NewLine): Unit = out.synchronized {
    for (line <- message.split(separator)) {
      out.print(label)
      out.println(line)
    }
  }

}
