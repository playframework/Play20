package play.core

import java.io._
import scala.concurrent.Await
import scala.concurrent.duration._

import play.api._
import play.api.mvc._
import scala.util.control.NonFatal
import system.DocumentationHandler

/**
 * provides source code to be displayed on error pages
 */
trait SourceMapper {

  def sourceOf(className: String, line: Option[Int] = None): Option[(File, Option[Int])]

  def sourceFor(e: Throwable): Option[(File, Option[Int])] = {
    e.getStackTrace.find(element => sourceOf(element.getClassName).isDefined).flatMap { interestingStackTrace =>
      sourceOf(interestingStackTrace.getClassName, Option(interestingStackTrace.getLineNumber))
    }
  }

}

trait DevSettings {
  def devSettings: Map[String, String]
}

/**
 * generic layout for initialized Applications
 */
trait ApplicationProvider {
  def path: File
  def get: Either[Throwable, Application]
  def handleWebCommand(requestHeader: play.api.mvc.RequestHeader): Option[SimpleResult] = None
}

trait HandleWebCommandSupport {
  def handleWebCommand(request: play.api.mvc.RequestHeader, sbtLink: play.core.SBTLink, path: java.io.File): Option[SimpleResult]
}

/**
 * creates and initializes an Application
 * @param applicationPath location of an Application
 */
class StaticApplication(applicationPath: File) extends ApplicationProvider {

  val application = new DefaultApplication(applicationPath, this.getClass.getClassLoader, None, Mode.Prod)

  Play.start(application)

  def get = Right(application)
  def path = applicationPath
}

/**
 * wraps and starts a fake application (used in tests)
 * @param application fake Application
 */
class TestApplication(application: Application) extends ApplicationProvider {

  Play.start(application)

  def get = Right(application)
  def path = application.path
}

/**
 * represents an application that can be reloaded in Dev Mode
 */
class ReloadableApplication(sbtLink: SBTLink) extends ApplicationProvider {

  // Use plain Java call here in case of scala classloader mess
  {
    if (System.getProperty("play.debug.classpath") == "true") {
      System.out.println("\n---- Current ClassLoader ----\n")
      System.out.println(this.getClass.getClassLoader)
      System.out.println("\n---- The where is Scala? test ----\n")
      System.out.println(this.getClass.getClassLoader.getResource("scala/Predef$.class"))
    }
  }

  lazy val path = sbtLink.projectPath
  private lazy val documentationHandler = new DocumentationHandler(sbtLink.markdownToHtml _)

  println(play.utils.Colors.magenta("--- (Running the application from SBT, auto-reloading is enabled) ---"))
  println()

  var lastState: Either[Throwable, Application] = Left(new PlayException("Not initialized", "?"))

  def get = {

    synchronized {

      // Let's load the application on another thread
      // as we are now on the Netty IO thread.
      //
      // Because we are on DEV mode here, it doesn't really matter
      // but it's more coherent with the way it works in PROD mode.
      implicit val ec = play.core.Execution.internalContext
      Await.result(scala.concurrent.Future {

        val reloaded = sbtLink.reload match {
          case t: Throwable => Left(t)
          case cl: ClassLoader => Right(Some(cl))
          case null => Right(None)
        }

        reloaded.right.flatMap { maybeClassLoader =>

          val maybeApplication: Option[Either[Throwable, Application]] = maybeClassLoader.map { projectClassloader =>
            try {

              if (lastState.isRight) {
                println()
                println(play.utils.Colors.magenta("--- (RELOAD) ---"))
                println()
              }

              val reloadable = this

              // First, stop the old application if it exists
              Play.stop()

              val newApplication = new DefaultApplication(reloadable.path, projectClassloader, Some(new SourceMapper {
                def sourceOf(className: String, line: Option[Int]) = {
                  Option(sbtLink.findSource(className, line.map(_.asInstanceOf[java.lang.Integer]).orNull)).flatMap {
                    case Array(file: java.io.File, null) => Some((file, None))
                    case Array(file: java.io.File, line: java.lang.Integer) => Some((file, Some(line)))
                    case _ => None
                  }
                }
              }), Mode.Dev) with DevSettings {
                import scala.collection.JavaConverters._
                lazy val devSettings: Map[String, String] = sbtLink.settings.asScala.toMap
              }

              Play.start(newApplication)

              Right(newApplication)
            } catch {
              case e: PlayException => {
                lastState = Left(e)
                lastState
              }
              case NonFatal(e) => {
                lastState = Left(UnexpectedException(unexpected = Some(e)))
                lastState
              }
              case e: LinkageError => {
                lastState = Left(UnexpectedException(unexpected = Some(e)))
                lastState
              }
            }
          }

          maybeApplication.flatMap(_.right.toOption).foreach { app =>
            lastState = Right(app)
          }

          maybeApplication.getOrElse(lastState)
        }

      }, Duration.Inf)
    }
  }

  override def handleWebCommand(request: play.api.mvc.RequestHeader): Option[SimpleResult] = {

    documentationHandler.maybeHandleDocumentationRequest(request).orElse(
      for {
        app <- Play.maybeApplication
        result <- app.plugins.foldLeft(Option.empty[SimpleResult]) {
          case (None, plugin: HandleWebCommandSupport) => plugin.handleWebCommand(request, sbtLink, path)
          case (result, _) => result
        }
      } yield result
    )

  }
}

