import sbt._

object Common {

  /** Invokes an external process and returns the stdout produced by that process.
    */
  def runProcess(command: String): String =
    sbt.Process("jps").!!

}