//
// Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
//

lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .enablePlugins(MediatorWorkaroundPlugin)

libraryDependencies += guice

scalaVersion := Option(System.getProperty("scala.version")).getOrElse("2.12.3")

PlayKeys.playInteractionMode := play.sbt.StaticPlayNonBlockingInteractionMode

// Start by using the sbt watcher
// use an hardcoded value to avoid compatibility problems
// between sbt 1.0 and 0.13.
PlayKeys.fileWatchService := play.dev.filewatch.FileWatchService.polling(500)

TaskKey[Unit]("resetReloads") := {
  (target.value / "reload.log").delete()
}

InputKey[Unit]("verifyReloads") := {
  val expected = Def.spaceDelimited().parsed.head.toInt
  val actual = IO.readLines(target.value / "reload.log").count(_.nonEmpty)
  if (expected == actual) {
    println(s"Expected and got $expected reloads")
  } else {
    throw new RuntimeException(s"Expected $expected reloads but got $actual")
  }
}

InputKey[Unit]("verifyResourceContains") := {
  val args = Def.spaceDelimited("<path> <status> <words> ...").parsed
  val path = args.head
  val status = args.tail.head.toInt
  val assertions = args.tail.tail
  DevModeBuild.verifyResourceContains(path, status, assertions, 0)
}
