name := "play-scala-intro"

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion in ThisBuild := "%SCALA_VERSION%"

libraryDependencies ++= Seq(
  guice,
  "com.typesafe.play" %% "play-slick" % "%PLAY_SLICK_VERSION%",
  "com.typesafe.play" %% "play-slick-evolutions" % "%PLAY_SLICK_VERSION%",
  "com.h2database" % "h2" % "1.4.191",
  "org.scalatestplus.play" %% "scalatestplus-play" % "%SCALATESTPLUS_PLAY_VERSION%" % Test
)

