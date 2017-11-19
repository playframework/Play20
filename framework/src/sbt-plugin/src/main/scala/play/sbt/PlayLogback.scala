/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.sbt

import sbt.Keys._
import sbt._

/**
 * This plugin enables Play Logback
 */
object PlayLogback extends AutoPlugin {
  override def requires = PlayService

  // add this plugin automatically if Play is added.
  override def trigger = AllRequirements

  override def projectSettings = Seq(
    libraryDependencies ++= {
      Seq("com.typesafe.play" %% "play-logback" % play.core.PlayVersion.current)
    }
  )
}
