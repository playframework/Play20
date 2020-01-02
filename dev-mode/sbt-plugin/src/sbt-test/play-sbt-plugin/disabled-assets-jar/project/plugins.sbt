//
// Copyright (C) Lightbend Inc. <https://www.lightbend.com>
//

updateOptions := updateOptions.value.withLatestSnapshots(false)
addSbtPlugin("com.typesafe.play" % "sbt-plugin"         % sys.props("project.version"))
addSbtPlugin("com.typesafe.play" % "sbt-scripted-tools" % sys.props("project.version"))
addSbtPlugin("com.typesafe.sbt"  % "sbt-less"           % "1.1.2")
