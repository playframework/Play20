// Copyright (C) 2009-2013 Typesafe Inc. <http://www.typesafe.com>

logLevel := Level.Warn

addSbtPlugin("com.typesafe" % "sbt-mima-plugin" % "0.1.6")

addSbtPlugin("com.typesafe.sbt" % "sbt-scalariform" % "1.2.0")

addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "0.6.0")

libraryDependencies <+= sbtVersion { sv =>
  "org.scala-sbt" % "scripted-plugin" % sv
}

addSbtPlugin("com.github.mpeltonen" % "sbt-idea" % "1.5.2")

