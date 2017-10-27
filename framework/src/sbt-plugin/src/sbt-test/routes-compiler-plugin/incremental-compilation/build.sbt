//
// Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
//
lazy val root = (project in file("."))
  .enablePlugins(RoutesCompiler)
  .enablePlugins(MediatorWorkaroundPlugin)
  .settings(
    scalaVersion := sys.props.get("scala.version").getOrElse("2.12.4"),
    sources in (Compile, routes) := Seq(baseDirectory.value / "a.routes", baseDirectory.value / "b.routes"),
    // turn off cross paths so that expressions don't need to include the scala version
    crossPaths := false
  )
