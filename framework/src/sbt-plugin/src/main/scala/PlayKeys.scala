package sbt

trait PlayKeys {

  val jdbc = "com.typesafe.play" %% "play-jdbc" % play.core.PlayVersion.current

  val anorm = "com.typesafe.play" %% "anorm" % play.core.PlayVersion.current

  val javaCore = "com.typesafe.play" %% "play-java" % play.core.PlayVersion.current

  val javaJdbc = "com.typesafe.play" %% "play-java-jdbc" % play.core.PlayVersion.current

  val javaEbean = "com.typesafe.play" %% "play-java-ebean" % play.core.PlayVersion.current

  val javaJpa = "com.typesafe.play" %% "play-java-jpa" % play.core.PlayVersion.current

  def component(id: String) = "com.typesafe.play" %% id % play.core.PlayVersion.current

  val filters = "com.typesafe.play" %% "filters-helpers" % play.core.PlayVersion.current

  val playVersion = SettingKey[String]("play-version")

  val playDefaultPort = SettingKey[Int]("play-default-port")

  val requireJs = SettingKey[Seq[String]]("play-require-js")

  val requireJsFolder = SettingKey[String]("play-require-js-folder")

  val requireJsShim = SettingKey[String]("play-require-js-shim")

  val requireNativePath = SettingKey[Option[String]]("play-require-native-path")

  val playOnStarted = SettingKey[Seq[(java.net.InetSocketAddress) => Unit]]("play-onStarted")

  val playOnStopped = SettingKey[Seq[() => Unit]]("play-onStopped")

  val distDirectory = SettingKey[File]("play-dist")

  val distExcludes = SettingKey[Seq[String]]("dist-excludes")

  val playAssetsDirectories = SettingKey[Seq[File]]("play-assets-directories")

  val playExternalAssets = SettingKey[Seq[(File, File => PathFinder, String)]]("play-external-assets")

  val confDirectory = SettingKey[File]("play-conf")

  val templatesImport = SettingKey[Seq[String]]("play-templates-imports")

  val routesImport = SettingKey[Seq[String]]("play-routes-imports")

  val generateReverseRouter = SettingKey[Boolean]("play-generate-reverse-router",
    "Whether the reverse router should be generated. Setting to false may reduce compile times if it's not needed.")

  val namespaceReverseRouter = SettingKey[Boolean]("play-namespace-reverse-router",
    "Whether the reverse router should be namespaced. Useful if you have many routers that use the same actions.")

  val ebeanEnabled = SettingKey[Boolean]("play-ebean-enabled")

  val templatesTypes = SettingKey[Map[String, String]]("play-templates-formats")

  val closureCompilerOptions = SettingKey[Seq[String]]("play-closure-compiler-options")

  val lessOptions = SettingKey[Seq[String]]("play-less-options")

  val coffeescriptOptions = SettingKey[Seq[String]]("play-coffeescript-options")

  val lessEntryPoints = SettingKey[PathFinder]("play-less-entry-points")

  val coffeescriptEntryPoints = SettingKey[PathFinder]("play-coffeescript-entry-points")

  val javascriptEntryPoints = SettingKey[PathFinder]("play-javascript-entry-points")

  val playPlugin = SettingKey[Boolean]("play-plugin")

  val devSettings = SettingKey[Seq[(String, String)]]("play-dev-settings")

  val scalaIdePlay2Prefs = TaskKey[Unit]("scala-ide-play2-prefs")

  // Constants that may be useful elsewhere
  val defaultJavaTemplatesImport = Seq(
    "models._",
    "controllers._",

    "java.lang._",
    "java.util._",

    "scala.collection.JavaConversions._",
    "scala.collection.JavaConverters._",

    "play.api.i18n._",
    "play.core.j.PlayMagicForJava._",

    "play.mvc._",
    "play.data._",
    "play.api.data.Field",

    "play.mvc.Http.Context.Implicit._",

    "views.%format%._")

  val defaultScalaTemplatesImport = Seq(
    "models._",
    "controllers._",

    "play.api.i18n._",

    "play.api.mvc._",
    "play.api.data._",

    "views.%format%._")

  val defaultTemplatesImport = Seq("play.api.templates._", "play.api.templates.PlayMagic._")

}
object PlayKeys extends PlayKeys

trait PlayInternalKeys {
  val playCommonClassloader = TaskKey[ClassLoader]("play-common-classloader")
  val playReload = TaskKey[sbt.inc.Analysis]("play-reload")
  val buildRequire = TaskKey[Seq[(File, File)]]("play-build-require-assets")
  val playCompileEverything = TaskKey[Seq[sbt.inc.Analysis]]("play-compile-everything")
  val playPackageEverything = TaskKey[Seq[File]]("play-package-everything")
}
