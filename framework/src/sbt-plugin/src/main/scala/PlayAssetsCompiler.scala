package sbt

import Keys._
import PlayKeys._
import PlayExceptions._
import play.api.PlayException

// ----- Assets
trait PlayAssetsCompiler {

  // Name: name of the compiler
  // files: the function to find files to compile from the assets directory
  // naming: how to name the generated file from the original file and whether it should be minified or not
  // compile: compile the file and return the compiled sources, the minified source (if relevant) and the list of dependencies
  def AssetsCompiler(name: String,
    watch: File => PathFinder,
    filesSetting: sbt.SettingKey[PathFinder],
    naming: (String, Boolean) => String,
    compile: (File, Seq[String]) => (String, Option[String], Option[String], Seq[File]),
    optionsSettings: sbt.SettingKey[Seq[String]]) =
    (state, sourceDirectory in Compile, resourceManaged in Compile, cacheDirectory, optionsSettings, filesSetting, requireJs) map { (state, src, resources, cache, options, files, requireJs) =>

      val requireSupport = if (!requireJs.isEmpty) {
        Seq("rjs")
      } else Seq[String]()

      import java.io._

      val cacheFile = cache / name
      val currentInfos = watch(src).get.map(f => f -> FileInfo.lastModified(f)).toMap

      val (previousRelation, previousInfo) = Sync.readInfo(cacheFile)(FileInfo.lastModified.format)

      if (previousInfo != currentInfos) {

        //a changed file can be either a new file, a deleted file or a modified one
        lazy val changedFiles: Seq[File] = currentInfos.filter(e => !previousInfo.get(e._1).isDefined || previousInfo(e._1).lastModified < e._2.lastModified).map(_._1).toSeq ++ previousInfo.filter(e => !currentInfos.get(e._1).isDefined).map(_._1).toSeq

        //erease dependencies that belong to changed files
        val dependencies = previousRelation.filter((original, compiled) => changedFiles.contains(original))._2s
        dependencies.foreach(IO.delete)

        /**
         * If the given file was changed or
         * if the given file was a dependency,
         * otherwise calculate dependencies based on previous relation graph
         */
        val generated: Seq[(File, java.io.File)] = (files x relativeTo(Seq(src / "assets"))).flatMap {
          case (sourceFile, name) => {
            if (changedFiles.contains(sourceFile) || dependencies.contains(new File(resources, "public/" + naming(name, false)))) {
              val (debug, min, sourceMap, dependencies) = try {
                compile(sourceFile, options ++ requireSupport)
              } catch {
                case e: AssetCompilationException => throw PlaySourceGenerators.reportCompilationError(state, e)
              }

              val out = new File(resources, "public/" + naming(name, false))
              IO.write(out, debug)

              (dependencies ++ Seq(sourceFile)).toSet[File].map(_ -> out) ++ min.map { minified =>
                val outMin = new File(resources, "public/" + naming(name, true))
                IO.write(outMin, minified)
                (dependencies ++ Seq(sourceFile)).map(_ -> outMin)
              }.getOrElse(Nil) ++ sourceMap.map { map =>
                val nameAsFile = new File(name)
                val nameParent = Option(nameAsFile.getParent) getOrElse ""
                val (nameBase, nameExt) = IO.split(nameAsFile.getName)

                // copy dependencies
                val dependencyOutputFiles =
                  dependencies.map { d =>
                    val out = new File(resources, "public/" + nameParent + "/" + d.getName)
                    IO.copyFile(d, out, false)
                    out
                  }

                // write map file
                val outMap = new File(resources, "public/" + nameParent + "/" + nameBase + ".map")
                IO.write(outMap, map)

                (dependencyOutputFiles ++ Seq(outMap)).map { file =>
                  (dependencies ++ Seq(sourceFile)).toSet[File].map(_ -> file)
                }.flatten
              }.getOrElse(Nil)
            } else {
              previousRelation.filter((original, compiled) => original == sourceFile)._2s.map(sourceFile -> _)
            }
          }
        }

        //write object graph to cache file 
        Sync.writeInfo(cacheFile,
          Relation.empty[File, File] ++ generated,
          currentInfos)(FileInfo.lastModified.format)

        // Return new files
        generated.map(_._2).distinct.toList

      } else {
        // Return previously generated files
        previousRelation._2s.toSeq
      }

    }

  val LessCompiler = AssetsCompiler("less",
    (_ ** "*.less"),
    lessEntryPoints,
    { (name, min) => name.replace(".less", if (min) ".min.css" else ".css") },
    { (lessFile, options) =>
      val (debug, min, dependencies) = play.core.less.LessCompiler.compile(lessFile)
      (debug, min, None, dependencies)
    },
    lessOptions
  )

  def JavascriptCompiler(fullCompilerOptions: Option[com.google.javascript.jscomp.CompilerOptions]) = AssetsCompiler("javascripts",
    (_ ** "*.js"),
    javascriptEntryPoints,
    { (name, min) => name.replace(".js", if (min) ".min.js" else ".js") },
    { (jsFile: File, simpleCompilerOptions) =>
      val (debug, min, dependencies) = play.core.jscompile.JavascriptCompiler.compile(jsFile, simpleCompilerOptions, fullCompilerOptions)
      (debug, min, None, dependencies)
    },
    closureCompilerOptions
  )

  val CoffeescriptCompiler = AssetsCompiler("coffeescript",
    (_ ** "*.coffee"),
    coffeescriptEntryPoints,
    { (name, min) => name.replace(".coffee", if (min) ".min.js" else ".js") },
    { (coffeeFile, options) =>
      import scala.util.control.Exception._
      val (jsSource, sourceMapOption) = play.core.coffeescript.CoffeescriptCompiler.compile(coffeeFile, options)
      val (nameBase, nameExt) = IO.split(coffeeFile.getName)
      // Any error here would be because of CoffeeScript, not the developer;
      // so we don't want compilation to fail.
      val minified = catching(classOf[CompilationException]).opt(play.core.jscompile.JavascriptCompiler.minify(jsSource, Some(coffeeFile.getName())))
      // sourceMappingURL annotation should be added because CoffeeScript add it only when writing js file
      val (enhancedJsSource, enhancedMinified) =
        if (sourceMapOption.isDefined) {
          def enhance(s: String) = s + "\n" + "/*\n//@ sourceMappingURL=" + nameBase + ".map" + "\n*/\n"
          (enhance(jsSource), minified.map(enhance))
        } else (jsSource, minified)
      (enhancedJsSource, enhancedMinified, sourceMapOption, Seq(coffeeFile))
    },
    coffeescriptOptions
  )

}
