/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.api

import javax.inject.{ Inject, Provider, Singleton }

import play.api.ApplicationLoader.DevContext
import play.api.inject.ApplicationLifecycle
import play.api.mvc.{ ControllerComponents, DefaultControllerComponents }
import play.core.{ BuildLink, SourceMapper, WebCommands }
import play.utils.Reflect

/**
 * Loads an application.  This is responsible for instantiating an application given a context.
 *
 * Application loaders are expected to instantiate all parts of an application, wiring everything together. They may
 * be manually implemented, if compile time wiring is preferred, or core/third party implementations may be used, for
 * example that provide a runtime dependency injection framework.
 *
 * During dev mode, an ApplicationLoader will be instantiated once, and called once, each time the application is
 * reloaded. In prod mode, the ApplicationLoader will be instantiated and called once when the application is started.
 *
 * Out of the box Play provides a Guice module that defines a Java and Scala default implementation based on Guice,
 * as well as various helpers like GuiceApplicationBuilder.  This can be used simply by adding the "PlayImport.guice"
 * dependency in build.sbt.
 *
 * A custom application loader can be configured using the `play.application.loader` configuration property.
 * Implementations must define a no-arg constructor.
 */
trait ApplicationLoader {

  /**
   * Load an application given the context.
   */
  def load(context: ApplicationLoader.Context): Application

}

object ApplicationLoader {

  import play.api.inject.DefaultApplicationLifecycle

  // Method to call if we cannot find a configured ApplicationLoader
  private def loaderNotFound(): Nothing = {
    sys.error("No application loader is configured. Please configure an application loader either using the " +
      "play.application.loader configuration property, or by depending on a module that configures one. " +
      "You can add the Guice support module by adding \"libraryDependencies += guice\" to your build.sbt.")
  }

  private[play] final class NoApplicationLoader extends ApplicationLoader {
    override def load(context: Context): Nothing = loaderNotFound()
  }

  /**
   * The context for loading an application.
   *
   * @param environment The environment
   * @param initialConfiguration The initial configuration.  This configuration is not necessarily the same
   *                             configuration used by the application, as the ApplicationLoader may, through it's own
   *                             mechanisms, modify it or completely ignore it.
   * @param lifecycle Used to register hooks that run when the application stops.
   * @param devContext If an application is loaded in dev mode then this additional context is available.
   */
  final case class Context(
      environment: Environment,
      initialConfiguration: Configuration,
      lifecycle: ApplicationLifecycle,
      devContext: Option[DevContext]
  ) {
    @deprecated("Use devContext.map(_.sourceMapper) instead", "2.7.0")
    def sourceMapper: Option[SourceMapper] = devContext.map(_.sourceMapper)
    @deprecated("WebCommands are no longer a property of ApplicationLoader.Context; they are available via injection or from the BuiltinComponents trait", "2.7.0")
    def webCommands: WebCommands =
      throw new UnsupportedOperationException("WebCommands are no longer a property of ApplicationLoader.Context; they are available via injection or from the BuiltinComponents trait")
  }

  /**
   * If an application is loaded in dev mode then this additional context is available. It is available as a property
   * in the `Context` object, from [[BuiltInComponents]] trait or injected via [[OptionalDevContext]].
   *
   * @param sourceMapper Information about the source files that were used to compile the application.
   * @param buildLink An interface that can be used to interact with the build system.
   */
  final case class DevContext(
      sourceMapper: SourceMapper,
      buildLink: BuildLink
  )

  object Context {

    /**
     * Create an application loading context.
     *
     * Locates and loads the necessary configuration files for the application.
     *
     * @param environment The application environment.
     * @param initialSettings The initial settings. These settings are merged with the settings from the loaded
     *                        configuration files, and together form the initialConfiguration provided by the context.  It
     *                        is intended for use in dev mode, to allow the build system to pass additional configuration
     *                        into the application.
     * @param lifecycle Used to register hooks that run when the application stops.
     * @param devContext If an application is loaded in dev mode then this additional context can be provided.
     */
    def create(
      environment: Environment,
      initialSettings: Map[String, AnyRef] = Map.empty[String, AnyRef],
      lifecycle: ApplicationLifecycle = new DefaultApplicationLifecycle(),
      devContext: Option[DevContext] = None): Context = {
      Context(
        environment = environment,
        devContext = devContext,
        lifecycle = lifecycle,
        initialConfiguration = Configuration.load(environment, initialSettings)
      )
    }

    @deprecated("Context properties have changed; use the default Context apply method or Context.create instead", "2.7.0")
    def apply(
      environment: Environment,
      sourceMapper: Option[SourceMapper],
      webCommands: WebCommands,
      initialConfiguration: Configuration,
      lifecycle: ApplicationLifecycle): Context = {
      require(sourceMapper == None, "sourceMapper parameter is no longer supported by ApplicationLoader.Context; use devContext parameter instead")
      require(webCommands == null, "webCommands parameter is no longer supported by ApplicationLoader.Context")
      Context(
        environment = environment,
        devContext = None,
        initialConfiguration = initialConfiguration,
        lifecycle = lifecycle
      )
    }
  }

  /**
   * Locate and instantiate the ApplicationLoader.
   */
  def apply(context: Context): ApplicationLoader = {
    val LoaderKey = "play.application.loader"
    if (!context.initialConfiguration.has(LoaderKey)) {
      loaderNotFound()
    }

    Reflect.configuredClass[ApplicationLoader, play.ApplicationLoader, NoApplicationLoader](
      context.environment, context.initialConfiguration, LoaderKey, classOf[NoApplicationLoader].getName
    ) match {
        case None =>
          loaderNotFound()
        case Some(Left(scalaClass)) =>
          scalaClass.getDeclaredConstructor().newInstance()
        case Some(Right(javaClass)) =>
          val javaApplicationLoader: play.ApplicationLoader = javaClass.newInstance
          // Create an adapter from a Java to a Scala ApplicationLoader. This class is
          // effectively anonymous, but let's give it a name to make debugging easier.
          class JavaApplicationLoaderAdapter extends ApplicationLoader {
            override def load(context: ApplicationLoader.Context): Application = {
              val javaContext = new play.ApplicationLoader.Context(context)
              val javaApplication = javaApplicationLoader.load(javaContext)
              javaApplication.asScala()
            }
          }
          new JavaApplicationLoaderAdapter
      }
  }

  /**
   * Create an application loading context.
   *
   * Locates and loads the necessary configuration files for the application.
   *
   * @param environment The application environment.
   * @param initialSettings The initial settings. These settings are merged with the settings from the loaded
   *                        configuration files, and together form the initialConfiguration provided by the context.  It
   *                        is intended for use in dev mode, to allow the build system to pass additional configuration
   *                        into the application.
   * @param sourceMapper An optional source mapper.
   */
  @deprecated("Context properties have changed; use the default Context apply method or Context.create instead", "2.7.0")
  def createContext(
    environment: Environment,
    initialSettings: Map[String, AnyRef] = Map.empty[String, AnyRef],
    sourceMapper: Option[SourceMapper] = None,
    webCommands: WebCommands = null,
    lifecycle: ApplicationLifecycle = new DefaultApplicationLifecycle()): Context = {
    require(sourceMapper == None, "sourceMapper parameter is no longer supported by createContext; use create method's devContext parameter instead")
    require(webCommands == null, "webCommands parameter is no longer supported by ApplicationLoader.Context")
    Context.create(
      environment = environment,
      initialSettings = initialSettings,
      lifecycle = lifecycle
    )
  }

}

/**
 * Helper that provides all the built in components dependencies from the application loader context
 */
abstract class BuiltInComponentsFromContext(context: ApplicationLoader.Context) extends BuiltInComponents {
  override def environment: Environment = context.environment
  override def devContext: Option[DevContext] = context.devContext
  override def applicationLifecycle: ApplicationLifecycle = context.lifecycle
  override def configuration: Configuration = context.initialConfiguration

  lazy val controllerComponents: ControllerComponents = DefaultControllerComponents(
    defaultActionBuilder, playBodyParsers, messagesApi, langs, fileMimeTypes, executionContext
  )
}

/**
 * Represents an `Option[DevContext]` so that it can be used for dependency
 * injection. We can't easily use a plain `Option[DevContext]` since Java
 * erases the type parameter of that type.
 */
final class OptionalDevContext(val devContext: Option[DevContext])

/**
 * Represents an `Option[SourceMapper]` so that it can be used for dependency
 * injection. We can't easily use a plain `Option[SourceMapper]` since Java
 * erases the type parameter of that type.
 */
final class OptionalSourceMapper(val sourceMapper: Option[SourceMapper])

@Singleton
final class OptionalSourceMapperProvider @Inject() (optDevContext: OptionalDevContext) extends Provider[OptionalSourceMapper] {
  val get = new OptionalSourceMapper(optDevContext.devContext.map(_.sourceMapper))
}