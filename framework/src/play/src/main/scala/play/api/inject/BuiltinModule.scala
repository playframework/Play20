/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.api.inject

import java.util.concurrent.Executor

import akka.actor.ActorSystem
import javax.inject.{ Singleton, Inject, Provider }
import akka.stream.Materializer
import play.api._
import play.api.http._
import play.api.libs.Files.{ DefaultTemporaryFileCreator, TemporaryFileCreator }
import play.api.libs.{ CryptoConfig, Crypto, CryptoConfigParser }
import play.api.libs.concurrent.{ MaterializerProvider, ExecutionContextProvider, ActorSystemProvider }
import play.api.routing.Router
import play.libs.concurrent.HttpExecutionContext

import scala.concurrent.ExecutionContext

/**
 * The Play BuiltinModule.
 *
 * Provides all the core components of a Play application. This is typically automatically enabled by Play for an
 * application.
 */
class BuiltinModule extends Module {
  def bindings(env: Environment, configuration: Configuration): Seq[Binding[_]] = {
    def dynamicBindings(factories: ((Environment, Configuration) => Seq[Binding[_]])*) = {
      factories.flatMap(_(env, configuration))
    }

    Seq(
      bind[Environment] to env,
      bind[ConfigurationProvider].to(new ConfigurationProvider(configuration)),
      bind[Configuration].toProvider[ConfigurationProvider],
      bind[HttpConfiguration].toProvider[HttpConfiguration.HttpConfigurationProvider],

      // Application lifecycle, bound both to the interface, and its implementation, so that Application can access it
      // to shut it down.
      bind[DefaultApplicationLifecycle].toSelf,
      bind[ApplicationLifecycle].to(bind[DefaultApplicationLifecycle]),

      bind[Application].to[DefaultApplication],
      bind[play.Application].to[play.DefaultApplication],

      bind[Router].toProvider[RoutesProvider],
      bind[ActorSystem].toProvider[ActorSystemProvider],
      bind[Materializer].toProvider[MaterializerProvider],
      bind[ExecutionContext].toProvider[ExecutionContextProvider],
      bind[Executor].toProvider[ExecutionContextProvider],
      bind[HttpExecutionContext].toSelf,
      bind[Plugins].toProvider[PluginsProvider],

      bind[CryptoConfig].toProvider[CryptoConfigParser],
      bind[Crypto].toSelf,
      bind[TemporaryFileCreator].to[DefaultTemporaryFileCreator]
    ) ++ dynamicBindings(
        HttpErrorHandler.bindingsFromConfiguration,
        HttpFilters.bindingsFromConfiguration,
        HttpRequestHandler.bindingsFromConfiguration
      )
  }
}

// This allows us to access the original configuration via this
// provider while overriding the binding for Configuration itself.
class ConfigurationProvider(val get: Configuration) extends Provider[Configuration]

@Singleton
class RoutesProvider @Inject() (injector: Injector, environment: Environment, configuration: Configuration, httpConfig: HttpConfiguration) extends Provider[Router] {
  lazy val get = {
    val prefix = httpConfig.context

    val router = Router.load(environment, configuration)
      .fold[Router](Router.empty)(injector.instanceOf(_))
    router.withPrefix(prefix)
  }
}

@Singleton
class PluginsProvider @Inject() (environment: Environment, injector: Injector) extends Provider[Plugins] {
  lazy val get = Plugins(environment, injector)
}
