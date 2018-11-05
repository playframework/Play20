/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import com.typesafe.config.Config;
import play.api.inject.DefaultApplicationLifecycle;
import play.core.BuildLink;
import play.core.SourceMapper;
import play.core.DefaultWebCommands;
import play.inject.ApplicationLifecycle;
import play.libs.Scala;
import scala.compat.java8.OptionConverters;

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
 * Out of the box Play provides a Java and Scala default implementation based on Guice. The Java implementation is the
 * {@link play.inject.guice.GuiceApplicationLoader} and the Scala implementation is {@link play.api.inject.guice.GuiceApplicationLoader}.
 *
 * A custom application loader can be configured using the `play.application.loader` configuration property.
 * Implementations must define a no-arg constructor.
 */
public interface ApplicationLoader {

    static ApplicationLoader apply(Context context) {
        final play.api.ApplicationLoader loader = play.api.ApplicationLoader$.MODULE$.apply(context.asScala());
        return new ApplicationLoader() {
            @Override
            public Application load(Context context) {
                return loader.load(context.asScala()).asJava();
            }
        };
    }

    /**
     * Load an application given the context.
     *
     * @param context the context the apps hould be loaded into
     * @return the loaded application
     */
    Application load(ApplicationLoader.Context context);

    /**
     * The context for loading an application.
     */
    final class Context {

        private final play.api.ApplicationLoader.Context underlying;

        /**
         * The context for loading an application.
         *
         * @param underlying The Scala context that is being wrapped.
         */
        public Context(play.api.ApplicationLoader.Context underlying) {
            this.underlying = underlying;
        }

        /**
         * The context for loading an application.
         *
         * @param environment the application environment
         */
        public Context(Environment environment) {
            this(environment, new HashMap<>());
        }

        /**
         * The context for loading an application.
         *
         * @param environment     the application environment
         * @param initialSettings the initial settings. These settings are merged with the settings from the loaded
         *                        configuration files, and together form the initialConfiguration provided by the context.  It
         *                        is intended for use in dev mode, to allow the build system to pass additional configuration
         *                        into the application.
         */
        public Context(Environment environment, Map<String, Object> initialSettings) {
            this.underlying = new play.api.ApplicationLoader.Context(
                    environment.asScala(),
                    play.api.Configuration.load(environment.asScala(),
                    play.libs.Scala.asScala(initialSettings)),
                    new DefaultApplicationLifecycle(),
                    scala.Option.empty());
        }

        /**
         * Get the wrapped Scala context.
         *
         * @return the wrapped scala context
         */
        public play.api.ApplicationLoader.Context asScala() {
            return underlying;
        }

        /**
         * Get the environment from the context.
         *
         * @return the environment
         */
        public Environment environment() {
            return new Environment(underlying.environment());
        }

        /**
         * Get the configuration from the context. This configuration is not necessarily the same
         * configuration used by the application, as the ApplicationLoader may, through it's own
         * mechanisms, modify it or completely ignore it.
         *
         * @return the initial configuration
         */
        public Config initialConfig() {
            return underlying.initialConfiguration().underlying();
        }

        /**
         * Get the application lifecycle from the context.
         *
         * @return the application lifecycle
         */
        public ApplicationLifecycle applicationLifecycle() {
           return underlying.lifecycle().asJava();
        }

        /**
         * If an application is loaded in dev mode then this additional context is available.
         *
         * @return optional with the value if the application is running in dev mode or empty otherwise.
         */
        public Optional<play.api.ApplicationLoader.DevContext> devContext() {
            return OptionConverters.toJava(underlying.devContext());
        }

        /**
         * Get the source mapper from the context.
         *
         * @return an optional source mapper
         *
         * @deprecated Deprecated as of 2.7.0. Access it using {@link #devContext()}.
         */
        @Deprecated
        public Optional<SourceMapper> sourceMapper() {
            return devContext().map(play.api.ApplicationLoader.DevContext::sourceMapper);
        }

        /**
         * Create a new context with a different environment.
         *
         * @param environment the environment this context should use
         * @return a context using the specified environment
         */
        public Context withEnvironment(Environment environment) {
            play.api.ApplicationLoader.Context scalaContext = new play.api.ApplicationLoader.Context(
                    environment.asScala(),
                    underlying.initialConfiguration(),
                    new DefaultApplicationLifecycle(),
                    underlying.devContext());
            return new Context(scalaContext);
        }

        /**
         * Create a new context with a different configuration.
         *
         * @param initialConfiguration the configuration to use in the created context
         * @return the created context
         */
        public Context withConfig(Config initialConfiguration) {
            play.api.ApplicationLoader.Context scalaContext = new play.api.ApplicationLoader.Context(
                    underlying.environment(),
                    new play.api.Configuration(initialConfiguration),
                    new DefaultApplicationLifecycle(),
                    underlying.devContext());
            return new Context(scalaContext);
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
     * @return the created context
     */
    static Context create(Environment environment, Map<String, Object> initialSettings) {
        play.api.ApplicationLoader.Context scalaContext = play.api.ApplicationLoader.Context$.MODULE$.create(
                environment.asScala(),
                Scala.asScala(initialSettings),
                new DefaultApplicationLifecycle(),
                Scala.<play.api.ApplicationLoader.DevContext>None());
        return new Context(scalaContext);
    }

    /**
     * Create an application loading context.
     *
     * Locates and loads the necessary configuration files for the application.
     *
     * @param environment The application environment.
     * @return a context created with the provided underlying environment
     */
    static Context create(Environment environment) {
        return create(environment, Collections.emptyMap());
    }

}
