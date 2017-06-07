/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

import com.typesafe.config.Config;
import play.inject.Injector;
import play.libs.Scala;

/**
 * A Play application.
 * <p>
 * Application creation is handled by the framework engine.
 */
public interface Application {

    /**
     * Get the underlying Scala application.
     *
     * @return the application
     * @see Application#asScala() method
     */
    play.api.Application getWrappedApplication();

    /**
     * Get the application as a Scala application.
     *
     * @return this application as a Scala application.
     * @see play.api.Application
     */
    play.api.Application asScala();

    /**
     * Get the application configuration.
     *
     * @return the configuration
     */
    @Deprecated
    default Configuration configuration() {
        return new Configuration(this.config());
    }

    /**
     * Get the application configuration.
     *
     * @return the configuration
     */
    Config config();

    /**
     * Get the runtime injector for this application. In a runtime dependency injection based application, this can be
     * used to obtain components as bound by the DI framework.
     *
     * @return the injector
     */
    Injector injector();

    /**
     * Get the application path.
     *
     * @return the application path
     */
    default File path() {
        return getWrappedApplication().path();
    }

    /**
     * Get the application classloader.
     *
     * @return the application classloader
     */
    default ClassLoader classloader() {
        return getWrappedApplication().classloader();
    }

    /**
     * Get a file relative to the application root path.
     *
     * @param relativePath relative path of the file to fetch
     * @return a file instance - it is not guaranteed that the file exists
     * @deprecated Deprecated as in 2.6.0. Use {@link Environment#getFile} instead.
     */
    @Deprecated
    default File getFile(String relativePath) {
        return getWrappedApplication().getFile(relativePath);
    }

    /**
     * Get a resource from the classpath.
     *
     * @param relativePath relative path of the resource to fetch
     * @return URL to the resource (may be null)
     * @deprecated Deprecated as in 2.6.0. Use {@link Environment#resource(String)} instead.
     */
    @Deprecated
    default URL resource(String relativePath) {
        return Scala.orNull(getWrappedApplication().resource(relativePath));
    }

    /**
     * Get a resource stream from the classpath.
     *
     * @param relativePath relative path of the resource to fetch
     * @return InputStream to the resource (may be null)
     * @deprecated Deprecated as in 2.6.0. Use{@link Environment#resourceAsStream(String)} instead.
     */
    @Deprecated
    default InputStream resourceAsStream(String relativePath) {
        return Scala.orNull(getWrappedApplication().resourceAsStream(relativePath));
    }

    /**
     * Check whether the application is in {@link Mode#DEV} mode.
     *
     * @return true if the application is in DEV mode
     */
    default boolean isDev() {
        return getWrappedApplication().isDev();
    }

    /**
     * Check whether the application is in {@link Mode#PROD} mode.
     *
     * @return true if the application is in PROD mode
     */
    default boolean isProd() {
        return getWrappedApplication().isProd();
    }

    /**
     * Check whether the application is in {@link Mode#TEST} mode.
     *
     * @return true if the application is in TEST mode
     */
    default boolean isTest() {
        return getWrappedApplication().isTest();
    }

}
