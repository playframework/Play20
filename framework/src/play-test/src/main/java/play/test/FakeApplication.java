package play.test;

import java.io.*;
import java.util.*;

import play.libs.*;

/**
 * A Fake application.
 */
public class FakeApplication {

    final play.api.test.FakeApplication wrappedApplication;

    /**
     * A Fake application.
     *
     * @param path The application path
     * @param classloader The application classloader
     * @param additionalConfiguration Additional configuration
     * @param additionalPlugins Additional plugins
     */
    public FakeApplication(File path, ClassLoader classloader, Map<String, ? extends Object> additionalConfiguration, List<String> additionalPlugins) {
        wrappedApplication = new play.api.test.FakeApplication(
                path,
                classloader,
                Scala.toSeq(additionalPlugins),
                Scala.<String>emptySeq(),
                Scala.asScala((Map<String, Object>)additionalConfiguration)
                );
    }

    public play.api.test.FakeApplication getWrappedApplication() {
        return wrappedApplication;
    }

}