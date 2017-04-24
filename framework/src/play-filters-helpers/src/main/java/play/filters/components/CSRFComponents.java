/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.filters.components;

import play.components.*;
import play.filters.csrf.*;
import play.inject.Injector;

/**
 * The Java CSRF components.
 */
public interface CSRFComponents extends ConfigurationComponents,
        CryptoComponents,
        HttpConfigurationComponents,
        HttpErrorHandlerComponents,
        AkkaComponents {

    Injector injector();

    default CSRFConfig csrfConfig() {
        return CSRFConfig$.MODULE$.fromConfiguration(configuration());
    }

    default CSRF.TokenProvider csrfTokenProvider() {
        return new CSRF.TokenProviderProvider(csrfConfig(), csrfTokenSigner().asScala()).get();
    }

    default AddCSRFTokenAction addCSRFTokenAction() {
        return new AddCSRFTokenAction(
                csrfConfig(),
                sessionConfiguration(),
                csrfTokenProvider(),
                csrfTokenSigner().asScala()
        );
    }

    default RequireCSRFCheckAction requireCSRFCheckAction() {
        return new RequireCSRFCheckAction(
                csrfConfig(),
                sessionConfiguration(),
                csrfTokenProvider(),
                csrfTokenSigner().asScala(),
                injector()
        );
    }

    default CSRFErrorHandler csrfErrorHandler() {
        return new CSRFErrorHandler.DefaultCSRFErrorHandler(
                new CSRF.CSRFHttpErrorHandler(scalaHttpErrorHandler())
        );
    }

    default CSRFFilter csrfFilter() {
        return new CSRFFilter(
                csrfConfig(),
                csrfTokenSigner(),
                sessionConfiguration(),
                csrfTokenProvider(),
                csrfErrorHandler(),
                javaContextComponents(),
                materializer()
        );
    }

    // TODO do we need this?
    default CSRFCheck csrfCheck() {
        return new CSRFCheck(csrfConfig(), csrfTokenSigner().asScala(), sessionConfiguration());
    }

    // TODO do we need this?
    default CSRFAddToken csrfAddToken() {
        return new CSRFAddToken(csrfConfig(), csrfTokenSigner().asScala(), sessionConfiguration());
    }
}
