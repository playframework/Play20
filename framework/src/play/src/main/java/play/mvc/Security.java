/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.mvc;

import play.inject.Injector;
import play.libs.typedmap.TypedKey;
import play.mvc.Http.Context;
import play.mvc.Http.Request;

import javax.inject.Inject;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

/**
 * Defines several security helpers.
 */
public class Security {

    public static final TypedKey<String> USERNAME = TypedKey.create("username");

    /**
     * Wraps the annotated action in an {@link AuthenticatedAction}.
     */
    @With(AuthenticatedAction.class)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface Authenticated {
        Class<? extends Authenticator> value() default Authenticator.class;
    }

    /**
     * Wraps another action, allowing only authenticated HTTP requests.
     * <p>
     * The user name is retrieved from the session cookie, and added to the HTTP request's
     * <code>username</code> attribute.
     */
    public static class AuthenticatedAction extends Action<Authenticated> {

        private final Function<Authenticated, Authenticator> configurator;

        @Inject
        public AuthenticatedAction(Injector injector) {
            this(authenticated -> injector.instanceOf(authenticated.value()));
        }

        public AuthenticatedAction(Authenticator authenticator) {
            this(authenticated -> authenticator);
        }

        public AuthenticatedAction(Function<Authenticated, Authenticator> configurator) {
            this.configurator = configurator;
        }

        public CompletionStage<Result> call(final Context ctx) {
            Authenticator authenticator = configurator.apply(configuration);
            String username = authenticator.getUsername(ctx);
            if (username == null) {
                Result unauthorized = authenticator.onUnauthorized(ctx);
                return CompletableFuture.completedFuture(unauthorized);
            } else {
                Request usernameReq = ctx.request().addAttr(USERNAME, username);
                Context usernameCtx = ctx.withRequest(usernameReq);
                return delegate.call(usernameCtx);
            }
        }

    }

    /**
     * Handles authentication.
     */
    public static class Authenticator extends Results {

        /**
         * Retrieves the username from the HTTP context; the default is to read from the session cookie.
         *
         * @param ctx the current request context
         * @return null if the user is not authenticated.
         */
        public String getUsername(Context ctx) {
            return ctx.session().get("username");
        }

        /**
         * Generates an alternative result if the user is not authenticated; the default a simple '401 Not Authorized' page.
         *
         * @param ctx the current request context
         * @return a <code>401 Not Authorized</code> result
         */
        public Result onUnauthorized(Context ctx) {
            return unauthorized(views.html.defaultpages.unauthorized.render());
        }

    }


}
