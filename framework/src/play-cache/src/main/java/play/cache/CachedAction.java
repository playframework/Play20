/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.cache;

import play.libs.F;
import play.mvc.*;
import play.mvc.Http.*;

import java.util.concurrent.CompletionStage;

/**
 * Cache another action.
 */
public class CachedAction extends Action<Cached> {

    public CompletionStage<Result> call(Context ctx) {
        try {
            final String key = configuration.key();
            final Integer duration = configuration.duration();

            Result cacheResult = (Result) Cache.get(key);

            if (cacheResult == null) {
                return delegate.call(ctx).thenApply(result -> {
                    Cache.set(key, result, duration);
                    return result;
                });
            } else {
                return F.Promise.pure(cacheResult);
            }

        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

}
