/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.mvc;

import java.util.concurrent.CompletionStage;

public abstract class NewAction<T> extends Action<T> {

    public NewAction<?> next;

    @Override
    public CompletionStage<Result> call(Http.Context ctx) {
        return call(ctx.request());
    }

    public abstract CompletionStage<Result> call(Http.Request request);
}