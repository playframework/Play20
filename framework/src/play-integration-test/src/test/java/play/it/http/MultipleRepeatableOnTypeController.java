/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.it.http;

import play.mvc.Result;
import play.mvc.Results;

import play.it.http.ActionCompositionOrderTest.SomeRepeatable;

@SomeRepeatable // runs two actions
@SomeRepeatable // once more, so makes it four
public class MultipleRepeatableOnTypeController extends MockController {

    public Result action() {
        return Results.ok();
    }

}
