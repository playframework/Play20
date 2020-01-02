/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import java.util.Optional;
// #server-request-attribute
import play.api.mvc.request.RequestAttrKey;

public class SomeJavaController extends Controller {

  public Result index(Http.Request request) {
    assert (request
        .attrs()
        .getOptional(RequestAttrKey.Server().asJava())
        .equals(Optional.of("netty")));
    // ...
    // ###skip: 1
    return ok("");
  }
}
// #server-request-attribute
