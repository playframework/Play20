/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */
package controllers.b;

import play.mvc.*;

public class B extends Controller {

  public Result index() {
    controllers.a.routes.A.index();
    controllers.b.routes.B.index();
    controllers.c.routes.C.index();
    return ok();
  }

}
