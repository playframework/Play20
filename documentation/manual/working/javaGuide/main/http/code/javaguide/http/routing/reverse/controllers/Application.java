/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

// #controller
// ###replace: package controllers;
package javaguide.http.routing.reverse.controllers;

import play.*;
import play.mvc.*;

public class Application extends Controller {

  public Result hello(String name) {
    return ok("Hello " + name + "!");
  }
}
// #controller
