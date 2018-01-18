/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package javaguide.tests.controllers;

import play.mvc.*;

public class HomeController extends BaseController {

  public Result index() {
    return ok(javaguide.tests.html.index.render("Welcome to Play!"));
  }
  
}
