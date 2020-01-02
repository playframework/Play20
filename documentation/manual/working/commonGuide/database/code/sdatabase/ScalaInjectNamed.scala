/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package sdatabase

// #named-database
// ###insert: package controllers
import javax.inject.Inject

import play.api.mvc.BaseController
import play.api.mvc.ControllerComponents
import play.api.db.Database
import play.api.db.NamedDatabase

// inject "orders" database instead of "default"
class ScalaInjectNamed @Inject() (
    @NamedDatabase("orders") db: Database,
    val controllerComponents: ControllerComponents
) extends BaseController {
  // do whatever you need with the db
}
// #named-database
