/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package scalaguide.detailed.filters.csp

import javax.inject.Inject
import play.api.mvc.AbstractController
import play.api.mvc.ControllerComponents
import play.filters.csp.CSPActionBuilder

// #csp-action-controller
class CSPActionController @Inject() (cspAction: CSPActionBuilder, cc: ControllerComponents)
    extends AbstractController(cc) {
  def index = cspAction { implicit request =>
    Ok("result containing CSP")
  }
}
// #csp-action-controller
