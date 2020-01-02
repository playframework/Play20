/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package controllers

import java.util.concurrent.TimeUnit

import org.scalatestplus.play._
import org.scalatestplus.play.guice._
import play.api.test._
import play.api.test.Helpers._

class HomeControllerSpec extends PlaySpec with GuiceOneAppPerTest with Injecting {

  "HomeController GET" should {
    "responds 'original'in plain text" in {
      val controller = new HomeController(stubControllerComponents(), app.actorSystem, app.coordinatedShutdown)
      val home       = controller.index().apply(FakeRequest(GET, "/"))

      TimeUnit.SECONDS.sleep(10)
      status(home) mustBe OK
      contentType(home) mustBe Some("text/plain")
      contentAsString(home) must include("original")
    }

  }
}
