/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.core.server.akkahttp

import akka.http.scaladsl.model.{ HttpRequest, HttpResponse }
import play.api.mvc.Handler
import play.mvc.Http.RequestHeader

import scala.concurrent.Future

trait AkkaHttpHandler extends (HttpRequest => Future[HttpResponse]) with Handler
