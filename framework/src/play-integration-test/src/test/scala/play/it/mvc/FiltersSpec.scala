/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.it.mvc

import org.specs2.mutable.Specification
import play.api.http.{ DefaultHttpErrorHandler, HttpErrorHandler }
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.ws.WSClient
import play.api.routing.Router
import play.api.{ Environment, ApplicationLoader, BuiltInComponentsFromContext }
import play.api.mvc._
import play.api.test._
import play.core.server.Server
import play.it._
import scala.concurrent.duration.Duration
import scala.concurrent._
import play.api.libs.concurrent.Execution.{ defaultContext => ec }

object NettyDefaultFiltersSpec extends DefaultFiltersSpec with NettyIntegrationSpecification
object AkkaDefaultHttpFiltersSpec extends DefaultFiltersSpec with AkkaHttpIntegrationSpecification

trait DefaultFiltersSpec extends FiltersSpec {
  def withServer[T](settings: Map[String, String] = Map.empty, errorHandler: Option[HttpErrorHandler] = None)(filters: EssentialFilter*)(block: WSClient => T) = {

    val app = new BuiltInComponentsFromContext(ApplicationLoader.createContext(
      environment = Environment.simple(),
      initialSettings = settings
    )) {
      lazy val router = testRouter
      override lazy val httpFilters: Seq[EssentialFilter] = filters
      override lazy val httpErrorHandler = errorHandler.getOrElse(
        new DefaultHttpErrorHandler(environment, configuration, sourceMapper, Some(router))
      )
    }.application

    Server.withApplication(app) { implicit port =>
      WsTestClient.withClient(block)
    }

  }
}

trait FiltersSpec extends Specification with ServerIntegrationSpecification {

  sequential

  "filters" should {
    "handle errors" in {

      "ErrorHandlingFilter has no effect on a GET that returns a 200 OK" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/ok").get(), Duration.Inf)
        response.status must_== 200
        response.body must_== expectedOkText
      }

      "ErrorHandlingFilter has no effect on a POST that returns a 200 OK" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/ok").post(expectedOkText), Duration.Inf)
        response.status must_== 200
        response.body must_== expectedOkText
      }

      "ErrorHandlingFilter recovers from a GET that throws a synchronous exception" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/error").get(), Duration.Inf)
        response.status must_== 500
        response.body must_== expectedErrorText
      }

      "ErrorHandlingFilter recovers from a GET that throws an asynchronous exception" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/error-async").get(), Duration.Inf)
        response.status must_== 500
        response.body must_== expectedErrorText
      }

      "ErrorHandlingFilter recovers from a POST that throws a synchronous exception" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/error").post(expectedOkText), Duration.Inf)
        response.status must_== 500
        response.body must_== expectedOkText
      }

      "ErrorHandlingFilter recovers from a POST that throws an asynchronous exception" in withServer()(ErrorHandlingFilter) { ws =>
        val response = Await.result(ws.url("/error-async").post(expectedOkText), Duration.Inf)
        response.status must_== 500
        response.body must_== expectedOkText
      }
    }

    "Filters are not applied when the request is outside the application.context" in withServer(
      Map("play.http.context" -> "/foo"))(ErrorHandlingFilter, ThrowExceptionFilter) { ws =>
        val response = Await.result(ws.url("/ok").post(expectedOkText), Duration.Inf)
        response.status must_== 200
        response.body must_== expectedOkText
      }

    "Filters are applied on the root of the application context" in withServer(
      Map("play.http.context" -> "/foo"))(SkipNextFilter) { ws =>
        val response = Await.result(ws.url("/foo").post(expectedOkText), Duration.Inf)
        response.status must_== 200
        response.body must_== SkipNextFilter.expectedText
      }

    "Filters work even if one of them does not call next" in withServer()(ErrorHandlingFilter, SkipNextFilter) { ws =>
      val response = Await.result(ws.url("/ok").get(), Duration.Inf)
      response.status must_== 200
      response.body must_== SkipNextFilter.expectedText
    }

    "ErrorHandlingFilter can recover from an exception throw by another filter in the filter chain, even if that Filter does not call next" in withServer()(ErrorHandlingFilter, SkipNextWithErrorFilter) { ws =>
      val response = Await.result(ws.url("/ok").get(), Duration.Inf)
      response.status must_== 500
      response.body must_== SkipNextWithErrorFilter.expectedText
    }

    "ErrorHandlingFilter can recover from an exception throw by another filter in the filter chain when that filter calls next and asynchronously throws an exception" in withServer()(ErrorHandlingFilter, ThrowExceptionFilter) { ws =>
      val response = Await.result(ws.url("/ok").get(), Duration.Inf)
      response.status must_== 500
      response.body must_== ThrowExceptionFilter.expectedText
    }

    val filterAddedHeaderKey = "CUSTOM_HEADER"
    val filterAddedHeaderVal = "custom header val"

    object CustomHeaderFilter extends Filter {
      def apply(next: RequestHeader => Future[Result])(request: RequestHeader): Future[Result] = {
        next(request.copy(headers = addCustomHeader(request.headers)))
      }
      def addCustomHeader(originalHeaders: Headers): Headers = {
        FakeHeaders(originalHeaders.headers :+ (filterAddedHeaderKey -> filterAddedHeaderVal))
      }
    }

    object CustomErrorHandler extends HttpErrorHandler {
      def onClientError(request: RequestHeader, statusCode: Int, message: String) = {
        Future.successful(Results.NotFound(request.headers.get(filterAddedHeaderKey).getOrElse("undefined header")))
      }
      def onServerError(request: RequestHeader, exception: Throwable) = Future.successful(Results.InternalServerError)
    }

    "requests not matching a route should receive a RequestHeader modified by upstream filters" in withServer(errorHandler = Some(CustomErrorHandler))(CustomHeaderFilter) { ws =>
      val response = Await.result(ws.url("/not-a-real-route").get(), Duration.Inf)
      response.status must_== 404
      response.body must_== filterAddedHeaderVal
    }
  }

  object ErrorHandlingFilter extends Filter {
    def apply(next: RequestHeader => Future[Result])(request: RequestHeader): Future[Result] = {
      try {
        next(request).recover {
          case t: Throwable =>
            Results.InternalServerError(t.getMessage)
        }(play.api.libs.concurrent.Execution.Implicits.defaultContext)
      } catch {
        case t: Throwable => Future.successful(Results.InternalServerError(t.getMessage))
      }
    }
  }

  object SkipNextFilter extends Filter {
    val expectedText = "This filter does not call next"

    def apply(next: RequestHeader => Future[Result])(request: RequestHeader): Future[Result] = {
      Future.successful(Results.Ok(expectedText))
    }
  }

  object SkipNextWithErrorFilter extends Filter {
    val expectedText = "This filter does not call next and throws an exception"

    def apply(next: RequestHeader => Future[Result])(request: RequestHeader): Future[Result] = {
      Future.failed(new RuntimeException(expectedText))
    }
  }

  object ThrowExceptionFilter extends Filter {
    val expectedText = "This filter calls next and throws an exception afterwords"

    override def apply(next: (RequestHeader) => Future[Result])(rh: RequestHeader): Future[Result] = {
      next(rh).map { _ =>
        throw new RuntimeException(expectedText)
      }(ec)
    }
  }

  val expectedOkText = "Hello World"
  val expectedErrorText = "Error"

  import play.api.routing.sird._
  val testRouter = Router.from {
    case GET(p"/") => Action { request => Results.Ok(expectedOkText) }
    case GET(p"/ok") => Action { request => Results.Ok(expectedOkText) }
    case POST(p"/ok") => Action { request => Results.Ok(request.body.asText.getOrElse("")) }
    case GET(p"/error") => Action { request => throw new RuntimeException(expectedErrorText) }
    case POST(p"/error") => Action { request => throw new RuntimeException(request.body.asText.getOrElse("")) }
    case GET(p"/error-async") => Action.async { request => Future { throw new RuntimeException(expectedErrorText) }(ec) }
    case POST(p"/error-async") => Action.async { request => Future { throw new RuntimeException(request.body.asText.getOrElse("")) }(ec) }
  }

  def withServer[T](settings: Map[String, String] = Map.empty, errorHandler: Option[HttpErrorHandler] = None)(filters: EssentialFilter*)(block: WSClient => T): T

}
