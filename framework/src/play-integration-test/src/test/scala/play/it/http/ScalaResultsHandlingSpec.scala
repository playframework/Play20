/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.it.http

import akka.util.Timeout
import java.io.IOException
import java.util.concurrent.{ LinkedBlockingQueue, TimeUnit }
import play.api.http._
import play.api.inject.bind
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.mvc._
import play.api.test._
import play.api.libs.ws._
import play.api.libs.iteratee._
import play.api.routing.Router
import play.core.server.common.ServerResultException
import play.it._
import scala.concurrent.Future
import scala.concurrent.duration.Duration
import scala.util.{ Failure, Success, Try }
import play.api.libs.concurrent.Execution.{ defaultContext => ec }
import play.api.http.Status

object NettyScalaResultsHandlingSpec extends ScalaResultsHandlingSpec with NettyIntegrationSpecification
object AkkaHttpScalaResultsHandlingSpec extends ScalaResultsHandlingSpec with AkkaHttpIntegrationSpecification

trait ScalaResultsHandlingSpec extends PlaySpecification with WsTestClient with ServerIntegrationSpecification {

  sequential

  "scala body handling" should {

    def tryRequest[T](result: => Result)(block: Try[WSResponse] => T) = withServer(result) { implicit port =>
      val response = Try(await(wsUrl("/").get()))
      block(response)
    }

    def makeRequest[T](result: => Result)(block: WSResponse => T) = {
      tryRequest(result)(tryResult => block(tryResult.get))
    }

    def withServer[T](result: => Result, errorHandler: HttpErrorHandler = DefaultHttpErrorHandler)(block: Port => T) = {
      val port = testServerPort
      val app = new GuiceApplicationBuilder()
        .overrides(
          bind[HttpErrorHandler].to(errorHandler),
          bind[Router].to(Router.from {
            case _ => Action(result)
          }))
        .build()
      running(TestServer(port, app)) {
        block(port)
      }
    }

    // For testing server error handling
    class TestingHttpErrorHandler(result: => Result) extends HttpErrorHandler {
      private val errorQueue = new LinkedBlockingQueue[(RequestHeader, Throwable)]()
      override def onClientError(request: RequestHeader, statusCode: Int, message: String = ""): Future[Result] = ???
      override def onServerError(request: RequestHeader, exception: Throwable): Future[Result] = {
        errorQueue.put((request, exception))
        Future.successful(result)
      }
      def nextError(): (RequestHeader, Throwable) = {
        val timeout: Duration = implicitly[Timeout].duration
        val result = errorQueue.poll(timeout.length, timeout.unit)
        if (result == null) { throw new NoSuchElementException("Error queue is empty") }
        result
      }
      def hasErrors: Boolean = errorQueue.peek != null
    }

    "add Date header" in makeRequest(Results.Ok("Hello world")) { response =>
      response.header(DATE) must beSome
    }

    "add Content-Length when enumerator contains a single item" in makeRequest(Results.Ok("Hello world")) { response =>
      response.header(CONTENT_LENGTH) must beSome("11")
      response.body must_== "Hello world"
    }

    "revert to chunked encoding when enumerator contains more than one item" in makeRequest(
      Result(ResponseHeader(200, Map()), Enumerator("abc", "def", "ghi") &> Enumeratee.map[String](_.getBytes)(ec))
    ) { response =>
        response.header(CONTENT_LENGTH) must beNone
        response.header(TRANSFER_ENCODING) must beSome("chunked")
        response.body must_== "abcdefghi"
      }

    "truncate result body or close connection when body is larger than Content-Length" in tryRequest(Results.Ok("Hello world")
      .withHeaders(CONTENT_LENGTH -> "5")) { tryResponse =>
      tryResponse must beLike {
        case Success(response) =>
          response.header(CONTENT_LENGTH) must_== Some("5")
          response.body must_== "Hello"
        case Failure(t) =>
          t must haveClass[IOException]
          t.getMessage.toLowerCase must_== "remotely closed"
      }
    }

    "chunk results for chunked streaming strategy" in makeRequest(
      Results.Ok.chunked(Enumerator("a", "b", "c"))
    ) { response =>
        response.header(TRANSFER_ENCODING) must beSome("chunked")
        response.header(CONTENT_LENGTH) must beNone
        response.body must_== "abc"
      }

    "close the connection for feed results" in withServer(
      Results.Ok.feed(Enumerator("a", "b", "c"))
    ) { port =>
        val response = BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.status must_== 200
        response.headers.get(TRANSFER_ENCODING) must beNone
        response.headers.get(CONTENT_LENGTH) must beNone
        response.headers.get(CONNECTION) must beSome("close")
        response.body must beLeft("abc")
      }

    "close the HTTP 1.1 connection when requested" in withServer(
      Results.Ok.copy(connection = HttpConnection.Close)
    ) { port =>
        val response = BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.status must_== 200
        response.headers.get(CONNECTION) must beSome("close")
      }

    "close the HTTP 1.0 connection when requested" in withServer(
      Results.Ok.copy(connection = HttpConnection.Close)
    ) { port =>
        val response = BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.0", Map("Connection" -> "keep-alive"), "")
        )(0)
        response.status must_== 200
        response.headers.get(CONNECTION).map(_.toLowerCase) must beOneOf(None, Some("close"))
      }

    "close the connection when the connection close header is present" in withServer(
      Results.Ok
    ) { port =>
        BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.1", Map("Connection" -> "close"), "")
        )(0).status must_== 200
      }

    "close the connection when the connection when protocol is HTTP 1.0" in withServer(
      Results.Ok
    ) { port =>
        BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.0", Map(), "")
        )(0).status must_== 200
      }

    "honour the keep alive header for HTTP 1.0" in withServer(
      Results.Ok
    ) { port =>
        val responses = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.0", Map("Connection" -> "keep-alive"), ""),
          BasicRequest("GET", "/", "HTTP/1.0", Map(), "")
        )
        responses(0).status must_== 200
        responses(0).headers.get(CONNECTION) must beSome.like {
          case s => s.toLowerCase must_== "keep-alive"
        }
        responses(1).status must_== 200
      }

    "keep alive HTTP 1.1 connections" in withServer(
      Results.Ok
    ) { port =>
        val responses = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), ""),
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )
        responses(0).status must_== 200
        responses(1).status must_== 200
      }

    "close chunked connections when requested" in withServer(
      Results.Ok.chunked(Enumerator("a", "b", "c"))
    ) { port =>
        // will timeout if not closed
        BasicHttpClient.makeRequests(port, checkClosed = true)(
          BasicRequest("GET", "/", "HTTP/1.1", Map("Connection" -> "close"), "")
        )(0).status must_== 200
      }

    "keep chunked connections alive by default" in withServer(
      Results.Ok.chunked(Enumerator("a", "b", "c"))
    ) { port =>
        val responses = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), ""),
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )
        responses(0).status must_== 200
        responses(1).status must_== 200
      }

    "allow sending trailers" in withServer(
      Result(ResponseHeader(200, Map(TRANSFER_ENCODING -> CHUNKED, TRAILER -> "Chunks")),
        Enumerator("aa", "bb", "cc") &> Enumeratee.map[String](_.getBytes)(ec) &> Results.chunk(Some(
          Iteratee.fold[Array[Byte], Int](0)((count, in) => count + 1)(ec)
            .map(count => Seq("Chunks" -> count.toString))(ec)
        )))
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )(0)

        response.status must_== 200
        response.body must beRight
        val (chunks, trailers) = response.body.right.get
        chunks must containAllOf(Seq("aa", "bb", "cc")).inOrder
        trailers.get("Chunks") must beSome("3")
      }

    "fall back to simple streaming when more than one chunk is sent and protocol is HTTP 1.0" in withServer(
      Result(ResponseHeader(200, Map()), Enumerator("abc", "def", "ghi") &> Enumeratee.map[String](_.getBytes)(ec))
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.0", Map(), "")
        )(0)
        response.headers.keySet must not contain TRANSFER_ENCODING
        response.headers.keySet must not contain CONTENT_LENGTH
        response.body must beLeft("abcdefghi")
      }

    "Strip malformed cookies" in withServer(
      Results.Ok
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map("Cookie" -> """£"""), "")
        )(0)

        response.status must_== 200
        response.body must beLeft
      }

    "reject HTTP 1.0 requests for chunked results" in {
      val errorHandler = new TestingHttpErrorHandler(Results.InternalServerError("Custom error message"))
      withServer(
        Results.Ok.chunked(Enumerator("a", "b", "c")),
        errorHandler = errorHandler
      ) { port =>
          val response = BasicHttpClient.makeRequests(port)(
            BasicRequest("GET", "/", "HTTP/1.0", Map(), "")
          ).head
          response.status must_== HTTP_VERSION_NOT_SUPPORTED
          response.body must beLeft("Custom error message")
          val (request, exception) = errorHandler.nextError()
          request.path must_== "/"
          exception must beLike {
            case e: ServerResultException =>
              // Check original result
              e.result.header.status must_== 200
          }
          errorHandler.hasErrors must beFalse
        }
    }

    "return a 500 error on response with null header" in {
      val errorHandler = new TestingHttpErrorHandler(Results.InternalServerError("Null error message"))
      withServer(
        Results.Ok("some body").withHeaders("X-Null" -> null),
        errorHandler = errorHandler
      ) { port =>
          val response = BasicHttpClient.makeRequests(port)(
            BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
          ).head

          response.status must_== 500
          response.body must beLeft("Null error message")
          val (request, exception) = errorHandler.nextError()
          request.path must_== "/"
          exception must beLike {
            case e: NullPointerException =>
              e.getMessage must contain("X-Null") // Check we're giving the header name in the exception
          }
          errorHandler.hasErrors must beFalse
        }
    }

    "not send empty chunks before the end of the enumerator stream" in makeRequest(
      Results.Ok.chunked(Enumerator("foo", "", "bar"))
    ) { response =>
        response.header(TRANSFER_ENCODING) must beSome("chunked")
        response.header(CONTENT_LENGTH) must beNone
        response.body must_== "foobar"
      }

    "return a 400 error on Header value contains a prohibited character" in withServer(
      Results.Ok
    ) { port =>

        forall(List(
          "aaa" -> "bbb\fccc",
          "ddd" -> "eee\u000bfff"
        )) { header =>

          val response = BasicHttpClient.makeRequests(port)(
            BasicRequest("GET", "/", "HTTP/1.1", Map(header), "")
          )(0)

          response.status must_== 400
          response.body must beLeft
        }
      }

    "split Set-Cookie headers" in {
      import play.api.mvc.Cookie
      val aCookie = Cookie("a", "1")
      val bCookie = Cookie("b", "2")
      val cCookie = Cookie("c", "3")
      makeRequest {
        Results.Ok.withCookies(aCookie, bCookie, cCookie)
      } { response =>
        response.allHeaders.get(SET_COOKIE) must beSome.like {
          case rawCookieHeaders =>
            val decodedCookieHeaders: Set[Set[Cookie]] = rawCookieHeaders.map { headerValue =>
              Cookies.decodeSetCookieHeader(headerValue).to[Set]
            }.to[Set]
            decodedCookieHeaders must_== (Set(Set(aCookie), Set(bCookie), Set(cCookie)))
        }
      }
    }

    "not have a message body even when a 204 response with a non-empty body is returned" in withServer(
      Result(header = ResponseHeader(NO_CONTENT),
        body = Enumerator("foo") &> Enumeratee.map[String](_.getBytes)(ec),
        connection = HttpConnection.KeepAlive)
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("PUT", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
      }

    "not have a message body even when a 304 response with a non-empty body is returned" in withServer(
      Result(header = ResponseHeader(NOT_MODIFIED),
        body = Enumerator("foo") &> Enumeratee.map[String](_.getBytes)(ec),
        connection = HttpConnection.KeepAlive)
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("PUT", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
      }

    "not have a message body, nor Content-Length, when a 204 response is returned" in withServer(
      Results.NoContent
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("PUT", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
        response.headers.get(CONTENT_LENGTH) must beNone
      }

    "not have a message body, but may have a Content-Length, when a 204 response with an explicit Content-Length is returned" in withServer(
      Results.NoContent.withHeaders("Content-Length" -> "0")
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("PUT", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
        response.headers.get(CONTENT_LENGTH) must beOneOf(None, Some("0")) // Both header values are valid
      }

    "not have a message body, nor a Content-Length, when a 304 response is returned" in withServer(
      Results.NotModified
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
        response.headers.get(CONTENT_LENGTH) must beNone
      }

    "not have a message body, but may have a Content-Length, when a 304 response with an explicit Content-Length is returned" in withServer(
      Results.NotModified.withHeaders("Content-Length" -> "0")
    ) { port =>
        val response = BasicHttpClient.makeRequests(port)(
          BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
        )(0)
        response.body must beLeft("")
        response.headers.get(CONTENT_LENGTH) must beOneOf(None, Some("0")) // Both header values are valid
      }

    "return a 500 response if a forbidden character is used in a response's header field" in {
      val errorHandler = new TestingHttpErrorHandler(Results.InternalServerError("Another error message"))
      withServer(
        Results.Ok.withHeaders("BadFieldName: " -> "SomeContent"),
        errorHandler = errorHandler
      ) { port =>
          val response = BasicHttpClient.makeRequests(port)(
            BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
          ).head
          response.status must_== INTERNAL_SERVER_ERROR
          response.body must beLeft("Another error message")
          val (request, exception) = errorHandler.nextError()
          request.path must_== "/"
          exception must beLike {
            case e: ServerResultException =>
              // Check original result
              e.result.header.status must_== 200
              e.getCause must not be (null)
          }
          errorHandler.hasErrors must beFalse
        }
    }

    "return a 500 response if an error occurs during the onError" in {
      val errorHandler = new TestingHttpErrorHandler(throw new Exception("Failing on purpose :)"))
      withServer(
        Results.Ok.withHeaders("BadFieldName: " -> "SomeContent"),
        errorHandler = errorHandler
      ) { port =>
          val response = BasicHttpClient.makeRequests(port)(
            BasicRequest("GET", "/", "HTTP/1.1", Map(), "")
          ).head
          response.status must_== INTERNAL_SERVER_ERROR

          // Original error should be handled
          val (request, exception) = errorHandler.nextError()
          request.path must_== "/"
          exception must beLike {
            case e: ServerResultException =>
              // Check original result
              e.result.header.status must_== 200
              e.getCause must not be (null)
          }

          // Error in handler should not be handled
          errorHandler.hasErrors must beFalse
        }
    }

  }
}
