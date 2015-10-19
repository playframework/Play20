/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.it.libs

import akka.util.ByteString
import akka.stream.scaladsl.Source
import akka.stream.scaladsl.Sink

import java.io.IOException

import org.asynchttpclient.{ RequestBuilderBase, SignatureCalculator }

import play.api.http.{ HttpEntity, Port }
import play.api.libs.iteratee._
import play.api.libs.oauth._
import play.api.mvc._
import play.api.test._
import play.core.server.Server
import play.it._
import play.it.tools.HttpBinApplication
import play.api.mvc.BodyParsers.parse
import play.api.mvc.Results.Ok
import play.api.libs.streams.Accumulator

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.concurrent.Future

object NettyWSSpec extends WSSpec with NettyIntegrationSpecification

object AkkaHttpWSSpec extends WSSpec with AkkaHttpIntegrationSpecification

trait WSSpec extends PlaySpecification with ServerIntegrationSpecification {

  "Web service client" title

  sequential

  def app = HttpBinApplication.app

  val foldingSink = Sink.fold[ByteString, ByteString](ByteString.empty)((state, bs) => state ++ bs)

  "WS@java" should {

    def withServer[T](block: play.libs.ws.WSClient => T) = {
      Server.withApplication(app) { implicit port =>
        withClient(block)
      }
    }

    def withEchoServer[T](block: play.libs.ws.WSClient => T) = {
      def echo = BodyParser { req =>
        import play.api.libs.concurrent.Execution.Implicits.defaultContext
        Accumulator.source[ByteString].mapFuture { source =>
          Future.successful(source).map(Right.apply)
        }
      }

      Server.withRouter() {
        case _ => Action(echo) { req =>
          Ok.chunked(req.body)
        }
      } { implicit port =>
        withClient(block)
      }
    }

    def withResult[T](result: Result)(block: play.libs.ws.WSClient => T) = {
      Server.withRouter() {
        case _ => Action(result)
      } { implicit port =>
        withClient(block)
      }
    }

    def withClient[T](block: play.libs.ws.WSClient => T)(implicit port: Port): T = {
      val wsClient = play.libs.ws.WS.newClient(port.value)
      try {
        block(wsClient)
      } finally {
        wsClient.close()
      }
    }

    import play.libs.ws.WSSignatureCalculator

    "make GET Requests" in withServer { ws =>
      val req = ws.url("/get").get
      val rep = req.get(1000) // AWait result

      rep.getStatus aka "status" must_== 200 and (
        rep.asJson.path("origin").textValue must not beNull)
    }

    "use queryString in url" in withServer { ws =>
      val rep = ws.url("/get?foo=bar").get().get(1000)

      rep.getStatus aka "status" must_== 200 and (
        rep.asJson().path("args").path("foo").textValue() must_== "bar")
    }

    "use user:password in url" in Server.withApplication(app) { implicit port =>
      withClient { ws =>
        val rep = ws.url(s"http://user:password@localhost:$port/basic-auth/user/password").get().get(1000)

        rep.getStatus aka "status" must_== 200 and (
          rep.asJson().path("authenticated").booleanValue() must beTrue)
      }
    }

    "reject invalid query string" in withServer { ws =>
      import java.net.MalformedURLException

      ws.url("/get?=&foo").
        aka("invalid request") must throwA[RuntimeException].like {
          case e: RuntimeException =>
            e.getCause must beAnInstanceOf[MalformedURLException]
        }
    }

    "reject invalid user password string" in withServer { ws =>
      import java.net.MalformedURLException

      ws.url("http://@localhost/get").
        aka("invalid request") must throwA[RuntimeException].like {
          case e: RuntimeException =>
            e.getCause must beAnInstanceOf[MalformedURLException]
        }
    }

    "consider query string in JSON conversion" in withServer { ws =>
      val empty = ws.url("/get?foo").get.get(1000)
      val bar = ws.url("/get?foo=bar").get.get(1000)

      empty.asJson.path("args").path("foo").textValue() must_== "" and (
        bar.asJson.path("args").path("foo").textValue() must_== "bar")
    }

    "get a streamed response" in withResult(
      Results.Ok.chunked(Source(List("a", "b", "c")))) { ws =>
        val res = ws.url("/get").stream().toCompletableFuture.get()

        await(res.getBody().runWith(foldingSink, app.materializer)).decodeString("utf-8").
          aka("streamed response") must_== "abc"
      }

    "streaming a request body" in withEchoServer { ws =>
      val source = akka.stream.javadsl.Source.adapt(Source(List("a", "b", "c").map(ByteString.apply)))
      val res = ws.url("/post").setMethod("POST").setBody(source).execute()
      val body = await(res.wrapped).getBody

      body must_== "abc"
    }

    class CustomSigner extends WSSignatureCalculator with org.asynchttpclient.SignatureCalculator {
      def calculateAndAddSignature(request: org.asynchttpclient.Request, requestBuilder: org.asynchttpclient.RequestBuilderBase[_]) = {
        // do nothing
      }
    }

    "not throw an exception while signing requests" in withServer { ws =>
      val key = "12234"
      val secret = "asbcdef"
      val token = "token"
      val tokenSecret = "tokenSecret"
      (ConsumerKey(key, secret), RequestToken(token, tokenSecret))

      val calc: WSSignatureCalculator = new CustomSigner

      ws.url("/").sign(calc).
        aka("signed request") must not(throwA[Exception])
    }
  }

  "WS@scala" should {

    import play.api.libs.ws.WSSignatureCalculator
    import play.api.libs.ws.StreamedBody

    implicit val materializer = app.materializer

    val foldingSink = Sink.fold[ByteString, ByteString](ByteString.empty)((state, bs) => state ++ bs)

    def withServer[T](block: play.api.libs.ws.WSClient => T) = {
      Server.withApplication(app) { implicit port =>
        WsTestClient.withClient(block)
      }
    }

    def withEchoServer[T](block: play.api.libs.ws.WSClient => T) = {
      def echo = BodyParser { req =>
        import play.api.libs.concurrent.Execution.Implicits.defaultContext
        Accumulator.source[ByteString].mapFuture { source =>
          Future.successful(source).map(Right.apply)
        }
      }

      Server.withRouter() {
        case _ => Action(echo) { req =>
          Ok.chunked(req.body)
        }
      } { implicit port =>
        WsTestClient.withClient(block)
      }
    }

    def withResult[T](result: Result)(block: play.api.libs.ws.WSClient => T) = {
      Server.withRouter() {
        case _ => Action(result)
      } { implicit port =>
        WsTestClient.withClient(block)
      }
    }

    "make GET Requests" in withServer { ws =>
      val req = ws.url("/get").get()

      Await.result(req, Duration(1, SECONDS)).status aka "status" must_== 200
    }

    "Get 404 errors" in withServer { ws =>
      val req = ws.url("/post").get()

      Await.result(req, Duration(1, SECONDS)).status aka "status" must_== 404
    }

    "get a streamed response" in withResult(
      Results.Ok.chunked(Source(List("a", "b", "c")))) { ws =>

        val res = ws.url("/get").stream()
        val body = await(res).body

        await(body.runWith(foldingSink)).decodeString("utf-8").
          aka("streamed response") must_== "abc"
      }

    "streaming a request body" in withEchoServer { ws =>
      val source = Source(List("a", "b", "c").map(ByteString.apply))
      val res = ws.url("/post").withMethod("POST").withBody(StreamedBody(source)).execute()
      val body = await(res).body

      body must_== "abc"
    }

    class CustomSigner extends WSSignatureCalculator with SignatureCalculator {
      def calculateAndAddSignature(request: org.asynchttpclient.Request, requestBuilder: RequestBuilderBase[_]) = {
        // do nothing
      }
    }

    "not throw an exception while signing requests" >> {
      val calc = new CustomSigner

      "without query string" in withServer { ws =>
        ws.url("/").sign(calc).get().
          aka("signed request") must not(throwA[NullPointerException])
      }

      "with query string" in withServer { ws =>
        ws.url("/").withQueryString("lorem" -> "ipsum").
          sign(calc) aka "signed request" must not(throwA[Exception])
      }
    }
  }
}
