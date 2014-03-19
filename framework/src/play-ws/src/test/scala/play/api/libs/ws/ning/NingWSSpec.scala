/*
 * Copyright (C) 2009-2013 Typesafe Inc. <http://www.typesafe.com>
 */
package play.api.libs.ws.ning

import org.specs2.mutable._
import org.specs2.mock.Mockito

import com.ning.http.client.{Response => AHCResponse, Cookie => AHCCookie, _}

import play.api.mvc._

import play.api.libs.ws._
import play.api.libs.ws.ssl.{SystemConfiguration, DefaultSSLLooseConfig, DefaultSSLConfig}
import play.api.test._

import scala.concurrent.Await
import scala.concurrent.duration._

import java.util

object NingWSSpec extends PlaySpecification with Mockito {

  sequential

  "Ning WS" should {

    object PairMagnet {
      implicit def fromPair(pair: Pair[WSClient, java.net.URL]) =
        new WSRequestHolderMagnet {
          def apply(): WSRequestHolder = {
            val (client, netUrl) = pair
            client.url(netUrl.toString)
          }
        }
    }

    "support ning magnet" in new WithApplication {
      import scala.language.implicitConversions
      import PairMagnet._

      val client = WS.client
      val exampleURL = new java.net.URL("http://example.com")
      WS.url(client -> exampleURL) must beAnInstanceOf[WSRequestHolder]
    }

    "support direct client instantiation" in new WithApplication {
      val sslBuilder = new com.ning.http.client.AsyncHttpClientConfig.Builder()
      implicit val sslClient = new play.api.libs.ws.ning.NingWSClient(sslBuilder.build())
      WS.clientUrl("http://example.com/feed") must beAnInstanceOf[WSRequestHolder]
    }

    "NingWSClient.underlying" in new WithApplication {
      val client = WS.client
      client.underlying[AsyncHttpClient] must beAnInstanceOf[AsyncHttpClient]
    }

    "NingWSCookie.underlying" in new WithApplication() {

      import com.ning.http.client.Cookie

      val mockCookie = mock[Cookie]
      val cookie = new NingWSCookie(mockCookie)
      val thisCookie = cookie.underlying[Cookie]
    }

    "NingWSRequest.setHeaders using a builder with fluent map" in new WithApplication {
      val request = new NingWSRequest(mock[NingWSClient], "GET", None, None, builder = new RequestBuilder("GET"))
      val headerMap: java.util.Map[String, java.util.Collection[String]] = new java.util.HashMap()
      headerMap.put("key", java.util.Arrays.asList("value"))

      val ningRequest = request.setHeaders(new FluentCaseInsensitiveStringsMap(headerMap)).build
      ningRequest.getHeaders.containsKey("key") must beTrue
    }

    "NingWSRequest.setHeaders using a builder with direct map" in new WithApplication {
      val request = new NingWSRequest(mock[NingWSClient], "GET", None, None, builder = new RequestBuilder("GET"))
      val headerMap: Map[String, Seq[String]] = Map("key" -> Seq("value"))
      val ningRequest = request.setHeaders(headerMap).build
      ningRequest.getHeaders.containsKey("key") must beTrue
    }

    "NingWSRequest.setQueryString" in new WithApplication {
      val request = new NingWSRequest(mock[NingWSClient], "GET", None, None, builder = new RequestBuilder("GET"))
      val queryString: Map[String, Seq[String]] = Map("key" -> Seq("value"))
      val ningRequest = request.setQueryString(queryString).build
      ningRequest.getQueryParams().containsKey("key") must beTrue
    }

    "support several query string values for a parameter" in new WithApplication {
      val req = WS.url("http://playframework.com/")
        .withQueryString("foo" -> "foo1", "foo" -> "foo2").asInstanceOf[NingWSRequestHolder]
        .prepare("GET").build
      req.getQueryParams.get("foo").contains("foo1") must beTrue
      req.getQueryParams.get("foo").contains("foo2") must beTrue
      req.getQueryParams.get("foo").size must equalTo(2)
    }

    "support a proxy server" in new WithApplication {
      val proxy = DefaultWSProxyServer(protocol = Some("https"), host = "localhost", port = 8080, principal = Some("principal"), password = Some("password"))
      val req = WS.url("http://playframework.com/").withProxyServer(proxy).asInstanceOf[NingWSRequestHolder].prepare("GET").build
      val actual = req.getProxyServer

      actual.getProtocolAsString must be equalTo "https"
      actual.getHost must be equalTo "localhost"
      actual.getPort must be equalTo 8080
      actual.getPrincipal must be equalTo "principal"
      actual.getPassword must be equalTo "password"
    }

    "support a proxy server" in new WithApplication {
      val proxy = DefaultWSProxyServer(host = "localhost", port = 8080)
      val req = WS.url("http://playframework.com/").withProxyServer(proxy).asInstanceOf[NingWSRequestHolder].prepare("GET").build
      val actual = req.getProxyServer

      actual.getProtocolAsString must be equalTo "http"
      actual.getHost must be equalTo "localhost"
      actual.getPort must be equalTo 8080
      actual.getPrincipal must beNull
      actual.getPassword must beNull
    }

    val patchFakeApp = FakeApplication(withRoutes = {
      case ("PATCH", "/") => Action {
        Results.Ok(play.api.libs.json.Json.parse(
          """{
            |  "data": "body"
            |}
          """.stripMargin))
      }
    })

    "support patch method" in new WithServer(patchFakeApp) {

      // NOTE: if you are using a client proxy like Privoxy or Polipo, your proxy may not support PATCH & return 400.
      val req = WS.url("http://localhost:" + port + "/").patch("body")

      val rep = await(req)

      rep.status must ===(200)
      (rep.json \ "data").asOpt[String] must beSome("body")
    }

    def gzipFakeApp = {
      import java.io._
      import java.util.zip._
      FakeApplication(
        withRoutes = {
          case ("GET", "/") => Action { request =>
            request.headers.get("Accept-Encoding") match {
              case Some(encoding) if encoding.contains("gzip") =>
                val os = new ByteArrayOutputStream
                val gzipOs = new GZIPOutputStream(os)
                gzipOs.write("gzipped response".getBytes("utf-8"))
                gzipOs.close()
                Results.Ok(os.toByteArray).as("text/plain").withHeaders("Content-Encoding" -> "gzip")
              case _ =>
                Results.Ok("plain response")
            }
          }
        },
        additionalConfiguration = Map("ws.compressionEnabled" -> true)
      )
    }

    "support gzipped encoding" in new WithServer(gzipFakeApp) {

      val req = WS.url("http://localhost:" + port + "/").get()
      val rep = await(req)
      rep.body must ===("gzipped response")
    }
  }

  "Ning WS Response" should {
    "get cookies from an AHC response" in {

      val ahcResponse: AHCResponse = mock[AHCResponse]
      val (domain, name, value, path, maxAge, secure) = ("example.com", "someName", "someValue", "/", 1000, false)

      val ahcCookie: AHCCookie = new AHCCookie(domain, name, value, path, maxAge, secure)
      ahcResponse.getCookies returns util.Arrays.asList(ahcCookie)

      val response = NingWSResponse(ahcResponse)

      val cookies: Seq[WSCookie] = response.cookies
      val cookie = cookies(0)

      cookie.domain must ===("example.com")
      cookie.name must beSome("someName")
      cookie.value must beSome("someValue")
      cookie.path must ===("/")
      cookie.maxAge must ===(1000)
      cookie.secure must beFalse
    }

    "get a single cookie from an AHC response" in {
      val ahcResponse: AHCResponse = mock[AHCResponse]
      val (domain, name, value, path, maxAge, secure) = ("example.com", "someName", "someValue", "/", 1000, false)

      val ahcCookie: AHCCookie = new AHCCookie(domain, name, value, path, maxAge, secure)
      ahcResponse.getCookies returns util.Arrays.asList(ahcCookie)

      val response = NingWSResponse(ahcResponse)

      val optionCookie = response.cookie("someName")
      optionCookie must beSome[WSCookie].which {
        cookie =>
          cookie.domain must ===("example.com")
          cookie.name must beSome("someName")
          cookie.value must beSome("someValue")
          cookie.path must ===("/")
          cookie.maxAge must ===(1000)
          cookie.secure must beFalse
      }
    }
  }

}
