/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.it.http

import play.api.libs.streams.Accumulator
import play.api.mvc.{ Results, EssentialAction }
import play.api.test._
import play.api.test.TestServer
import play.api.libs.concurrent.Promise
import play.api.libs.iteratee._
import play.it._
import java.util.concurrent.TimeUnit
import scala.concurrent.Future
import scala.concurrent.duration.DurationInt
import akka.pattern.after

import scala.concurrent.ExecutionContext.Implicits.global

object NettyHttpPipeliningSpec extends HttpPipeliningSpec with NettyIntegrationSpecification
object AkkaHttpHttpPipeliningSpec extends HttpPipeliningSpec with AkkaHttpIntegrationSpecification

trait HttpPipeliningSpec extends PlaySpecification with ServerIntegrationSpecification {

  val actorSystem = akka.actor.ActorSystem()

  "Play's http pipelining support" should {

    def withServer[T](action: EssentialAction)(block: Port => T) = {
      val port = testServerPort
      running(TestServer(port, FakeApplication(
        withRoutes = {
          case _ => action
        }
      ))) {
        block(port)
      }
    }

    "wait for the first response to return before returning the second" in withServer(EssentialAction { req =>
      req.path match {
        case "/long" => Accumulator.done(after(100.milliseconds, actorSystem.scheduler)(Future(Results.Ok("long"))))
        case "/short" => Accumulator.done(Results.Ok("short"))
        case _ => Accumulator.done(Results.NotFound)
      }
    }) { port =>
      val responses = BasicHttpClient.pipelineRequests(port,
        BasicRequest("GET", "/long", "HTTP/1.1", Map(), ""),
        BasicRequest("GET", "/short", "HTTP/1.1", Map(), "")
      )
      responses(0).status must_== 200
      responses(0).body must beLeft("long")
      responses(1).status must_== 200
      responses(1).body must beLeft("short")
    }

    "wait for the first response body to return before returning the second" in withServer(EssentialAction { req =>
      req.path match {
        case "/long" => Accumulator.done(
          Results.Ok.chunked(Enumerator.unfoldM[Int, String](0) { chunk =>
            if (chunk < 3) {
              after(50.milliseconds, actorSystem.scheduler)(Future(Some((chunk + 1, chunk.toString))))
            } else {
              Future.successful(None)
            }
          })
        )
        case "/short" => Accumulator.done(Results.Ok("short"))
        case _ => Accumulator.done(Results.NotFound)
      }
    }) { port =>
      val responses = BasicHttpClient.pipelineRequests(port,
        BasicRequest("GET", "/long", "HTTP/1.1", Map(), ""),
        BasicRequest("GET", "/short", "HTTP/1.1", Map(), "")
      )
      responses(0).status must_== 200
      responses(0).body must beRight
      responses(0).body.right.get._1 must containAllOf(Seq("0", "1", "2")).inOrder
      responses(1).status must_== 200
      responses(1).body must beLeft("short")
    }

  }
}
