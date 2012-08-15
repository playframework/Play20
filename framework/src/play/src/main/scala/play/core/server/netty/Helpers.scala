package play.core.server.netty

import org.jboss.netty.channel._
import org.jboss.netty.handler.codec.http._


import play.api.mvc._
import play.api.libs.iteratee._
import play.api.libs.iteratee.Input._

import scala.collection.JavaConverters._
import collection.immutable.TreeMap
import play.core.utils.CaseInsensitiveOrdered

private[netty] trait Helpers {

  def socketOut[A](ctx: ChannelHandlerContext)(frameFormatter: play.api.mvc.WebSocket.FrameFormatter[A]): Iteratee[A, Unit] = {
    val channel = ctx.getChannel()
    val nettyFrameFormatter = frameFormatter.asInstanceOf[play.core.server.websocket.FrameFormatter[A]]

    def step(future: Option[ChannelFuture])(input: Input[A]): Iteratee[A, Unit] =
      input match {
        case El(e) => Cont(step(Some(channel.write(nettyFrameFormatter.toFrame(e)))))
        case e @ EOF => future.map(_.addListener(ChannelFutureListener.CLOSE)).getOrElse(channel.close()); Done((), e)
        case Empty => Cont(step(future))
      }

    Enumeratee.breakE[A](_ => !channel.isConnected()).transform(Cont(step(None)))
  }

  def getHeaders(nettyRequest: HttpRequest): Headers = {

    //todo: wrap the underlying map in a structure more efficient than TreeMap
    val headers: Map[String, Seq[String]] = {
      val pairs = nettyRequest.getHeaderNames.asScala.map { key =>
        key -> nettyRequest.getHeaders(key).asScala
      }
      TreeMap(pairs.toSeq: _*)(CaseInsensitiveOrdered)
    }

    new Headers {
      def getAll(key: String) = headers.get(key).flatten.toSeq
      def keys = headers.keySet
      def toMap: Map[String, Seq[String]] = headers
      override def toString = headers.toString
    }

  }

  def getCookies(nettyRequest: HttpRequest): Cookies = {

    val cookies: Map[String, play.api.mvc.Cookie] = getHeaders(nettyRequest).get(play.api.http.HeaderNames.COOKIE).map { cookiesHeader =>
      new CookieDecoder().decode(cookiesHeader).asScala.map { c =>
        c.getName -> play.api.mvc.Cookie(
          c.getName, c.getValue, c.getMaxAge, Option(c.getPath).getOrElse("/"), Option(c.getDomain), c.isSecure, c.isHttpOnly)
      }.toMap
    }.getOrElse(Map.empty)

    new Cookies {
      def get(name: String) = cookies.get(name)
      override def toString = cookies.toString
    }

  }
}
