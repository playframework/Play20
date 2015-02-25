/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.core.j

import play.libs.F
import play.api.libs.iteratee.Execution.trampoline
import play.api.mvc._
import play.mvc.{ Result => JResult }
import play.mvc.Http.{ Context => JContext, Request => JRequest, RequestImpl => JRequestImpl, RequestHeader => JRequestHeader, Cookies => JCookies, Cookie => JCookie }
import play.mvc.Http.RequestBody

import scala.concurrent.Future
import collection.JavaConverters._

/**
 * Provides helper methods that manage Java to Scala Result and Scala to Java Context
 * creation
 */
trait JavaHelpers {

  /**
   * Creates a scala result from java context and result objects
   * @param javaContext
   * @param javaResult
   */
  def createScalaResult(javaContext: JContext, javaResult: JResult): Result = {
    val wResult = javaResult.toScala.withHeaders(javaContext.response.getHeaders.asScala.toSeq: _*)
      .withCookies(javaContext.response.cookies.asScala.toSeq map { c =>
        Cookie(c.name, c.value,
          if (c.maxAge == null) None else Some(c.maxAge), c.path, Option(c.domain), c.secure, c.httpOnly)
      }: _*)

    if (javaContext.session.isDirty && javaContext.flash.isDirty) {
      wResult.withSession(Session(javaContext.session.asScala.toMap)).flashing(Flash(javaContext.flash.asScala.toMap))
    } else {
      if (javaContext.session.isDirty) {
        wResult.withSession(Session(javaContext.session.asScala.toMap))
      } else {
        if (javaContext.flash.isDirty) {
          wResult.flashing(Flash(javaContext.flash.asScala.toMap))
        } else {
          wResult
        }
      }
    }
  }

  /**
   * Creates a java context from a scala RequestHeader
   * @param req
   */
  def createJavaContext(req: RequestHeader): JContext = {
    new JContext(
      req.id,
      req,
      new JRequestImpl(req),
      req.session.data.asJava,
      req.flash.data.asJava,
      req.tags.mapValues(_.asInstanceOf[AnyRef]).asJava
    )
  }

  /**
   * Creates a java context from a scala Request[RequestBody]
   * @param req
   */
  def createJavaContext(req: Request[RequestBody]): JContext = {
    new JContext(
      req.id,
      req,
      new JRequestImpl(req),
      req.session.data.asJava,
      req.flash.data.asJava,
      req.tags.mapValues(_.asInstanceOf[AnyRef]).asJava)
  }

  /**
   * Invoke the given function, converting the scala request to a Java request,
   * and converting the resulting Java result to a Scala result, before returning
   * it.
   *
   * This is intended for use by methods in the JavaGlobalSettingsAdapter, which need to be handled
   * like Java actions, but are not Java actions.
   *
   * @param request The request
   * @param f The function to invoke
   * @return The result
   */
  def invokeWithoutContext(request: RequestHeader, f: JRequest => F.Promise[JResult]): Future[Result] = {
    f(new JRequestImpl(request)).wrapped.map(_.toScala)(trampoline)
  }

}

object JavaHelpers extends JavaHelpers

class RequestHeaderImpl(header: RequestHeader) extends JRequestHeader {

  def uri = header.uri

  def method = header.method

  def version = header.version

  def remoteAddress = header.remoteAddress

  def secure = header.secure

  def host = header.host

  def path = header.path

  def headers = createHeaderMap(header.headers)

  def acceptLanguages = header.acceptLanguages.map(new play.i18n.Lang(_)).asJava

  def queryString = {
    header.queryString.mapValues(_.toArray).asJava
  }

  def acceptedTypes = header.acceptedTypes.asJava

  def accepts(mediaType: String) = header.accepts(mediaType)

  def cookies = new JCookies {
    def get(name: String): JCookie = {
      header.cookies.get(name).map(makeJavaCookie).orNull
    }

    private def makeJavaCookie(cookie: Cookie): JCookie = {
      new JCookie(cookie.name,
        cookie.value,
        cookie.maxAge.map(i => new Integer(i)).orNull,
        cookie.path,
        cookie.domain.orNull,
        cookie.secure,
        cookie.httpOnly)
    }

    def iterator: java.util.Iterator[JCookie] = {
      header.cookies.toIterator.map(makeJavaCookie).asJava
    }
  }

  def getQueryString(key: String): String = {
    if (queryString().containsKey(key) && queryString().get(key).length > 0) queryString().get(key)(0) else null
  }

  def cookie(name: String): JCookie = {
    cookies().get(name)
  }

  def getHeader(headerName: String): String = {
    val header: Array[String] = headers.get(headerName)
    if (header == null) null else header(0)
  }

  def hasHeader(headerName: String): Boolean = {
    getHeader(headerName) != null
  }

  private def createHeaderMap(headers: Headers): java.util.Map[String, Array[String]] = {
    val map = new java.util.TreeMap[String, Array[String]](play.core.utils.CaseInsensitiveOrdered)
    map.putAll(headers.toMap.mapValues(_.toArray).asJava)
    map
  }

  override def toString = header.toString

}
