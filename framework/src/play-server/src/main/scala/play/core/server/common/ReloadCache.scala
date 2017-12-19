/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.core.server.common

import play.api.Application
import play.api.http.HttpConfiguration
import play.api.libs.crypto.CookieSignerProvider
import play.api.mvc.{ DefaultCookieHeaderEncoding, DefaultFlashCookieBaker, DefaultSessionCookieBaker }
import play.api.mvc.request.DefaultRequestFactory
import play.utils.InlineCache

import scala.util.{ Failure, Success, Try }

/**
 * Helps a `Server` to cache objects that change when an `Application` is reloaded.
 *
 * Subclasses should override the `reloadValue` method, which will be called
 * when the `Application` changes, and then cached. (Caching is provided by `InlineCache`,
 * so read its docs for the threading semantics.) Users should call
 * `cachedValue` to get the cached value.
 */
private[play] abstract class ReloadCache[+T] {

  private val reloadCache: Try[Application] => T = new InlineCache[Try[Application], T](reloadValue(_))

  /**
   * Get the cached `T` for the given application. If the application has changed
   * then `reloadValue` will be called to calculate a fresh value.
   */
  final def cachedFrom(tryApp: Try[Application]): T = reloadCache(tryApp)

  /**
   * Calculate a fresh `T` for the given application.
   */
  protected def reloadValue(tryApp: Try[Application]): T

  /**
   * Helper to calculate a `ServerResultUtil`.
   */
  protected final def reloadServerResultUtils(tryApp: Try[Application]): ServerResultUtils = {
    val (sessionBaker, flashBaker, cookieHeaderEncoding) = tryApp match {
      case Success(app) =>
        val requestFactory: DefaultRequestFactory = app.requestFactory match {
          case drf: DefaultRequestFactory => drf
          case _ => new DefaultRequestFactory(app.httpConfiguration)
        }

        (
          requestFactory.sessionBaker,
          requestFactory.flashBaker,
          requestFactory.cookieHeaderEncoding
        )
      case Failure(_) =>
        val httpConfig = HttpConfiguration()
        val cookieSigner = new CookieSignerProvider(httpConfig.secret).get

        (
          new DefaultSessionCookieBaker(httpConfig.session, httpConfig.secret, cookieSigner),
          new DefaultFlashCookieBaker(httpConfig.flash, httpConfig.secret, cookieSigner),
          new DefaultCookieHeaderEncoding(httpConfig.cookies)
        )
    }
    new ServerResultUtils(sessionBaker, flashBaker, cookieHeaderEncoding)
  }

  /**
   * Helper to calculate a `ForwardedHeaderHandler`.
   */
  protected final def reloadForwardedHeaderHandler(tryApp: Try[Application]): ForwardedHeaderHandler = {
    val forwardedHeaderConfiguration =
      ForwardedHeaderHandler.ForwardedHeaderHandlerConfig(tryApp.toOption.map(_.configuration))
    new ForwardedHeaderHandler(forwardedHeaderConfiguration)
  }
}
