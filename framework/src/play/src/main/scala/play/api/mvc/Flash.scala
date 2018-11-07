/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.api.mvc

import javax.inject.Inject

import play.api.http.{ FlashConfiguration, HttpConfiguration, SecretConfiguration }
import play.api.libs.crypto.{ CookieSigner, CookieSignerProvider }
import play.mvc.Http

import scala.annotation.varargs

/**
 * HTTP Flash scope.
 *
 * Flash data are encoded into an HTTP cookie, and can only contain simple `String` values.
 */
case class Flash(data: Map[String, String] = Map.empty[String, String]) {

  /**
   * Optionally returns the flash value associated with a key.
   */
  def get(key: String): Option[String] = data.get(key)

  /**
   * Returns `true` if this flash scope is empty.
   */
  def isEmpty: Boolean = data.isEmpty

  /**
   * Adds a value to the flash scope, and returns a new flash scope.
   *
   * For example:
   * {{{
   * flash + ("success" -> "Done!")
   * }}}
   *
   * @param kv the key-value pair to add
   * @return the modified flash scope
   */
  def +(kv: (String, String)): Flash = {
    require(kv._2 != null, "Cookie values cannot be null")
    copy(data + kv)
  }

  /**
   * Adds a value to the flash scope, and returns a new flash scope.
   *
   * This is an alias method to [[+]].
   *
   * @param kv the key-value pair to add
   * @return the modified flash scope
   */
  def add(kv: (String, String)): Flash = this + kv

  /**
   * Adds a number of elements provided by the given map object
   * and returns a new flash scope with the added elements.
   */
  def ++(kvs: (String, String)*): Flash = {
    copy(data ++ kvs)
  }

  /**
   * Adds a number of elements provided by the given map object
   * and returns a new flash scope with the added elements.
   */
  def addAll(kvs: Map[String, String]): Flash = {
    copy(data ++ kvs)
  }

  /**
   * Removes values from the flash scope.
   *
   * For example:
   * {{{
   * flash - "success"
   * }}}
   *
   * @param keys the keys to remove
   * @return the modified flash scope
   */
  def -(keys: String*): Flash = remove(keys: _*)

  /**
   * Removes values from the flash scope.
   *
   * @param keys the keys to remove
   * @return the modified flash scope
   */
  @varargs def remove(keys: String*): Flash = copy(data -- keys)

  /**
   * Retrieves the flash value that is associated with the given key.
   */
  def apply(key: String): String = data(key)

  lazy val asJava: Http.Flash = new Http.Flash(this)
}

/**
 * Helper utilities to manage the Flash cookie.
 */
trait FlashCookieBaker extends CookieBaker[Flash] with CookieDataCodec {

  def config: FlashConfiguration

  def COOKIE_NAME: String = config.cookieName

  lazy val emptyCookie = new Flash

  override def path: String = config.path
  override def secure: Boolean = config.secure
  override def httpOnly: Boolean = config.httpOnly
  override def domain: Option[String] = config.domain
  override def sameSite: Option[Cookie.SameSite] = config.sameSite

  def deserialize(data: Map[String, String]): Flash = new Flash(data)

  def serialize(flash: Flash): Map[String, String] = flash.data

}

class DefaultFlashCookieBaker @Inject() (
    val config: FlashConfiguration,
    val secretConfiguration: SecretConfiguration,
    val cookieSigner: CookieSigner)
  extends FlashCookieBaker with FallbackCookieDataCodec {

  def this() = this(FlashConfiguration(), SecretConfiguration(), new CookieSignerProvider(SecretConfiguration()).get)

  override val jwtCodec: JWTCookieDataCodec = DefaultJWTCookieDataCodec(secretConfiguration, config.jwt)
  override val signedCodec: UrlEncodedCookieDataCodec = DefaultUrlEncodedCookieDataCodec(isSigned, cookieSigner)
}

class LegacyFlashCookieBaker @Inject() (
    val config: FlashConfiguration,
    val secretConfiguration: SecretConfiguration,
    val cookieSigner: CookieSigner)
  extends FlashCookieBaker with UrlEncodedCookieDataCodec {
  def this() = this(FlashConfiguration(), SecretConfiguration(), new CookieSignerProvider(SecretConfiguration()).get)
}

object Flash extends CookieBaker[Flash] with UrlEncodedCookieDataCodec {

  val emptyCookie = new Flash

  def fromJavaFlash(javaFlash: play.mvc.Http.Flash): Flash = javaFlash.asScala

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override val isSigned: Boolean = false

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  def config: FlashConfiguration = HttpConfiguration.current.flash

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def path: String = HttpConfiguration.current.context

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def cookieSigner: CookieSigner = play.api.libs.Crypto.cookieSigner

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def COOKIE_NAME: String = config.cookieName

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def secure: Boolean = config.secure

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def maxAge = None

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def httpOnly: Boolean = config.httpOnly

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def domain: Option[String] = config.domain

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def sameSite: Option[Cookie.SameSite] = config.sameSite

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def deserialize(data: Map[String, String]): Flash = new Flash(data)

  @deprecated("Inject play.api.mvc.FlashCookieBaker instead", "2.6.0")
  override def serialize(flash: Flash): Map[String, String] = flash.data

}
