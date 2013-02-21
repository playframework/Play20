package controllers

import play.api._
import play.api.mvc._
import play.api.libs._
import play.api.libs.iteratee._

import Play.current

import java.io._
import java.net.JarURLConnection
import org.joda.time.format.{ DateTimeFormatter, DateTimeFormat }
import org.joda.time.DateTimeZone
import collection.JavaConverters._
import scala.util.control.NonFatal
import collection.concurrent.TrieMap
import org.apache.commons.codec.digest.DigestUtils

/**
 * Controller that serves static resources.
 *
 * Resources are searched in the classpath.
 *
 * It handles Last-Modified and ETag header automatically.
 * If a gzipped version of a resource is found (Same resource name with the .gz suffix), it is served instead.
 *
 * You can set a custom Cache directive for a particular resource if needed. For example in your application.conf file:
 *
 * {{{
 * "assets.cache./public/images/logo.png" = "max-age=3600"
 * }}}
 *
 * You can use this controller in any application, just by declaring the appropriate route. For example:
 * {{{
 * GET     /assets/\uFEFF*file               controllers.Assets.at(path="/public", file)
 * }}}
 */
object Assets extends AssetsBuilder

object Asset {
  /**
   * /path/filename-fingerprint.ext
   * /path/filename-.ext
   */
  implicit def pathBinder = new PathBindable[Asset] {
    def bind(key: String, value: String) = {
      val lastDot = value.lastIndexOf('.')
      val file = value.slice(0, value.lastIndexOf('-', lastDot)) + value.slice(lastDot, value.length)
      Right(Asset(file))
    }

    def unbind(key: String, value: Asset) = {
      val resourceName = Option(value.path + "/" + value.file).map(name => if (name.startsWith("/")) name else ("/" + name)).get
      val fingerprint = Play.resource(resourceName).flatMap {
        fingerprintFor(_)
      }.getOrElse("fingerprint-error-file-not-found")
      val lastDot = value.file.lastIndexOf('.')
      value.file.slice(0, lastDot) + '-' + fingerprint + value.file.slice(lastDot, value.file.length)
    }
  }

  import scala.language.implicitConversions

  implicit def stringToAsset(asset: String) = {
    Asset(asset)
  }

  private val fingerprints = new TrieMap[String, Option[String]]

  def fingerprintFor(resource: java.net.URL): Option[String] = {
    def fingerprintSha1Hex: Option[String] = {
      try {
        val stream = resource.openStream()
        try {
          if (stream.available < 0) {
            None
          } else {
            Some(DigestUtils.sha1Hex(stream))
          }
        } finally {
          stream.close()
        }
      } catch {
        case e: IOException => None
      }
    }
    if (Play.isDev) {
      fingerprintSha1Hex
    } else {
      fingerprints.getOrElseUpdate(resource.toExternalForm, fingerprintSha1Hex)
    }
  }

}

case class Asset(file: String, path: String = "/public")

class AssetsBuilder extends Controller {

  private val timeZoneCode = "GMT"

  //Dateformatter is immutable and threadsafe
  private val df: DateTimeFormatter =
    DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss '" + timeZoneCode + "'").withLocale(java.util.Locale.ENGLISH).withZone(DateTimeZone.forID(timeZoneCode))

  //Dateformatter is immutable and threadsafe
  private val dfp: DateTimeFormatter =
    DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss").withLocale(java.util.Locale.ENGLISH).withZone(DateTimeZone.forID(timeZoneCode))

  private val parsableTimezoneCode = " " + timeZoneCode

  private lazy val defaultCharSet = Play.configuration.getString("default.charset").getOrElse("utf-8")

  private def addCharsetIfNeeded(mimeType: String): String =
    if (MimeTypes.isText(mimeType))
      "; charset=" + defaultCharSet
    else ""

  /**
   * Generates an `Action` that serves a static resource.
   *
   * @param path the root folder for searching the static resource files, such as `"/public"`
   * @param file the file part extracted from the URL
   */
  def at(path: String, file: String): Action[AnyContent] = Action { request =>
    // -- LastModified handling

    def parseDate(date: String): Option[java.util.Date] = try {
      //jodatime does not parse timezones, so we handle that manually
      val d = dfp.parseDateTime(date.replace(parsableTimezoneCode, "")).toDate
      Some(d)
    } catch {
      case NonFatal(_) => None
    }

    val resourceName = Option(path + "/" + file).map(name => if (name.startsWith("/")) name else ("/" + name)).get

    if (new File(resourceName).isDirectory || !new File(resourceName).getCanonicalPath.startsWith(new File(path).getCanonicalPath)) {
      NotFound
    } else {

      val gzippedResource = Play.resource(resourceName + ".gz")

      val resource = {
        gzippedResource.map(_ -> true)
          .filter(_ => request.headers.get(ACCEPT_ENCODING).map(_.split(',').exists(_.trim == "gzip" && Play.isProd)).getOrElse(false))
          .orElse(Play.resource(resourceName).map(_ -> false))
      }

      resource.map {

        case (url, _) if new File(url.getFile).isDirectory => NotFound

        case (url, isGzipped) => {

          lazy val (length, resourceData) = {
            val stream = url.openStream()
            try {
              (stream.available, Enumerator.fromStream(stream))
            } catch {
              case _ => (-1, Enumerator[Array[Byte]]())
            }
          }

          if (length == -1) {
            NotFound
          } else {
            request.headers.get(IF_NONE_MATCH).flatMap { ifNoneMatch =>
              etagFor(url).filter(_ == ifNoneMatch)
            }.map(_ => NotModified).getOrElse {
              request.headers.get(IF_MODIFIED_SINCE).flatMap(parseDate).flatMap { ifModifiedSince =>
                lastModifiedFor(url).flatMap(parseDate).filterNot(lastModified => lastModified.after(ifModifiedSince))
              }.map(_ => NotModified.withHeaders(
                DATE -> df.print({ new java.util.Date }.getTime))).getOrElse {

                // Prepare a streamed response
                val response = SimpleResult(
                  header = ResponseHeader(OK, Map(
                    CONTENT_LENGTH -> length.toString,
                    CONTENT_TYPE -> MimeTypes.forFileName(file).map(m => m + addCharsetIfNeeded(m)).getOrElse(BINARY),
                    DATE -> df.print({ new java.util.Date }.getTime))),
                  resourceData)

                // If there is a gzipped version, even if the client isn't accepting gzip, we need to specify the
                // Vary header so proxy servers will cache both the gzip and the non gzipped version
                val gzippedResponse = (gzippedResource.isDefined, isGzipped) match {
                  case (true, true) => response.withHeaders(VARY -> ACCEPT_ENCODING, CONTENT_ENCODING -> "gzip")
                  case (true, false) => response.withHeaders(VARY -> ACCEPT_ENCODING)
                  case _ => response
                }

                // Add Etag if we are able to compute it
                val taggedResponse = etagFor(url).map(etag => gzippedResponse.withHeaders(ETAG -> etag)).getOrElse(gzippedResponse)
                val lastModifiedResponse = lastModifiedFor(url).map(lastModified => taggedResponse.withHeaders(LAST_MODIFIED -> lastModified)).getOrElse(taggedResponse)

                // Add Cache directive if configured
                val cachedResponse = lastModifiedResponse.withHeaders(CACHE_CONTROL -> {
                  Play.configuration.getString("\"assets.cache." + resourceName + "\"").getOrElse(Play.mode match {
                    case Mode.Prod => Play.configuration.getString("assets.defaultCache").getOrElse("max-age=3600")
                    case _ => "no-cache"
                  })
                })

                cachedResponse

              }: Result

            }

          }

        }

      }.getOrElse(NotFound)

    }

  }

  /**
   * Generates an `Action` that serves a static resource.
   *
   * @param path the root folder for searching the static resource files, such as `"/public"`
   * @param file the file part extracted from the URL
   */
  def versionedAt(path: String, file: Asset): Action[AnyContent] = {
    Assets.at(file.path, file.file)
  }

  private val lastModifieds = (new java.util.concurrent.ConcurrentHashMap[String, String]()).asScala

  private def lastModifiedFor(resource: java.net.URL): Option[String] = {
    lastModifieds.get(resource.toExternalForm).filter(_ => Play.isProd).orElse {
      val maybeLastModified = resource.getProtocol match {
        case "file" => Some(df.print({ new java.util.Date(new java.io.File(resource.getPath).lastModified).getTime }))
        case "jar" => {
          resource.getPath.split('!').drop(1).headOption.flatMap { fileNameInJar =>
            Option(resource.openConnection)
              .collect { case c: JarURLConnection => c }
              .flatMap(c => Option(c.getJarFile.getJarEntry(fileNameInJar.drop(1))))
              .map(_.getTime)
              .filterNot(_ == 0)
              .map(lastModified => df.print({ new java.util.Date(lastModified) }.getTime))
          }
        }
        case _ => None
      }
      maybeLastModified.foreach(lastModifieds.put(resource.toExternalForm, _))
      maybeLastModified
    }
  }

  // -- ETags handling

  private val etags = (new java.util.concurrent.ConcurrentHashMap[String, String]()).asScala

  protected def etagFor(resource: java.net.URL): Option[String] = {
    etags.get(resource.toExternalForm).filter(_ => Play.isProd).orElse {
      val maybeEtag = lastModifiedFor(resource).map(_ + " -> " + resource.toExternalForm).map("\"" + Codecs.sha1(_) + "\"")
      maybeEtag.foreach(etags.put(resource.toExternalForm, _))
      maybeEtag
    }
  }

}

