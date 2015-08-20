/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.filters.csrf

import java.net.{ URLDecoder, URLEncoder }
import java.util.Locale

import akka.stream.Materializer
import akka.stream.scaladsl.{ Keep, Source, Sink, Flow }
import akka.stream.stage.{ DetachedContext, DetachedStage, PushStage, Context }
import akka.util.ByteString
import play.api.libs.streams.Accumulator
import play.api.mvc._
import play.api.http.HeaderNames._
import play.core.parsers.Multipart
import play.filters.csrf.CSRF._
import scala.concurrent.Future

/**
 * An action that provides CSRF protection.
 *
 * @param config The CSRF configuration.
 * @param tokenProvider A token provider to use.
 * @param next The composed action that is being protected.
 * @param errorHandler handling failed token error.
 */
class CSRFAction(next: EssentialAction,
    config: CSRFConfig = CSRFConfig(),
    tokenProvider: TokenProvider = SignedTokenProvider,
    errorHandler: => ErrorHandler = CSRF.DefaultErrorHandler)(implicit mat: Materializer) extends EssentialAction {

  import CSRFAction._
  import play.api.libs.iteratee.Execution.Implicits.trampoline

  private def checkFailed(req: RequestHeader, msg: String): Accumulator[ByteString, Result] =
    Accumulator.done(clearTokenIfInvalid(req, config, errorHandler, msg))

  def apply(request: RequestHeader) = {

    // this function exists purely to aid readability
    def continue = next(request)

    // Only filter unsafe methods and content types
    if (config.checkMethod(request.method) && config.checkContentType(request.contentType)) {

      if (checkCsrfBypass(request, config)) {
        continue
      } else {

        // Only proceed with checks if there is an incoming token in the header, otherwise there's no point
        getTokenFromHeader(request, config).map { headerToken =>

          // First check if there's a token in the query string or header, if we find one, don't bother handling the body
          getTokenFromQueryString(request, config).map { queryStringToken =>

            if (tokenProvider.compareTokens(headerToken, queryStringToken)) {
              filterLogger.trace("[CSRF] Valid token found in query string")
              continue
            } else {
              filterLogger.trace("[CSRF] Check failed because invalid token found in query string: " + queryStringToken)
              checkFailed(request, "Bad CSRF token found in query String")
            }

          } getOrElse {

            // Check the body
            request.contentType match {
              case Some("application/x-www-form-urlencoded") =>
                checkFormBody(request, next, headerToken, config.tokenName)
              case Some("multipart/form-data") =>
                checkMultipartBody(request, next, headerToken, config.tokenName)
              // No way to extract token from other content types
              case Some(content) =>
                filterLogger.trace(s"[CSRF] Check failed because $content request")
                checkFailed(request, s"No CSRF token found for $content body")
              case None =>
                filterLogger.trace(s"[CSRF] Check failed because request without content type")
                checkFailed(request, s"No CSRF token found for body without content type")
            }

          }
        } getOrElse {

          filterLogger.trace("[CSRF] Check failed because no token found in headers")
          checkFailed(request, "No CSRF token found in headers")

        }
      }
    } else if (getTokenFromHeader(request, config).isEmpty && config.createIfNotFound(request)) {

      // No token in header and we have to create one if not found, so create a new token
      val newToken = tokenProvider.generateToken

      // The request
      val requestWithNewToken = request.copy(tags = request.tags + (Token.RequestTag -> newToken))

      // Once done, add it to the result
      next(requestWithNewToken).map(result =>
        CSRFAction.addTokenToResponse(config, newToken, request, result))

    } else {
      filterLogger.trace("[CSRF] No check necessary")
      next(request)
    }
  }

  private def checkFormBody = checkBody(extractTokenFromFormBody) _
  private def checkMultipartBody(request: RequestHeader, action: EssentialAction, tokenFromHeader: String, tokenName: String) = {
    (for {
      mt <- request.mediaType
      maybeBoundary <- mt.parameters.find(_._1.equalsIgnoreCase("boundary"))
      boundary <- maybeBoundary._2
    } yield {
      checkBody(extractTokenFromMultipartFormDataBody(ByteString(boundary)))(request, action, tokenFromHeader, tokenName)
    }).getOrElse(checkFailed(request, "No boundary found in multipart/form-data request"))
  }

  private def checkBody[T](extractor: (ByteString, String) => Option[String])(request: RequestHeader, action: EssentialAction, tokenFromHeader: String, tokenName: String) = {
    // We need to ensure that the action isn't actually executed until the body is validated.
    // To do that, we use Flow.splitWhen(_ => false).  This basically says, give me a Source
    // containing all the elements when you receive the first element.  Our BodyHandler doesn't
    // output any part of the body until it has validated the CSRF check, so we know that
    // the source is validated. Then using a Sink.head, we turn that Source into an Accumulator,
    // which we can then map to execute and feed into our action.
    // CSRF check failures are used by failing the stream with a NoTokenInBody exception.
    Accumulator(
      Flow[ByteString].transform(() => new BodyHandler(config, { body =>
        if (extractor(body, tokenName).fold(false)(tokenProvider.compareTokens(_, tokenFromHeader))) {
          filterLogger.trace("[CSRF] Valid token found in body")
          true
        } else {
          filterLogger.trace("[CSRF] Check failed because no or invalid token found in body")
          false
        }
      }))
        .splitWhen(_ => false)
        .toMat(Sink.head[Source[ByteString, _]])(Keep.right)
    ).mapFuture { validatedBodySource =>
        action(request).run(validatedBodySource)
      }.recoverWith {
        case NoTokenInBody => clearTokenIfInvalid(request, config, errorHandler, "No CSRF token found in body")
      }
  }

  /**
   * Does a very simple parse of the form body to find the token, if it exists.
   */
  private def extractTokenFromFormBody(body: ByteString, tokenName: String): Option[String] = {
    val tokenEquals = ByteString(URLEncoder.encode(tokenName, "utf-8")) ++ ByteString('=')

    // First check if it's the first token
    if (body.startsWith(tokenEquals)) {
      Some(URLDecoder.decode(body.drop(tokenEquals.size).takeWhile(_ != '&').utf8String, "utf-8"))
    } else {
      val andTokenEquals = ByteString('&') ++ tokenEquals
      val index = body.indexOfSlice(andTokenEquals)
      if (index == -1) {
        None
      } else {
        Some(URLDecoder.decode(body.drop(index + andTokenEquals.size).takeWhile(_ != '&').utf8String, "utf-8"))
      }
    }
  }

  /**
   * Does a very simple multipart/form-data parse to find the token if it exists.
   */
  private def extractTokenFromMultipartFormDataBody(boundary: ByteString)(body: ByteString, tokenName: String): Option[String] = {
    val crlf = ByteString("\r\n")
    val boundaryLine = ByteString("\r\n--") ++ boundary

    /**
     * A boundary will start with CRLF, unless it's the first boundary in the body.  So that we don't have to handle
     * the first boundary differently, prefix the whole body with CRLF.
     */
    val prefixedBody = crlf ++ body

    /**
     * Extract the headers from the given position.
     *
     * This is invoked recursively, and exits when it reaches the end of stream, or a blank line (indicating end of
     * headers).  It returns the headers, and the position of the first byte after the headers.  The headers are all
     * converted to lower case.
     */
    def extractHeaders(position: Int): (Int, List[(String, String)]) = {
      // If it starts with CRLF, we've reached the end of the headers
      if (prefixedBody.startsWith(crlf, position)) {
        (position + 2) -> Nil
      } else {
        // Read up to the next CRLF
        val nextCrlf = prefixedBody.indexOfSlice(crlf, position)
        if (nextCrlf == -1) {
          // Technically this is a protocol error
          position -> Nil
        } else {
          val header = prefixedBody.slice(position, nextCrlf).utf8String
          header.split(":", 2) match {
            case Array(_) =>
              // Bad header, ignore
              extractHeaders(nextCrlf + 2)
            case Array(key, value) =>
              val (endIndex, headers) = extractHeaders(nextCrlf + 2)
              endIndex -> ((key.trim().toLowerCase(Locale.ENGLISH) -> value.trim()) :: headers)
          }
        }
      }
    }

    /**
     * Find the token.
     *
     * This is invoked recursively, once for each part found.  It finds the start of the next part, then extracts
     * the headers, and if the header has a name of our token name, then it extracts the body, and returns that,
     * otherwise it moves onto the next part.
     */
    def findToken(position: Int): Option[String] = {
      // Find the next boundary from position
      prefixedBody.indexOfSlice(boundaryLine, position) match {
        case -1 => None
        case nextBoundary =>
          // Progress past the CRLF at the end of the boundary
          val nextCrlf = prefixedBody.indexOfSlice(crlf, nextBoundary + boundaryLine.size)
          if (nextCrlf == -1) {
            None
          } else {
            val startOfNextPart = nextCrlf + 2
            // Extract the headers
            val (startOfPartData, headers) = extractHeaders(startOfNextPart)
            headers.toMap match {
              case Multipart.PartInfoMatcher(name) if name == tokenName =>
                // This part is the token, find the next boundary
                val endOfData = prefixedBody.indexOfSlice(boundaryLine, startOfPartData)
                if (endOfData == -1) {
                  None
                } else {
                  // Extract the token value
                  Some(prefixedBody.slice(startOfPartData, endOfData).utf8String)
                }
              case _ =>
                // Find the next part
                findToken(startOfPartData)
            }
          }
      }
    }

    findToken(0)
  }

}

/**
 * A body handler.
 *
 * This will buffer the body until it reaches the end of stream, or until the buffer limit is reached.
 *
 * Once it has finished buffering, it will attempt to find the token in the body, and if it does, validates it,
 * failing the stream if it's invalid.  If it's valid, it forwards the buffered body, and then stops buffering and
 * continues forwarding the body as is (or finishes if the stream was finished).
 */
private class BodyHandler(config: CSRFConfig, checkBody: ByteString => Boolean) extends DetachedStage[ByteString, ByteString] {
  var buffer: ByteString = ByteString.empty
  var next: ByteString = null
  var continue = false

  def onPush(elem: ByteString, ctx: DetachedContext[ByteString]) = {
    if (continue) {
      // Standard contract for forwarding as is in DetachedStage
      if (ctx.isHoldingDownstream) {
        ctx.pushAndPull(elem)
      } else {
        next = elem
        ctx.holdUpstream()
      }
    } else {
      if (buffer.size + elem.size > config.postBodyBuffer) {
        // We've finished buffering up to the configured limit, try to validate
        buffer ++= elem
        if (checkBody(buffer)) {
          // Switch to continue, and push the buffer
          continue = true
          if (ctx.isHoldingDownstream) {
            val toPush = buffer
            buffer = null
            ctx.pushAndPull(toPush)
          } else {
            next = buffer
            buffer = null
            ctx.holdUpstream()
          }
        } else {
          // CSRF check failed
          ctx.fail(CSRFAction.NoTokenInBody)
        }
      } else {
        // Buffer
        buffer ++= elem
        ctx.pull()
      }
    }
  }

  def onPull(ctx: DetachedContext[ByteString]) = {
    if (continue) {
      // Standard contract for forwarding as is in DetachedStage
      if (next != null) {
        val toPush = next
        next = null
        if (ctx.isFinishing) {
          ctx.pushAndFinish(toPush)
        } else {
          ctx.pushAndPull(toPush)
        }
      } else {
        if (ctx.isFinishing) {
          ctx.finish()
        } else {
          ctx.holdDownstream()
        }
      }
    } else {
      // Otherwise hold because we're buffering
      ctx.holdDownstream()
    }
  }

  override def onUpstreamFinish(ctx: DetachedContext[ByteString]) = {
    if (continue) {
      if (next != null) {
        ctx.absorbTermination()
      } else {
        ctx.finish()
      }
    } else {
      // CSRF check
      if (checkBody(buffer)) {
        if (ctx.isHoldingDownstream) {
          // If we have demand, push the buffer downstream.
          // This seems like it shouldn't work, since you shouldn't be allowed to pull when finishing.  But it does.
          // See https://github.com/akka/akka/issues/18285.
          ctx.pushAndPull(buffer)
        } else {
          // Otherwise, absorb the termination, and hold the buffer, and enter the continue state.
          next = buffer
          buffer = null
          continue = true
          ctx.absorbTermination()
        }
      } else {
        ctx.fail(CSRFAction.NoTokenInBody)
      }
    }
  }
}

object CSRFAction {

  private[csrf] object NoTokenInBody extends RuntimeException(null, null, false, false)

  /**
   * Get the header token, that is, the token that should be validated.
   */
  private[csrf] def getTokenFromHeader(request: RequestHeader, config: CSRFConfig) = {
    val cookieToken = config.cookieName.flatMap(cookie => request.cookies.get(cookie).map(_.value))
    val sessionToken = request.session.get(config.tokenName)
    cookieToken orElse sessionToken
  }

  private[csrf] def getTokenFromQueryString(request: RequestHeader, config: CSRFConfig) = {
    val queryStringToken = request.getQueryString(config.tokenName)
    val headerToken = request.headers.get(config.headerName)

    queryStringToken orElse headerToken
  }

  private[csrf] def checkCsrfBypass(request: RequestHeader, config: CSRFConfig): Boolean = {
    if (config.headerBypass) {
      if (request.headers.get(config.headerName).exists(_ == CSRFConfig.HeaderNoCheck)) {

        // Since injecting arbitrary header values is not possible with a CSRF attack, the presence of this header
        // indicates that this is not a CSRF attack
        filterLogger.trace("[CSRF] Bypassing check because " + config.headerName + ": " + CSRFConfig.HeaderNoCheck + " header found")
        true

      } else if (request.headers.get("X-Requested-With").isDefined) {

        // AJAX requests are not CSRF attacks either because they are restricted to same origin policy
        filterLogger.trace("[CSRF] Bypassing check because X-Requested-With header found")
        true
      } else {
        false
      }
    } else {
      false
    }
  }

  private[csrf] def addTokenToResponse(config: CSRFConfig, newToken: String, request: RequestHeader, result: Result) = {

    if (isCached(result)) {
      filterLogger.trace("[CSRF] Not adding token to cached response")
      result
    } else {
      filterLogger.trace("[CSRF] Adding token to result: " + result)

      config.cookieName.map {
        // cookie
        name =>
          result.withCookies(Cookie(name, newToken, path = Session.path, domain = Session.domain,
            secure = config.secureCookie, httpOnly = config.httpOnlyCookie))
      } getOrElse {

        val newSession = result.session(request) + (config.tokenName -> newToken)
        result.withSession(newSession)
      }
    }

  }

  private[csrf] def isCached(result: Result): Boolean =
    result.header.headers.get(CACHE_CONTROL).fold(false)(!_.contains("no-cache"))

  private[csrf] def clearTokenIfInvalid(request: RequestHeader, config: CSRFConfig, errorHandler: ErrorHandler, msg: String): Future[Result] = {
    import play.api.libs.iteratee.Execution.Implicits.trampoline

    errorHandler.handle(request, msg) map { result =>
      CSRF.getToken(request).fold(
        config.cookieName.flatMap { cookie =>
          request.cookies.get(cookie).map { token =>
            result.discardingCookies(DiscardingCookie(cookie, domain = Session.domain, path = Session.path,
              secure = config.secureCookie))
          }
        }.getOrElse {
          result.withSession(result.session(request) - config.tokenName)
        }
      )(_ => result)
    }
  }
}

/**
 * CSRF check action.
 *
 * Apply this to all actions that require a CSRF check.
 */
object CSRFCheck {

  private class CSRFCheckAction[A](config: CSRFConfig, tokenProvider: TokenProvider, errorHandler: ErrorHandler,
      wrapped: Action[A]) extends Action[A] {
    def parser = wrapped.parser
    def apply(request: Request[A]) = {

      // Maybe bypass
      if (CSRFAction.checkCsrfBypass(request, config) || !config.checkContentType(request.contentType)) {
        wrapped(request)
      } else {
        // Get token from header
        CSRFAction.getTokenFromHeader(request, config).flatMap { headerToken =>
          // Get token from query string
          CSRFAction.getTokenFromQueryString(request, config)
            // Or from body if not found
            .orElse({
              val form = request.body match {
                case body: play.api.mvc.AnyContent if body.asFormUrlEncoded.isDefined => body.asFormUrlEncoded.get
                case body: play.api.mvc.AnyContent if body.asMultipartFormData.isDefined => body.asMultipartFormData.get.asFormUrlEncoded
                case body: Map[_, _] => body.asInstanceOf[Map[String, Seq[String]]]
                case body: play.api.mvc.MultipartFormData[_] => body.asFormUrlEncoded
                case _ => Map.empty[String, Seq[String]]
              }
              form.get(config.tokenName).flatMap(_.headOption)
            })
            // Execute if it matches
            .collect {
              case queryToken if tokenProvider.compareTokens(queryToken, headerToken) => wrapped(request)
            }
        }.getOrElse {
          CSRFAction.clearTokenIfInvalid(request, config, errorHandler, "CSRF token check failed")
        }
      }
    }
  }

  /**
   * Wrap an action in a CSRF check.
   */
  def apply[A](action: Action[A], errorHandler: ErrorHandler = CSRF.DefaultErrorHandler, config: CSRFConfig = CSRFConfig.global): Action[A] =
    new CSRFCheckAction(config, new TokenProviderProvider(config).get, errorHandler, action)
}

/**
 * CSRF add token action.
 *
 * Apply this to all actions that render a form that contains a CSRF token.
 */
object CSRFAddToken {

  private class CSRFAddTokenAction[A](config: CSRFConfig, tokenProvider: TokenProvider, wrapped: Action[A]) extends Action[A] {
    def parser = wrapped.parser
    def apply(request: Request[A]) = {
      if (CSRFAction.getTokenFromHeader(request, config).isEmpty) {
        // No token in header and we have to create one if not found, so create a new token
        val newToken = tokenProvider.generateToken

        // The request
        val requestWithNewToken = new WrappedRequest(request) {
          override val tags = request.tags + (Token.RequestTag -> newToken)
        }

        // Once done, add it to the result
        import play.api.libs.iteratee.Execution.Implicits.trampoline
        wrapped(requestWithNewToken).map(result =>
          CSRFAction.addTokenToResponse(config, newToken, request, result))
      } else {
        wrapped(request)
      }
    }
  }

  /**
   * Wrap an action in an action that ensures there is a CSRF token.
   */
  def apply[A](action: Action[A], config: CSRFConfig = CSRFConfig.global): Action[A] =
    new CSRFAddTokenAction(config, new TokenProviderProvider(config).get, action)
}
