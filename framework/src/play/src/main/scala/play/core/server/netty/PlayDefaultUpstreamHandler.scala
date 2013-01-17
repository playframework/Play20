package play.core.server.netty

import scala.language.reflectiveCalls

import org.jboss.netty.buffer._
import org.jboss.netty.channel._
import org.jboss.netty.bootstrap._
import org.jboss.netty.channel.Channels._
import org.jboss.netty.handler.codec.http._
import org.jboss.netty.channel.socket.nio._
import org.jboss.netty.handler.stream._
import org.jboss.netty.handler.codec.http.HttpHeaders._
import org.jboss.netty.handler.codec.http.HttpHeaders.Names._
import org.jboss.netty.handler.codec.http.HttpHeaders.Values._
import org.jboss.netty.handler.ssl._

import org.jboss.netty.channel.group._
import java.util.concurrent._
import play.core._
import server.Server
import play.api._
import play.api.mvc._
import play.api.http.HeaderNames.X_FORWARDED_FOR
import play.api.libs.iteratee._
import play.api.libs.iteratee.Input._
import play.api.libs.concurrent._
import scala.collection.JavaConverters._
import scala.util.control.NonFatal


private[server] class PlayDefaultUpstreamHandler(server: Server, allChannels: DefaultChannelGroup) extends SimpleChannelUpstreamHandler with Helpers with WebSocketHandler with RequestBodyHandler {

  implicit val internalExecutionContext =  play.core.Execution.internalContext

  private val requestIDs = new java.util.concurrent.atomic.AtomicLong(0)

  override def exceptionCaught(ctx: ChannelHandlerContext, e: ExceptionEvent) {
    Logger.trace("Exception caught in Netty", e.getCause)
    e.getChannel.close()
  }

  override def channelConnected(ctx: ChannelHandlerContext, e: ChannelStateEvent) {
    Option(ctx.getPipeline.get(classOf[SslHandler])).map { sslHandler =>
      sslHandler.handshake()
    }
  }

  override def channelDisconnected(ctx: ChannelHandlerContext, e: ChannelStateEvent) {
    val rh = ctx.getAttachment
    if(rh!=null) play.api.Play.maybeApplication.foreach(_.global.onRequestCompletion(rh.asInstanceOf[RequestHeader]))
    ctx.setAttachment(null)
  }

  override def channelOpen(ctx: ChannelHandlerContext, e: ChannelStateEvent) {
    allChannels.add(e.getChannel)
  }

  override def messageReceived(ctx: ChannelHandlerContext, e: MessageEvent) {
    e.getMessage match {

      case nettyHttpRequest: HttpRequest =>

        Logger("play").trace("Http request received by netty: " + nettyHttpRequest)
        val keepAlive = isKeepAlive(nettyHttpRequest)
        val websocketableRequest = websocketable(nettyHttpRequest)
        val nettyVersion = nettyHttpRequest.getProtocolVersion
        val nettyUri = new QueryStringDecoder(nettyHttpRequest.getUri)
        val parameters = Map.empty[String, Seq[String]] ++ nettyUri.getParameters.asScala.mapValues(_.asScala)

        val rHeaders = getHeaders(nettyHttpRequest)

        def rRemoteAddress = e.getRemoteAddress match {
          case ra: java.net.InetSocketAddress => {
            val remoteAddress = ra.getAddress.getHostAddress
            (for {
              xff <- rHeaders.get(X_FORWARDED_FOR)
              app <- server.applicationProvider.get.right.toOption
              trustxforwarded <- app.configuration.getBoolean("trustxforwarded").orElse(Some(false))
              if remoteAddress == "127.0.0.1" || trustxforwarded
            } yield xff).getOrElse(remoteAddress)
          }
        }

        val requestHeader = new RequestHeader {
          val id = requestIDs.incrementAndGet
          val tags = Map.empty[String,String]
          def uri = nettyHttpRequest.getUri
          def path = nettyUri.getPath
          def method = nettyHttpRequest.getMethod.getName
          def version = nettyVersion.getText
          def queryString = parameters
          def headers = rHeaders
          lazy val remoteAddress = rRemoteAddress
          def username = None
        }
        //attach the request to the channel context for after cleaning
        ctx.setAttachment(requestHeader)

        // get handler for request
        val handler = server.getHandlerFor(requestHeader)

        handler match {
          //execute normal action
          case Right((action: EssentialAction, app)) =>
            val a = EssentialAction{ rh =>
              Iteratee.flatten(action(rh).map {
                case r: PlainResult => cleanFlashCookie(requestHeader)(r)
                case a:AsyncResult => a.transform(cleanFlashCookie(requestHeader))
              }.unflatten.extend1{
                case Redeemed(it) => it.it
                case Thrown(e) => Done(app.handleError(requestHeader, e),Input.Empty)
              })
            }
            handleAction(a,Some(app))

          case Right((ws @ WebSocket(f), app)) if (websocketableRequest.check) =>
            Logger("play").trace("Serving this request with: " + ws)

            try {
              val enumerator = websocketHandshake(ctx, nettyHttpRequest, e)(ws.frameFormatter)
              f(requestHeader)(enumerator, socketOut(ctx)(ws.frameFormatter))
            } catch {
              case NonFatal(e) => e.printStackTrace()
            }

          //handle bad websocket request
          case Right((WebSocket(_), app)) =>
            Logger("play").trace("Bad websocket request")
            val a = EssentialAction(_ => Done(Results.BadRequest,Input.Empty))
            handleAction(a,Some(app))

          case Left(e) =>
            Logger("play").trace("No handler, got direct result: " + e)
            val a = EssentialAction(_ => Done(e,Input.Empty))
            handleAction(a,None)

        }

        def handleAction(a:EssentialAction,app:Option[Application]){
          Logger("play").trace("Serving this request with: " + a)

          val filteredAction = app.map(_.global).getOrElse(DefaultGlobal).doFilter(a)

          val eventuallyBodyParser = scala.concurrent.Future(filteredAction(requestHeader))(play.api.libs.concurrent.Execution.defaultContext)

          requestHeader.headers.get("Expect").filter(_ == "100-continue").foreach { _ =>
            eventuallyBodyParser.flatMap(_.unflatten).map {
              case Step.Cont(k) =>
                val continue = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE)
                //TODO wait for the promise of the write
                e.getChannel.write(continue)
              case _ =>
            }
          }

          val eventuallyResultIteratee = if (nettyHttpRequest.isChunked) {

            val (result, handler) = newRequestBodyHandler(eventuallyBodyParser, allChannels, server)

            val p: ChannelPipeline = ctx.getChannel().getPipeline()
            p.replace("handler", "handler", handler)

            result

          } else {

            lazy val bodyEnumerator = {
              val body = {
                val cBuffer = nettyHttpRequest.getContent()
                val bytes = new Array[Byte](cBuffer.readableBytes())
                cBuffer.readBytes(bytes)
                bytes
              }
              Enumerator(body).andThen(Enumerator.enumInput(EOF))
            }

            eventuallyBodyParser.flatMap(it => bodyEnumerator |>> it): scala.concurrent.Future[Iteratee[Array[Byte], Result]]

          }

          //mapping netty request to Play's
          val response = new Response {
            def handle(result: Result) = handleResult(result)
          }
          val eventuallyResult = eventuallyResultIteratee.flatMap(it => it.run)
          eventuallyResult.extend1 {
            case Redeemed(r) => response.handle(r)

            case Thrown(error) =>
              Logger("play").error("Cannot invoke the action, eventually got an error: " + error)
              response.handle( app.map(_.handleError(requestHeader, error)).getOrElse(DefaultGlobal.onError(requestHeader, error)))
              e.getChannel.setReadable(true)
          }
        }

        def handleResult(result: Result) {
          result match {

            case AsyncResult(p) => p.extend1 {
              case Redeemed(v) => handleResult(v)
              case Thrown(e) => {
                server.applicationProvider.get match {
                  case Right(app) => handleResult(app.handleError(requestHeader, e))
                  case Left(_) => handleResult(Results.InternalServerError)
                }
              }
            }

            case r@SimpleResult(ResponseHeader(status, headers), body) if (!websocketableRequest.check) => {
              val nettyResponse = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(status))

              Logger("play").trace("Sending simple result: " + r)

              // Set response headers
              setNettyHeaders(headers.filterNot(_ ==(CONTENT_LENGTH, "-1")), nettyResponse)

              // Response header Connection: Keep-Alive is needed for HTTP 1.0
              if (keepAlive && nettyVersion == HttpVersion.HTTP_1_0) {
                nettyResponse.setHeader(CONNECTION, KEEP_ALIVE)
              }

              // Stream the result
              val bodyIteratee = headers.get(CONTENT_LENGTH).map {
                contentLength => {
                  def iterateeWrite(message: Object): Iteratee[r.BODY_CONTENT, Unit] = {
                    Iteratee.flatten(
                      NettyPromise(e.getChannel.write(message))
                        .map(_ => if (e.getChannel.isConnected()) Cont(step) else Done((), Input.Empty: Input[r.BODY_CONTENT])))
                  }
                  def step(in: Input[r.BODY_CONTENT]): Iteratee[r.BODY_CONTENT, Unit] = (e.getChannel.isConnected(), in) match {
                    case (true, Input.El(x)) =>
                      iterateeWrite(ChannelBuffers.wrappedBuffer(r.writeable.transform(x)))
                    case (true, Input.Empty) => Cont(step)
                    case (_, in) => Done((), in)
                  }
                  iterateeWrite(nettyResponse)
                }
              }.getOrElse {

                // No Content-Length header specified, buffer in-memory
                val channelBuffer = ChannelBuffers.dynamicBuffer(512)
                val writer: Function2[ChannelBuffer, r.BODY_CONTENT, Unit] = (c, x) => c.writeBytes(r.writeable.transform(x))
                val stringIteratee = Iteratee.fold(channelBuffer)((c, e: r.BODY_CONTENT) => {
                  writer(c, e); c
                })
                Enumeratee.grouped(stringIteratee) &>> Cont {
                  case Input.El(buffer) =>
                    nettyResponse.setHeader(CONTENT_LENGTH, channelBuffer.readableBytes)
                    nettyResponse.setContent(buffer)
                    val f = e.getChannel.write(nettyResponse)
                    val p = NettyPromise(f)
                    if (!keepAlive) f.addListener(ChannelFutureListener.CLOSE)
                    Iteratee.flatten(p.map(_ => Done(1, Input.Empty: Input[org.jboss.netty.buffer.ChannelBuffer])))

                  case other => Error("unexepected input", other)
                }
              }
              (body |>>> bodyIteratee).extend1 {
                case Redeemed(_) =>
                  play.api.Play.maybeApplication.foreach(_.global.onRequestCompletion(requestHeader))
                  ctx.setAttachment(null)
                  if (e.getChannel.isConnected() && !keepAlive) e.getChannel.close()
                case Thrown(ex) =>
                  Logger("play").debug(ex.toString)
                  if (e.getChannel.isConnected()) e.getChannel.close()
              }
            }

            case r@ChunkedResult(ResponseHeader(status, headers), chunks) => {

              Logger("play").trace("Sending chunked result: " + r)

              val nettyResponse = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(status))

              // Copy headers to netty response
              setNettyHeaders(headers, nettyResponse)

              nettyResponse.setHeader(TRANSFER_ENCODING, HttpHeaders.Values.CHUNKED)
              nettyResponse.setChunked(true)

              val bodyIteratee = {
                def iterateeWrite(message: Object): Iteratee[r.BODY_CONTENT, Unit] = {
                  Iteratee.flatten(
                    NettyPromise(e.getChannel.write(message))
                      .extend1 {
                      case Redeemed(_) => if (e.getChannel.isConnected()) Cont(step) else Done((), Input.Empty: Input[r.BODY_CONTENT])
                      case Thrown(ex) =>
                        Logger("play").debug(ex.toString)
                        if (e.getChannel.isConnected()) e.getChannel.close()
                        throw ex
                    })
                }
                def step(in: Input[r.BODY_CONTENT]): Iteratee[r.BODY_CONTENT, Unit] = (e.getChannel.isConnected(), in) match {
                  case (true, Input.El(x)) =>
                    iterateeWrite(new DefaultHttpChunk(ChannelBuffers.wrappedBuffer(r.writeable.transform(x))))
                  case (true, Input.Empty) => Cont(step)
                  case (_, in) => Done((), in)
                }
                iterateeWrite(nettyResponse)
              }

              chunks apply bodyIteratee.map {
                _ =>
                  play.api.Play.maybeApplication.foreach(_.global.onRequestCompletion(requestHeader))
                  if (e.getChannel.isConnected()) {
                    val f = e.getChannel.write(HttpChunk.LAST_CHUNK);
                    if (!keepAlive) f.addListener(ChannelFutureListener.CLOSE)
                  }
              }
            }

            case _ =>
              val nettyResponse = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR)
              nettyResponse.setContent(ChannelBuffers.EMPTY_BUFFER)
              nettyResponse.setHeader(CONTENT_LENGTH, 0)
              val f = e.getChannel.write(nettyResponse)
              if (!keepAlive) f.addListener(ChannelFutureListener.CLOSE)
          }
        }

      case unexpected => Logger("play").error("Oops, unexpected message received in NettyServer (please report this problem): " + unexpected)

    }
  }

}
