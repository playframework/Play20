/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.it.auth

import javax.inject.Inject

import play.api.Application
import play.api.i18n.MessagesApi
import play.api.mvc.Security.{ AuthenticatedBuilder, AuthenticatedRequest }
import play.api.mvc._
import play.api.test._

import scala.concurrent.{ ExecutionContext, Future }

class SecuritySpec extends PlaySpecification {

  "AuthenticatedBuilder" should {
    "block unauthenticated requests" in withApplication { implicit app =>
      status(TestAction(app) { req: Security.AuthenticatedRequest[_, String] =>
        Results.Ok(req.user)
      }(FakeRequest())) must_== UNAUTHORIZED
    }
    "allow authenticated requests" in withApplication { implicit app =>
      val result = TestAction(app) { req: Security.AuthenticatedRequest[_, String] =>
        Results.Ok(req.user)
      }(FakeRequest().withSession("username" -> "john"))
      status(result) must_== OK
      contentAsString(result) must_== "john"
    }

    "allow use as an ActionBuilder" in withApplication { implicit app =>
      val result = Authenticated(app) { req: AuthenticatedDbRequest[_] =>
        Results.Ok(s"${req.conn.name}:${req.user.name}")
      }(FakeRequest().withSession("user" -> "Phil"))
      status(result) must_== OK
      contentAsString(result) must_== "fake:Phil"
    }
  }

  "AuthenticatedActionBuilder" should {

    "be injected using Guice" in new WithApplication() with Injecting {
      val builder = inject[AuthenticatedActionBuilder]
      val result = builder.apply { req =>
        Results.Ok(s"${req.messages("derp")}:${req.user.name}")
      }(FakeRequest().withSession("user" -> "Phil"))
      status(result) must_== OK
      contentAsString(result) must_== "derp:Phil"
    }

  }

  def TestAction(implicit app: Application) =
    AuthenticatedBuilder(app.injector.instanceOf[BodyParsers.Default])(app.materializer.executionContext)

  def getUserFromRequest(req: RequestHeader) = req.session.get("user") map (User(_))

  class AuthenticatedDbRequest[A](val user: User, val conn: Connection, request: Request[A]) extends WrappedRequest[A](request)

  def Authenticated(implicit app: Application) = new ActionBuilder[AuthenticatedDbRequest, AnyContent] {
    lazy val executionContext = app.materializer.executionContext
    lazy val parser = app.injector.instanceOf[PlayBodyParsers].default
    def invokeBlock[A](request: Request[A], block: (AuthenticatedDbRequest[A]) => Future[Result]) = {
      val builder = AuthenticatedBuilder(req => getUserFromRequest(req), app.injector.instanceOf[BodyParsers.Default])(app.materializer.executionContext)
      builder.authenticate(request, { authRequest: AuthenticatedRequest[A, User] =>
        fakedb.withConnection { conn =>
          block(new AuthenticatedDbRequest[A](authRequest.user, conn, request))
        }
      })
    }
  }

  object fakedb {
    def withConnection[A](block: Connection => A) = {
      block(FakeConnection)
    }
  }

  object FakeConnection extends Connection("fake")

  case class Connection(name: String)

  def withApplication[T](block: Application => T) = {
    running(_.configure("play.http.secret.key" -> "foobar"))(block)
  }
}

case class User(name: String)

class AuthMessagesRequest[A](
  val user: User,
  messagesApi: MessagesApi,
  request: Request[A]) extends MessagesRequest[A](request, messagesApi)

trait AuthMessagesActionBuilder extends ActionBuilder[AuthMessagesRequest, AnyContent]

class AuthenticatedActionBuilder(
  val parser: BodyParser[AnyContent],
  messagesApi: MessagesApi)(implicit val executionContext: ExecutionContext)
    extends AuthMessagesActionBuilder {

  type ResultBlock[A] = (AuthMessagesRequest[A]) => Future[Result]

  @Inject
  def this(
    parser: BodyParsers.Default,
    messagesApi: MessagesApi)(implicit ec: ExecutionContext) = {
    this(parser: BodyParser[AnyContent], messagesApi)
  }

  private def getUserFromRequest(req: RequestHeader) = {
    req.session.get("user").map(User)
  }

  private val builder = new AuthenticatedBuilder[User](getUserFromRequest, parser)

  def invokeBlock[A](request: Request[A], block: ResultBlock[A]) = {
    builder.authenticate(request, { authRequest: AuthenticatedRequest[A, User] =>
      block(new AuthMessagesRequest[A](authRequest.user, messagesApi, request))
    })
  }
}
