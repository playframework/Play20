
/*
 * Copyright (C) 2009-2016 Lightbend Inc. <https://www.lightbend.com>
 */
package scalaguide.http.scalaactionscomposition {

import javax.inject.Inject
import akka.actor._
import akka.stream.ActorMaterializer
import play.api.http._
import play.api.test._
import play.api.test.Helpers._
import play.api.mvc.BodyParsers
import org.specs2.mutable.Specification
import org.junit.runner.RunWith
import org.specs2.runner.JUnitRunner
import play.api.Logger
import play.api.mvc.Controller
import scala.concurrent.Future
import scala.concurrent.ExecutionContext
import org.specs2.execute.AsResult

case class User(name: String)
object User {
  def find(u: String) = Some(User("player"))
}

@RunWith(classOf[JUnitRunner])
class ScalaActionsCompositionSpec extends Specification with Controller {

  "an action composition" should {

    "Basic action composition" in {
      //#basic-logging
      import play.api.mvc._

      class LoggingAction @Inject() (parser: BodyParsers.Default)(implicit ec: ExecutionContext) extends ActionBuilderImpl(parser) {
        override def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[Result]) = {
          Logger.info("Calling action")
          block(request)
        }
      }
      //#basic-logging
      implicit val system = ActorSystem()
      implicit val ec: ExecutionContext = ExecutionContext.Implicits.global
      val eh: HttpErrorHandler =
        new DefaultHttpErrorHandler(play.api.Environment.simple(), play.api.Configuration.empty)
      val parse = PlayBodyParsers(ParserConfiguration(), eh, ActorMaterializer())
      val parser = new BodyParsers.Default(parse)
      val loggingAction = new LoggingAction(parser)

      //#basic-logging-index
      def index = loggingAction {
        Ok("Hello World")
      }
      //#basic-logging-index

      testAction(index)

      //#basic-logging-parse
      def submit = loggingAction(parse.text) { request =>
        Ok("Got a body " + request.body.length + " bytes long")
      }
      //#basic-logging-parse

      val request = FakeRequest().withTextBody("hello with the parse")
      testAction(index, request)
    }

    "Wrapping existing actions" in {

      //#actions-class-wrapping
      import play.api.mvc._

      case class Logging[A](action: Action[A]) extends Action[A] {

        def apply(request: Request[A]): Future[Result] = {
          Logger.info("Calling action")
          action(request)
        }

        lazy val parser = action.parser
      }
      //#actions-class-wrapping

      //#actions-wrapping-builder
      class LoggingAction @Inject() (parser: BodyParsers.Default)(implicit ec: ExecutionContext) extends ActionBuilderImpl(parser) {
        override def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[Result]) = {
          block(request)
        }
        override def composeAction[A](action: Action[A]) = new Logging(action)
      }
      //#actions-wrapping-builder

      implicit val system = ActorSystem()
      implicit val ec: ExecutionContext = ExecutionContext.Implicits.global
      val eh: HttpErrorHandler =
        new DefaultHttpErrorHandler(play.api.Environment.simple(), play.api.Configuration.empty)
      val parse = PlayBodyParsers(ParserConfiguration(), eh, ActorMaterializer())
      val parser = new BodyParsers.Default(parse)
      val loggingAction = new LoggingAction(parser)

      {
        //#actions-wrapping-index
        def index = loggingAction {
          Ok("Hello World")
        }
        //#actions-wrapping-index

        testAction(index)
      }

      {
        //#actions-wrapping-direct
        def index = Logging {
          Action {
            Ok("Hello World")
          }
        }
        //#actions-wrapping-direct

        testAction(index)
      }
    }

    "Wrapping existing actions without defining the Logging class" in {

      //#actions-def-wrapping
      import play.api.mvc._

      def logging[A](action: Action[A])= Action.async(action.parser) { request =>
        Logger.info("Calling action")
        action(request)
      }
      //#actions-def-wrapping

      val request = FakeRequest().withTextBody("hello with the parse")
      testAction(logging {
        Action {
          Ok("Hello World")
        }
      }, request)
    }

    "allow modifying the request object" in {
      //#modify-request
      import play.api.mvc._

      def xForwardedFor[A](action: Action[A]) = Action.async(action.parser) { request =>
        val newRequest = request.headers.get("X-Forwarded-For").map { xff =>
          new WrappedRequest[A](request) {
            override def remoteAddress = xff
          }
        } getOrElse request
        action(newRequest)
      }
      //#modify-request

      testAction(xForwardedFor(Action(Ok)))
    }

    "allow blocking the request" in {
      //#block-request
      import play.api.mvc._

      def onlyHttps[A](action: Action[A]) = Action.async(action.parser) { request =>
        request.headers.get("X-Forwarded-Proto").collect {
          case "https" => action(request)
        } getOrElse {
          Future.successful(Forbidden("Only HTTPS requests allowed"))
        }
      }
      //#block-request

      testAction(action = onlyHttps(Action(Ok)), expectedResponse = FORBIDDEN)
    }

    "allow modifying the result" in {
      implicit val ec = scala.concurrent.ExecutionContext.Implicits.global

      //#modify-result
      import play.api.mvc._

      def addUaHeader[A](action: Action[A]) = Action.async(action.parser) { request =>
        action(request).map(_.withHeaders("X-UA-Compatible" -> "Chrome=1"))
      }
      //#modify-result

      assertAction(addUaHeader(Action(Ok))) { result =>
        header("X-UA-Compatible", result) must beSome("Chrome=1")
      }
    }

    "allow action builders with different request types" in {

      //#authenticated-action-builder
      import play.api.mvc._

      class UserRequest[A](val username: Option[String], request: Request[A]) extends WrappedRequest[A](request)

      class UserAction @Inject()(val parser: BodyParsers.Default)(implicit val executionContext: ExecutionContext)
        extends ActionBuilder[UserRequest, AnyContent] with ActionTransformer[Request, UserRequest] {
        def transform[A](request: Request[A]) = Future.successful {
          new UserRequest(request.session.get("username"), request)
        }
      }
      //#authenticated-action-builder
      implicit val system = ActorSystem()
      implicit val ec: ExecutionContext = ExecutionContext.Implicits.global
      val eh: HttpErrorHandler =
        new DefaultHttpErrorHandler(play.api.Environment.simple(), play.api.Configuration.empty)
      val parser = new BodyParsers.Default(ParserConfiguration(), eh, ActorMaterializer())
      val userAction = new UserAction(parser)

      def currentUser = userAction { request =>
        Ok("The current user is " + request.username.getOrElse("anonymous"))
      }

      testAction(currentUser)

      case class Item(id: String) {
        def addTag(tag: String) = ()
        def accessibleByUser(user: Option[String]) = user.isDefined
      }
      object ItemDao {
        def findById(id: String) = Some(Item(id))
      }

      //#request-with-item
      import play.api.mvc._

      class ItemRequest[A](val item: Item, request: UserRequest[A]) extends WrappedRequest[A](request) {
        def username = request.username
      }
      //#request-with-item

      //#item-action-builder
      def ItemAction(itemId: String)(implicit ec: ExecutionContext) = new ActionRefiner[UserRequest, ItemRequest] {
        def executionContext = ec
        def refine[A](input: UserRequest[A]) = Future.successful {
          ItemDao.findById(itemId)
            .map(new ItemRequest(_, input))
            .toRight(NotFound)
        }
      }
      //#item-action-builder

      //#permission-check-action
      def PermissionCheckAction(implicit ec: ExecutionContext) = new ActionFilter[ItemRequest] {
        def executionContext = ec
        def filter[A](input: ItemRequest[A]) = Future.successful {
          if (!input.item.accessibleByUser(input.username))
            Some(Forbidden)
          else
            None
        }
      }
      //#permission-check-action

      //#item-action-use
      def tagItem(itemId: String, tag: String)(implicit ec: ExecutionContext) =
        (userAction andThen ItemAction(itemId) andThen PermissionCheckAction) { request =>
          request.item.addTag(tag)
          Ok("User " + request.username + " tagged " + request.item.id)
        }
      //#item-action-use

      import scala.concurrent.ExecutionContext.Implicits.global
      testAction(tagItem("foo", "bar"), expectedResponse = FORBIDDEN)
    }

  }

  import play.api.mvc._
  def testAction[A](action: EssentialAction, request: => Request[A] = FakeRequest(), expectedResponse: Int = OK) = {
    assertAction(action, request, expectedResponse) { result => success }
  }

  def assertAction[A, T: AsResult](action: EssentialAction, request: => Request[A] = FakeRequest(), expectedResponse: Int = OK)(assertions: Future[Result] => T) = {
    running() { app =>
      implicit val mat = ActorMaterializer()(app.actorSystem)
      val result = action(request).run()
      status(result) must_== expectedResponse
      assertions(result)
    }
  }

}

}
