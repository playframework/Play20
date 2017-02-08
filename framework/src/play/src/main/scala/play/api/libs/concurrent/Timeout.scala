/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.api.libs.concurrent

import akka.actor.ActorSystem

import scala.concurrent.{ Future, TimeoutException }
import scala.concurrent.duration.FiniteDuration

/**
 * This trait is used to provide a non-blocking timeout on an operation that returns a Future.
 *
 * Please note that the [[play.api.Application]] default ActorSystem should
 * be used as input here, as the actorSystem.scheduler is responsible for scheduling
 * the timeout, using <a href="http://doc.akka.io/docs/akka/current/scala/futures.html#After">akka.pattern.actor</a> under the hood.
 *
 * You can dependency inject the ActorSystem as follows to create a Future that will
 * timeout after a certain period of time:
 *
 * {{{
 * class MyService @Inject()(actorSystem: ActorSystem) extends Timeout {
 *
 *   def calculateWithTimeout(timeoutDuration: FiniteDuration): Future[Int] = {
 *     timeout(actorSystem, timeoutDuration)(rawCalculation())
 *   }
 *
 *   def rawCalculation(): Future[Int] = {
 *     import akka.pattern.after
 *     implicit val ec = actorSystem.dispatcher
 *     akka.pattern.after(300 millis, actorSystem.scheduler)(Future(42))(actorSystem.dispatcher)
 *   }
 * }
 * }}}
 *
 * You should check for timeout by using [[scala.concurrent.Future.recover()]] or [[scala.concurrent.Future.recoverWith()]]
 * and checking for [[TimeoutException]]:
 *
 * {{{
 * val future = myService.calculateWithTimeout(100 millis).recover {
 *   case _: TimeoutException =>
 *     -1
 * }
 * }}}
 *
 * @see [[http://docs.scala-lang.org/overviews/core/futures.html Futures and Promises]]
 *
 */
trait Timeout {

  /**
   * Creates a future which will resolve to a timeout exception if the
   * given Future has not successfully completed within timeoutDuration.
   *
   * Note that timeout is not the same as cancellation.  Even in case of timeout,
   * the given future will still complete, even though that completed value
   * is not returned.
   *
   * @tparam A the result type used in the Future.
   * @param actorSystem the application's actor system.
   * @param timeoutDuration the duration after which a Future.failed(TimeoutException) should be thrown.
   * @param f a call by value Future[A]
   * @return the future that completes first, either the failed future, or the operation.
   */
  def timeout[A](actorSystem: ActorSystem, timeoutDuration: FiniteDuration)(f: Future[A]): Future[A] = {
    implicit val ec = actorSystem.dispatchers.defaultGlobalDispatcher
    val timeoutFuture = akka.pattern.after(timeoutDuration, actorSystem.scheduler) {
      val msg = s"Timeout after $timeoutDuration"
      Future.failed(new TimeoutException(msg))
    }
    Future.firstCompletedOf(Seq(f, timeoutFuture))
  }

}

/**
 * This is a static object that can be used to import timeout implicits, as a convenience.
 *
 * {{{
 * import play.api.libs.concurrent.Timeout._
 * }}}
 */
object Timeout extends Timeout with LowPriorityTimeoutImplicits

/**
 * Low priority timeouts to add `withTimeout` methods to [[scala.concurrent.Future]].
 */
trait LowPriorityTimeoutImplicits {

  implicit class FutureTimeout[T](future: Future[T]) extends Timeout {

    /**
     * Creates a future which will resolve to a timeout exception if the
     * given [[scala.concurrent.Future]] has not successfully completed within timeoutDuration.
     *
     * Note that timeout is not the same as cancellation.  Even in case of timeout,
     * the given future will still complete, even though that completed value
     * is not returned.
     *
     * @param timeoutDuration the duration after which a Future.failed(TimeoutException) should be thrown.
     * @param actorSystem the application's actor system.
     * @return the future that completes first, either the failed future, or the operation.
     */
    def withTimeout(timeoutDuration: FiniteDuration)(implicit actorSystem: ActorSystem): Future[T] = {
      timeout(actorSystem, timeoutDuration)(future)
    }

    /**
     * Creates a future which will resolve to a timeout exception if the
     * given Future has not successfully completed within timeoutDuration.
     *
     * This version uses an implicit [[akka.util.Timeout]] rather than a [[scala.concurrent.duration.FiniteDuration]].
     *
     * Note that timeout is not the same as cancellation.  Even in case of timeout,
     * the given future will still complete, even though that completed value
     * is not returned.
     *
     * @param timeoutDuration the duration after which a Future.failed(TimeoutException) should be thrown.
     * @param actorSystem the application's actor system.
     * @return the future that completes first, either the failed future, or the operation.
     */
    def withTimeout(implicit timeoutDuration: akka.util.Timeout, actorSystem: ActorSystem): Future[T] = {
      timeout(actorSystem, timeoutDuration.duration)(future)
    }
  }
}
