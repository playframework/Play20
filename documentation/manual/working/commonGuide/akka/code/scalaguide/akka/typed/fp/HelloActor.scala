/*
 * Copyright (C) 2009-2019 Lightbend Inc. <https://www.lightbend.com>
 */

package scalaguide.akka.typed.fp

// #fp-hello-actor
import akka.actor.typed.ActorRef
import akka.actor.typed.Behavior
import akka.actor.typed.scaladsl.Behaviors

object HelloActor {
  final case class SayHello(name: String, replyTo: ActorRef[String])

  def apply(): Behavior[SayHello] = {
    Behaviors.receiveMessage[SayHello] {
      case SayHello(name, replyTo) =>
        replyTo ! s"Hello, $name"
        Behaviors.same
    }
  }
}
// #fp-hello-actor
