/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package scalaguide.akka.typed.oo
package multi

import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton
import akka.actor.typed.ActorRef

@Singleton final class Main @Inject() (
    @Named("hello-actor1") val helloActor1: ActorRef[HelloActor.SayHello],
    @Named("hello-actor2") val helloActor2: ActorRef[HelloActor.SayHello],
    @Named("configured-actor1") val configuredActor1: ActorRef[ConfiguredActor.GetConfig],
    @Named("configured-actor2") val configuredActor2: ActorRef[ConfiguredActor.GetConfig],
)
