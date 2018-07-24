/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.api.libs.concurrent

import java.util.concurrent.atomic.AtomicBoolean

import akka.Done
import akka.actor.{ ActorSystem, CoordinatedShutdown }
import akka.actor.CoordinatedShutdown._
import com.typesafe.config.{ Config, ConfigFactory, ConfigValueFactory }
import org.specs2.mutable.Specification
import play.api.inject.{ ApplicationLifecycle, DefaultApplicationLifecycle }
import play.api.{ Configuration, Environment }

import scala.concurrent.Future
import scala.concurrent.duration.Duration

class ActorSystemProviderSpec extends Specification {

  val akkaMaxDelayInSec = 2147483
  val fiveSec = Duration(5, "seconds")
  val oneSec = Duration(100, "milliseconds")

  val akkaTimeoutKey = "akka.coordinated-shutdown.phases.actor-system-terminate.timeout"
  val playTimeoutKey = "play.akka.shutdown-timeout"

  "ActorSystemProvider" should {

    "use Play's 'play.akka.shutdown-timeout' if defined " in {
      withOverriddenTimeout {
        _.withValue(playTimeoutKey, ConfigValueFactory.fromAnyRef("12 s"))
      } { actorSystem =>
        actorSystem.settings.config.getDuration(akkaTimeoutKey).getSeconds must equalTo(12)
      }
    }

    "use an infinite timeout if using Play's 'play.akka.shutdown-timeout = null' " in {
      withOverriddenTimeout {
        _.withFallback(ConfigFactory.parseResources("src/test/resources/application-infinite-timeout.conf"))
      } { actorSystem =>
        actorSystem.settings.config.getDuration(akkaTimeoutKey).getSeconds must equalTo(akkaMaxDelayInSec)
      }
    }

    "use Play's 'Duration.Inf' when no 'play.akka.shutdown-timeout' is defined and user overwrites Akka's default" in {
      withOverriddenTimeout {
        _.withValue(akkaTimeoutKey, ConfigValueFactory.fromAnyRef("21 s"))
      } { actorSystem =>
        actorSystem.settings.config.getDuration(akkaTimeoutKey).getSeconds must equalTo(akkaMaxDelayInSec)
      }
    }

    "use infinite when 'play.akka.shutdown-timeout = null' and user overwrites Akka's default" in {
      withOverriddenTimeout {
        _.withFallback(ConfigFactory.parseResources("src/test/resources/application-infinite-timeout.conf"))
          .withValue(akkaTimeoutKey, ConfigValueFactory.fromAnyRef("17 s"))
      } { actorSystem =>
        actorSystem.settings.config.getDuration(akkaTimeoutKey).getSeconds must equalTo(akkaMaxDelayInSec)
      }
    }

    "run all the phases for coordinated shutdown" in {
      // The default phases of Akka CoordinatedShutdown are ordered as a DAG by defining the
      // dependencies between the phases. That means we don't need to test each phase, but
      // just the first and the last one. We are then adding a custom phase so that we
      // can assert that Play is correctly executing CoordinatedShutdown.

      // First phase is PhaseBeforeServiceUnbind
      val phaseBeforeServiceUnbindExecuted = new AtomicBoolean(false)

      // Last phase is PhaseActorSystemTerminate
      val phaseActorSystemTerminateExecuted = new AtomicBoolean(false)

      val config = Configuration
        .load(Environment.simple())
        .underlying
        // Add a custom phase which executes after the last one defined by Akka.
        .withValue("akka.coordinated-shutdown.phases.custom-defined-phase.depends-on", ConfigValueFactory.fromIterable(java.util.Arrays.asList("actor-system-terminate")))

      // Custom phase CustomDefinedPhase
      val PhaseCustomDefinedPhase = "custom-defined-phase"
      val phaseCustomDefinedPhaseExecuted = new AtomicBoolean(false)

      val (actorSystem, _) = ActorSystemProvider.start(
        this.getClass.getClassLoader,
        Configuration(config)
      )

      val lifecycle: ApplicationLifecycle = new DefaultApplicationLifecycle()
      val cs = new CoordinatedShutdownProvider(actorSystem, lifecycle).get

      def run(atomicBoolean: AtomicBoolean) = () => {
        atomicBoolean.set(true)
        Future.successful(Done)
      }

      cs.addTask(PhaseBeforeServiceUnbind, "test-BeforeServiceUnbindExecuted")(run(phaseBeforeServiceUnbindExecuted))
      cs.addTask(PhaseActorSystemTerminate, "test-ActorSystemTerminateExecuted")(run(phaseActorSystemTerminateExecuted))
      cs.addTask(PhaseCustomDefinedPhase, "test-PhaseCustomDefinedPhaseExecuted")(run(phaseCustomDefinedPhaseExecuted))

      CoordinatedShutdownSupport.syncShutdown(actorSystem, CoordinatedShutdown.UnknownReason)

      phaseBeforeServiceUnbindExecuted.get() must equalTo(true)
      phaseActorSystemTerminateExecuted.get() must equalTo(true)
      phaseCustomDefinedPhaseExecuted.get() must equalTo(true)
    }

  }

  private def withOverriddenTimeout[T](reconfigure: Config => Config)(block: ActorSystem => T): T = {
    val config: Config = reconfigure(Configuration
      .load(Environment.simple())
      .underlying
      .withoutPath(playTimeoutKey)
    )
    val (actorSystem, stopHook) = ActorSystemProvider.start(
      this.getClass.getClassLoader,
      Configuration(config)
    )
    try {
      block(actorSystem)
    } finally {
      stopHook()
    }
  }

}
