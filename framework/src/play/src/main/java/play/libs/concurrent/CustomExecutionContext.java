/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.libs.concurrent;

import akka.actor.ActorSystem;
import scala.concurrent.ExecutionContext;
import scala.concurrent.ExecutionContextExecutor;

/**
 * Provides a custom execution context from an Akka dispatcher.
 *
 * Subclass this to create your own custom execution context, using
 * the full path to the Akka dispatcher.
 *
 * <pre>
 * <code>
 * {@literal @}Singleton
 * class MyCustomExecutionContext extends CustomExecutionContext {
 *   // Dependency inject the actorsystem from elsewhere
 *   {@literal @}Inject
 *   public MyCustomExecutionContext(ActorSystem actorSystem) {
 *     super(actorSystem, "full.path.to.my-custom-executor");
 *   }
 * }
 * </code>
 * </pre>
 *
 * and then bind it in dependency injection:
 *
 * <pre>
 * <code>
 * bind(DatabaseExecutionContext.class).toSelf().eagerly()
 * </code>
 * </pre>
 *
 * Then inject and use your custom execution context where you have blocking
 * operations that require processing outside of Play's main rendering
 * thread.
 *
 * <pre>
 * <code>
 * public class DatabaseService {
 *   {@literal @}Inject
 *   public DatabaseService(DatabaseExecutionContext executionContext) {
 *     ...
 *   }
 * }
 * </code>
 * </pre>
 *
 * @see <a href="http://doc.akka.io/docs/akka/2.5/java/dispatchers.html">Dispatchers</a>
 * @see <a href="https://www.playframework.com/documentation/latest/ThreadPools">Thread Pools</a>
 */
public abstract class CustomExecutionContext implements ExecutionContextExecutor {
    private final ExecutionContext executionContext;

    public CustomExecutionContext(ActorSystem actorSystem, String name) {
        this.executionContext = actorSystem.dispatchers().lookup(name);
    }

    @Override
    public ExecutionContext prepare() {
        return executionContext.prepare();
    }

    @Override
    public void execute(Runnable command) {
        executionContext.execute(command);
    }

    @Override
    public void reportFailure(Throwable cause) {
        executionContext.reportFailure(cause);
    }
}
