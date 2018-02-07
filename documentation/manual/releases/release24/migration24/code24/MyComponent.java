/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */

//#components-decl
import java.util.concurrent.CompletableFuture;
import javax.inject.Inject;
import play.inject.ApplicationLifecycle;
import play.libs.F;

public interface MyComponent {}

class MyComponentImpl implements MyComponent {
  @Inject
  public MyComponentImpl(ApplicationLifecycle lifecycle) {
    // previous contents of Plugin.onStart
    lifecycle.addStopHook( () -> {
      // previous contents of Plugin.onStop
      return CompletableFuture.completedFuture(null);
    });
  }
}
//#components-decl
