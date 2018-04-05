/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package javaguide.logging;

//#logging-pattern-mix
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.*;
import play.mvc.Http.Request;

import java.util.concurrent.CompletionStage;

public class Application extends BaseController {

  private static final Logger logger = LoggerFactory.getLogger(Application.class);

  @With(AccessLoggingAction.class)
  public Result index() {
    try {
      final int result = riskyCalculation();
      return ok("Result=" + result);
    } catch (Throwable t) {
      logger.error("Exception with riskyCalculation", t);
      return internalServerError("Error in calculation: " + t.getMessage());
    }
  }

  private static int riskyCalculation() {
    return 10 / (new java.util.Random()).nextInt(2);
  }

}

class AccessLoggingAction extends Action.Simple {

  private static final Logger accessLogger = LoggerFactory.getLogger(AccessLoggingAction.class);

  public CompletionStage<Result> call(Http.Context ctx) {
    final Request request = ctx.request();
    accessLogger.info("method={} uri={} remote-address={}", request.method(), request.uri(), request.remoteAddress());

    return delegate.call(ctx);
  }
}
//#logging-pattern-mix
