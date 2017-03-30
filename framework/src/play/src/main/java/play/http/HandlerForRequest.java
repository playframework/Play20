/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.http;

import play.api.mvc.Handler;
import play.mvc.Http.RequestHeader;

/**
 * A request and a handler to handle it.
 */
public class HandlerForRequest {
  private final RequestHeader request;
  private final Handler handler;

  public HandlerForRequest(RequestHeader request, Handler handler) {
    this.request = request;
    this.handler = handler;
  }

  /**
   * @return the request header.
   * @deprecated As of release 2.6.0. Use {@link #getRequestHeader()}
   */
  @Deprecated
  public RequestHeader getRequest() {
    return request;
  }

  /**
   * @return the request header.
   * @see play.mvc.Http.RequestHeader
   */
  public RequestHeader getRequestHeader() {
    return request;
  }

  public Handler getHandler() {
    return handler;
  }
}
