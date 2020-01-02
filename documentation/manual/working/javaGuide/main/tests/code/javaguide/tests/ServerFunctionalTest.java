/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package javaguide.tests;

import java.util.OptionalInt;
import java.util.concurrent.*;

import org.junit.*;

import play.test.*;
import play.libs.ws.*;

import static org.junit.Assert.*;

import static play.test.Helpers.NOT_FOUND;

// #test-withserver
public class ServerFunctionalTest extends WithServer {

  @Test
  public void testInServer() throws Exception {
    OptionalInt optHttpsPort = testServer.getRunningHttpsPort();
    String url;
    int port;
    if (optHttpsPort.isPresent()) {
      port = optHttpsPort.getAsInt();
      url = "https://localhost:" + port;
    } else {
      port = testServer.getRunningHttpPort().getAsInt();
      url = "http://localhost:" + port;
    }
    try (WSClient ws = play.test.WSTestClient.newClient(port)) {
      CompletionStage<WSResponse> stage = ws.url(url).get();
      WSResponse response = stage.toCompletableFuture().get();
      assertEquals(NOT_FOUND, response.getStatus());
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}
// #test-withserver
