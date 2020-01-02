/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package javaguide.tests;

import org.junit.*;

import play.test.*;
import static org.junit.Assert.*;

// #test-withbrowser
public class BrowserFunctionalTest extends WithBrowser {

  @Test
  public void runInBrowser() {
    browser.goTo("/");
    assertNotNull(browser.el("title").text());
  }
}
// #test-withbrowser
