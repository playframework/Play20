<!--- Copyright (C) 2009-2013 Typesafe Inc. <http://www.typesafe.com> -->
# Writing functional tests with ScalaTest

Play provides a number of classes and convenience methods that assist with functional testing.  Most of these can be found either in the [`play.api.test`](api/scala/index.html#play.api.test.package) package or in the [`Helpers`](api/scala/index.html#play.api.test.Helpers$) object. The _ScalaTest + Play_ integration library builds on this testing support for ScalaTest.

You can access all of Play's built-in test support and _ScalaTest + Play_ with the following imports:

```scala
import org.scalatest._
import play.api.test._
import play.api.test.Helpers._
import org.scalatestplus.play._
```

## FakeApplication

Play frequently requires a running [`Application`](api/scala/index.html#play.api.Application) as context: it is usually provided from [`play.api.Play.current`](api/scala/index.html#play.api.Play$).

To provide an environment for tests, Play provides a [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication) class which can be configured with a different Global object, additional configuration, or even additional plugins.

@[scalafunctionaltest-fakeApplication](code-scalatestplus-play/ScalaFunctionalTestSpec.scala)

If all or most tests in your test class need a `FakeApplication`, and they can all share the same `FakeApplication`, mix in trait [`OneAppPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneAppPerSuite). You can access the `FakeApplication` from the `app` field. If you need to customize the `FakeApplication`, override `app` as shown in this example:

@[scalafunctionaltest-oneapppersuite](code-scalatestplus-play/oneapppersuite/ExampleSpec.scala)

If you need each test to get its own `FakeApplication`, use `OneAppPerTest` instead:

@[scalafunctionaltest-oneapppertest](code-scalatestplus-play/oneapppertest/ExampleSpec.scala)

The reason _ScalaTest + Play_ provides both `OneAppPerSuite` and `OneAppPerTest` is to allow you to select the sharing strategy that makes your tests run fastest. If you want application state maintained between successive tests, you'll need to use `OneAppPerSuite`. If each test needs a clean slate, however, you could either use `OneAppPerTest` or use `OneAppPerSuite`, but clear any state at the end of each test. Furthermore, if your test suite will run fastest if multiple test classes share the same application, you can define a master suite that mixes in [`OneAppPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneAppPerSuite) and nested suites that mix in [`ConfiguredApp`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredApp), as shown in the example in the [documentation for `ConfiguredApp`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredApp). You can use whichever strategy makes your test suite run the fastest.

## Testing with a server

Sometimes you want to test with the real HTTP stack. If all tests in your test class can reuse the same server instance, you can mix in [`OneServerPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneServerPerSuite) (which will also provide a new `FakeApplication` for the suite):

@[scalafunctionaltest-oneserverpersuite](code-scalatestplus-play/oneserverpersuite/ExampleSpec.scala)

If all tests in your test class requires separate server instance, use [`OneServerPerTest`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneServerPerTest) instead (which will also provide a new `FakeApplication` for the suite):

@[scalafunctionaltest-oneserverpertest](code-scalatestplus-play/oneserverpertest/ExampleSpec.scala)

The `OneServerPerSuite` and `OneServerPerTest` traits provide the port number on which the server is running as the `port` field.  By default this is 19001, however you can change this either overriding `port` or by setting the system property `testserver.port`.  This can be useful for integrating with continuous integration servers, so that ports can be dynamically reserved for each build.

You can also customize the [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication) by overriding `app`, as demonstrated in the previous examples.

Lastly, if allowing multiple test classes to share the same server will give you better performance than either the `OneServerPerSuite` or `OneServerPerTest` approaches, you can define a master suite that mixes in [`OneServerPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneServerPerSuite) and nested suites that mix in [`ConfiguredServer`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredServer), as shown in the example in the [documentation for `ConfiguredServer`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredServer).

## Testing with a web browser

The _ScalaTest + Play_ library builds on ScalaTest's [Selenium DSL](http://doc.scalatest.org/2.1.5/index.html#org.scalatest.selenium.WebBrowser) to make it easy to test your Play applications from web browsers.

To run all tests in your test class using a same browser instance, mix [`OneBrowserPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneBrowserPerSuite) into your test class. You'll also need to mix in a [`BrowserFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.BrowserFactory) trait that will provide a Selenium web driver: one of [`ChromeFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ChromeFactory), [`FirefoxFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.FirefoxFactory), [`HtmlUnitFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.HtmlUnitFactory), [`InternetExplorerFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.InternetExplorerFactory), [`SafariFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.SafariFactory).

In addition to mixing in a [`BrowserFactory`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.BrowserFactory) when using `OneBrowserPerSuite`, you will need to mix in a [`ServerProvider`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ServerProvider) trait that provides a `TestServer`: one of [`OneServerPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneServerPerSuite), [`OneServerPerTest`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneServerPerTest), or [`ConfiguredServer`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredServer).

For example, the following test class mixes in `OneServerPerSuite` and `HtmUnitFactory`:

@[scalafunctionaltest-onebrowserpersuite](code-scalatestplus-play/onebrowserpersuite/ExampleSpec.scala)

If each of your tests requires a new browser instance, use [`OneBrowserPerTest`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneBrowserPerSuite) instead. As with `OneBrowserPerSuite`, you'll need to also mix in a `ServerProvider` and `BrowserFactory`:

@[scalafunctionaltest-onebrowserpertest](code-scalatestplus-play/onebrowserpertest/ExampleSpec.scala)

If you need multiple test classes to share the same browser instance, mix [`OneBrowserPerSuite`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.OneBrowserPerSuite) into a master suite and [`ConfiguredBrowser`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredBrowser) into multiple nested suites. The nested suites will all share the same web browser. For an example, see the [documentation for trait `ConfiguredBrowser`](http://doc.scalatest.org/plus-play/1.0.0/index.html#org.scalatestplus.play.ConfiguredBrowser).

## Running the same tests in multiple browsers

If you want to run your tests with all available web browsers on your system, you can use `AllBrowsersPerSuite`:

@[scalafunctionaltest-allbrowserspersuite](code-scalatestplus-play/allbrowserspersuite/ExampleSpec.scala)

All tests registered under `sharedTests` will be run with all available browsers on your system.  Note that it is important for you to append the `browser.name` manually to the test name, without it you'll get a duplicated test name error at runtime.

Using `AllBrowsersPerSuite` all tests will be run by the same instance for a browser type, if you want a new instance for each test, you can use `AllBrowsersPerTest` instead:

@[scalafunctionaltest-allbrowserspertest](code-scalatestplus-play/allbrowserspertest/ExampleSpec.scala)

For both `AllBrowsersPerSuite` and `AllBrowsersPerTest`, when a browser type is not available on the running system, the test will be canceled automatically and shown in output.  You can explicitly specify web browser(s) to be included by overriding `browsers`:

@[scalafunctionaltest-allbrowserspersuite](code-scalatestplus-play/allbrowserspersuite/ExampleOverrideBrowsersSpec.scala)

`AllBrowsersPerSuite` will then try to detect only Firefox and Chrome browser in the running system (and cancel test automatically if the browser is not available).  The same approach can be used on `AllBrowsersPerTest`.

## PlaySpec

`PlaySpec` provides a convenience "super Suite" ScalaTest base class for Play tests, you get `MustMatchers`, `OptionValues` and `WsScalaTestClient` automatically by extending `PlaySpec`:

@[scalafunctionaltest-playspec](code-scalatestplus-play/playspec/ExampleSpec.scala)

#WORK UP TO HERE



which is useful for setting up custom routes and testing WS calls:

@[scalafunctionaltest-testws](code/specs2/ScalaFunctionalTestSpec.scala)

## WithApplication

To pass in an application to an example, use [`WithApplication`](api/scala/index.html#play.api.test.WithApplication).  An explicit [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication) can be passed in, but a default [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication) is provided for convenience.

Because [`WithApplication`](api/scala/index.html#play.api.test.WithApplication) is a built in [`Around`](http://etorreborre.github.io/specs2/guide/org.specs2.guide.Structure.html#Around) block, you can override it to provide your own data population:

@[scalafunctionaltest-withdbdata](code/specs2/WithDbDataSpec.scala)

## WithServer

Sometimes you want to test the real HTTP stack from within your test, in which case you can start a test server using [`WithServer`](api/scala/index.html#play.api.test.WithServer):

@[scalafunctionaltest-testpaymentgateway](code/specs2/ScalaFunctionalTestSpec.scala)

The `port` value contains the port number the server is running on.  By default this is 19001, however you can change this either by passing the port into [`WithServer`](api/scala/index.html#play.api.test.WithServer), or by setting the system property `testserver.port`.  This can be useful for integrating with continuous integration servers, so that ports can be dynamically reserved for each build.

A [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication) can also be passed to the test server, which is useful for setting up custom routes and testing WS calls:

@[scalafunctionaltest-testws](code/specs2/ScalaFunctionalTestSpec.scala)

## WithBrowser

If you want to test your application using a browser, you can use [Selenium WebDriver](http://code.google.com/p/selenium/?redir=1). Play will start the WebDriver for you, and wrap it in the convenient API provided by [FluentLenium](https://github.com/FluentLenium/FluentLenium) using [`WithBrowser`](api/scala/index.html#play.api.test.WithBrowser).  Like [`WithServer`](api/scala/index.html#play.api.test.WithServer), you can change the port, [`FakeApplication`](api/scala/index.html#play.api.test.FakeApplication), and you can also select the web browser to use:

@[scalafunctionaltest-testwithbrowser](code/ScalaFunctionalTestSpec.scala)

## PlaySpecification

[`PlaySpecification`](api/scala/index.html#play.api.test.PlaySpecification) is an extension of [`Specification`](http://etorreborre.github.io/specs2/api/SPECS2-2.2.2/index.html#org.specs2.mutable.Specification) that excludes some of the mixins provided in the default specs2 specification that clash with Play helpers methods.  It also mixes in the Play test helpers and types for convenience.

@[scalatest-playspecification](code/specs2/ExamplePlaySpecificationSpec.scala)

## Testing a view template

Since a template is a standard Scala function, you can execute it from your test, and check the result:

@[scalatest-functionaltemplatespec](code/specs2/FunctionalTemplateSpec.scala)

## Testing a template

Since a template is a standard Scala function, you can execute it from your test, and check the result:

@[scalafunctionaltest-testview](code-scalatestplus-play/ScalaFunctionalTestSpec.scala)

## Testing a controller

You can call any `Action` code by providing a [`FakeRequest`](api/scala/index.html#play.api.test.FakeRequest):

@[scalafunctionaltest-functionalexamplecontrollerspec](code/FunctionalExampleControllerSpec.scala)

Technically, you don't need [`WithApplication`](api/scala/index.html#play.api.test.WithApplication) here, although it wouldn't hurt anything to have it.

@[scalatest-examplecontrollerspec](code-scalatestplus-play/ExampleControllerSpec.scala)

## Testing the router

Instead of calling the `Action` yourself, you can let the `Router` do it:

@[scalafunctionaltest-respondtoroute](code-scalatestplus-play/ScalaFunctionalTestSpec.scala)

## Testing a model

If you are using an SQL database, you can replace the database connection with an in-memory instance of an H2 database using `inMemoryDatabase`.

@[scalafunctionaltest-testmodel](code-scalatestplus-play/ScalaFunctionalTestSpec.scala)

> **Next:** [[Advanced topics|Iteratees]]
