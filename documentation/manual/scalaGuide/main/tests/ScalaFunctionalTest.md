# Writing functional tests

Play provides a number of classes and convenience methods that assist with functional testing.  Most of these can be found either in the [`play.api.test`](api/scala/index.html#play.api.test.package) package or in the [`Helpers`](api/scala/index.html#play.api.test.Helpers$) object.  You can add these methods and classes by importing the package and Helper object:

```scala
import play.api.test._
import play.api.test.Helpers._
```

## Testing a template

Since a template is a standard Scala function, you can execute it from your test, and check the result:

```scala
"render index template" in {
  val html = views.html.index("Coco")
  
  contentType(html) must equalTo("text/html")
  contentAsString(html) must contain("Hello Coco")
}
```

## Testing your controllers

You can call any `Action` code by providing a [`FakeRequest`](api/scala/index.html#play.api.test.FakeRequest):

```scala
"respond to the index Action" in {
  val result = controllers.Application.index("Bob")(FakeRequest())
  
  status(result) must equalTo(OK)
  contentType(result) must beSome("text/html")
  charset(result) must beSome("utf-8")
  contentAsString(result) must contain("Hello Bob")
}
```

## Testing the router

Instead of calling the `Action` yourself, you can let the `Router` do it:

@[scalafunctionaltest-respondtoroute](code/ScalaFunctionalTestSpec.scala)

## Testing a model

If you are using an SQL database, you can replace the database connection with an in-memory instance of an H2 database using `inMemoryDatabase`.

@[scalafunctionaltest-testmodel](code/ScalaFunctionalTestSpec.scala)

## Starting a real HTTP server

Sometimes you want to test the real HTTP stack from with your test, in which case you can start a test server using [`WithServer`](api/scala/index.html#play.api.test.WithServer):

@[scalafunctionaltest-testpaymentgateway](code/ScalaFunctionalTestSpec.scala)

The `port` value contains the port number the server is running on.  By default this is 19001, however you can change this either by passing the port into the with `WithServer` constructor, or by setting the system property `testserver.port`.  This can be useful for integrating with continuous integration servers, so that ports can be dynamically reserved for each build.

A `FakeApplication` can also be passed to the test server, which is useful for setting up custom routes:

@[scalafunctionaltest-testws](code/ScalaFunctionalTestSpec.scala)

## Testing from within a Web browser.

If you want to test your application using a browser, you can use [Selenium WebDriver](http://code.google.com/p/selenium/?redir=1). Play will start the WebDriver for your, and wrap it in the convenient API provided by [FluentLenium](https://github.com/FluentLenium/FluentLenium).

```scala
"run in a browser" in new WithBrowser {
  browser.goTo("/")
  browser.$("#title").getTexts().get(0) must equalTo("Hello Guest")
    
  browser.$("a").click()
    
  browser.url must equalTo("/")
  browser.$("#title").getTexts().get(0) must equalTo("Hello Coco")
}
```

Like `WithServer`, you can change the port, `FakeApplication`, and you can also select the web browser to use:

```scala
"run in a browser" in new WithBrowser(webDriver = FIREFOX) {
  ...
}
```

> **Next:** [[Advanced topics|Iteratees]]
