# Play 2.2 Migration Guide

This guide is for migrating a Play 2.1 application to Play 2.2.  To migrate from Play 2.0, first follow the [[Play 2.1 Migration Guide|Migration21]].

## Build tasks

### Update the Play organization and version

Play is now published under a different organisation id.  This is so that eventually we can deploy Play to Maven Central.  The old organisation id was `play`, the new one is `com.typesafe.play`.

The version also must be updated to 2.2.0.

In `project/plugins.sbt`, update the Play plugin to use the new organisation id:

```scala
addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.2.0")
```

In addition, if you have any other dependencies on Play artifacts, and you are not using the helpers to depend on them, you may have to update the organisation and version numbers there.

### Update SBT version

`project/build.properties` is required to be updated to use sbt 0.13.0.

### Update root project

If you're using a multi-project build, and none of the projects has a root directory of the current directory, the root project is now determined by overriding rootProject instead of alphabetically:

```scala
override def rootProject = Some(myProject) 
```

### Update Scala version

If you have set the scalaVersion (e.g. because you have a multi-project build that uses Project in addition to play.Project), you should update it to 2.10.2.

### Play cache module

Play cache is now split out into its own module.  If you are using the Play cache, you will need to add this as a dependency.  For example, in `Build.scala`:

```scala
val addDependencies = Seq(
  jdbc,
  cache,
  ...
)
```

Note that if you depend on plugins that depend on versions of Play prior to 2.2 then there will be a conflict within caching due to multiple caches being loaded. Update to a later plugin version or ensure that older Play versions are excluded if you see this issue.

## New results structure in Scala

In order to simplify action composition and filtering, the Play results structure has been simplified.  There is now only one type of result, `SimpleResult`, where before there were `SimpleResult`, `ChunkedResult` and `AsyncResult`, plus the interfaces `Result` and `PlainResult`.  All except `SimpleResult` have been deprecated.  `Status`, a subclass of `SimpleResult`, still exists as a convenience class for building results.  In most cases, actions can still use the deprecated types, but they will get deprecation warnings.  Actions doing composition and filters however will have to switch to using `SimpleResult`.

### Async actions

Previously, where you might have the following code:

```scala
def asyncAction = Action {
  Async {
    Future(someExpensiveComputation)
  }
}
```

You can now use the `Action.async` builder:

```scala
def asyncAction = Action.async {
  Future(someExpensiveComputation)
}
```

### Working with chunked results

Previously the `stream` method on `Status` was used to produce chunked results.  This has been deprecated, replaced with a `chunked` method, that makes it clear that the result is going to be chunked.  For example:

```scala
def cometAction = Action {
  Ok.chunked(Enumerator("a", "b", "c") &> Comet(callback = "parent.cometMessage"))
}
```

Advanced uses that created or used `ChunkedResult` directly should be replaced with code that manually sets/checks the `TransferEncoding: chunked` header, and uses the new `Results.chunk` and `Results.dechunk` enumeratees.

### Action composition

We are now recommending that action composition be done at the `EssentialAction` level, not the `Action` level, and that end users write their own `ActionBuilder` implementations for building actions.

TODO: Update/write documentation on how to do this, best practices etc.

### Filters

The iteratee produced by `EssentialAction` now produces `SimpleResult` instead of `Result`.  This means filters that needed to work with the result no longer have to unwrap `AsyncResult` into a `PlainResult`, arguably making all filters much simpler and easier to write.  Code that previously did the unwrapping can generally be replaced with a single iteratee `map` call.

### play.api.http.Writeable application

Previously the constructor to `SimpleResult` took a `Writeable` for the type of the `Enumerator` passed to it.  Now that enumerator must be an `Array[Byte]`, and `Writeable` is only used for the `Status` convenience methods.

### Tests

Previously `Helpers.route()` and similar methods returned a `Result`, which would always be an `AsyncResult`, and other methods on `Helpers` such as `status`, `header` and `contentAsString` took `Result` as a parameter.  Now `Future[SimpleResult]` is returned by `Helpers.route()`, and accepted by the extraction methods.  For many common use cases, where type inference is used to determine the types, no changes should be necessary to test code.

## New results structure in Java

In order to simply action composition, the Java structure of results has been changed.  `AsyncResult` has been deprecated, and `SimpleResult` has been introduced, to distinguish normal results from the `AsyncResult` type.

### Async actions

Previously, futures in async actions had to be wrapped in the `async` call.  Now actions may return either `Result` or `Promise<Result>`.  For example:

```java
public static Future<Result> myAsyncAction() {
    Promise<Integer> promiseOfInt = play.libs.Akka.future(
    new Callable<Integer>() {
      public Integer call() {
        return intensiveComputation();
      }
    }
  );
  return promiseOfInt.map(
    new Function<Integer, Result>() {
      public Result apply(Integer i) {
        return ok("Got result: " + i);
      } 
    }
  );
}
```

### Action composition

The signature of the `call` method in `play.mvc.Action` has changed to now return `Promise<SimpleResult>`.  If nothing is done with the result, then typically the only change necessary will be to update the type signatures.

## Iteratees execution contexts

Iteratees, enumeratees and enumerators that execute application supplied code now require an implicit execution context.  For example:

```scala
import play.api.libs.concurrent.Exceution.Implicits._

Iteratee.foreach[String] { msg =>
  println(msg)
}
```

## Preparing a distribution

The _stage_ and _dist_ tasks have been completely re-written in Play 2.2 so that they use the [Native Packager Plugin](https://github.com/sbt/sbt-native-packager). 

Play distributions are no longer created in the project's `dist` folder. Instead, they are created in the project's `target` folder. 

Another thing that has changed is the location of the Unix script that starts a Play application. Prior to 2.2 the Unix script was named `start` and it resided in the root level folder of the distribution. With 2.2 the `start` script is named as per the project's name and it resides in the distribution's `bin` folder. In addition there is now a `.bat` script available to start the Play application on Windows.

Please consult the [["Starting your application in production mode"|Production]] documentation for more information on the new `stage` and `dist` tasks.
