<!--- Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com> -->
# The Play cache API

Caching data is a typical optimization in modern applications, and so Play provides a global cache. An important point about the cache is that it behaves just like a cache should: the data you just stored may just go missing.

For any data stored in the cache, a regeneration strategy needs to be put in place in case the data goes missing. This philosophy is one of the fundamentals behind Play, and is different from Java EE, where the session is expected to retain values throughout its lifetime.

The default implementation of the cache API uses [Ehcache](http://www.ehcache.org/).

## Importing the Cache API

Play provides both an API and an default Ehcache implementation of that API. To get the full Ehcache implementation, add `ehcache` to your dependencies list:

@[ehcache-sbt-dependencies](code/cache.sbt)

This will also automatically set up the bindings for runtime DI so the components are injectable.

To add only the API, add `cacheApi` to your dependencies list.

@[cache-sbt-dependencies](code/cache.sbt)

The API dependency is useful if you'd like to define your own bindings for the `Cached` helper and `AsyncCacheApi`, etc., without having to depend on Ehcache. If you're writing a custom cache module you should use this.

## Accessing the Cache API

The cache API is defined by the [AsyncCacheApi](api/java/play/cache/AsyncCacheApi.html) and [SyncCacheApi](api/java/play/cache/SyncCacheApi.html) interfaces, depending on whether you want an asynchronous or synchronous implementation, and can be injected into your component like any other dependency.  For example:

@[inject](code/javaguide/cache/inject/Application.java)

> **Note:** The API is intentionally minimal to allow various implementations to be plugged in. If you need a more specific API, use the one provided by your Cache library.

Using this simple API you can store data in the cache:

@[simple-set](code/javaguide/cache/JavaCache.java)

Optionally you can specify an expiration (in seconds) for the cache:

@[time-set](code/javaguide/cache/JavaCache.java)

You can retrieve the data later:

@[get](code/javaguide/cache/JavaCache.java)

You can also supply a `Callable` that generates stores the value if no value is found in the cache:

@[get-or-else](code/javaguide/cache/JavaCache.java)

To remove an item from the cache use the `remove` method:

@[remove](code/javaguide/cache/JavaCache.java)

Note that the [SyncCacheApi](api/java/play/cache/SyncCacheApi.html) has the same API, except it returns the values directly instead of using futures.

## Accessing different caches

It is possible to access different caches. In the default Ehcache implementation, the default cache is called `play`, and can be configured by creating a file called `ehcache.xml`. Additional caches may be configured with different configurations, or even implementations.

If you want to access multiple different ehcache caches, then you'll need to tell Play to bind them in `application.conf`, like so:

    play.cache.bindCaches = ["db-cache", "user-cache", "session-cache"]

By default, Play will try to create these caches for you. If you would like to define them yourself in `ehcache.xml`, you can set:

    play.cache.createBoundCaches = false

Now to access these different caches, when you inject them, use the [NamedCache](api/java/play/cache/NamedCache.html) qualifier on your dependency, for example:

@[qualified](code/javaguide/cache/qualified/Application.java)

## Caching HTTP responses

You can easily create a smart cached action using standard `Action` composition.

> **Tip:** Play HTTP `Result` instances are safe to cache and reuse later.

Play provides a default built-in helper for the standard case:

@[http](code/javaguide/cache/JavaCache.java)

## Custom implementations

It is possible to provide a custom implementation of the cache API that either replaces or sits alongside the default implementation.

To replace the default implementation based on something other than Ehcache, you only need the `cacheApi` dependency rather than the `ehcache` dependency in your `build.sbt`. If you still need access to the Ehcache implementation classes, you can use `ehcache` and disable the module from automatically binding it in `application.conf`:

```
play.modules.disabled += "play.api.cache.ehcache.EhCacheModule"
```

You can then implement [AsyncCacheApi](api/java/play/cache/AsyncCacheApi.html) and bind it in the DI container. You can also bind [SyncCacheApi](api/java/play/cache/SyncCacheApi.html) to [DefaultSyncCacheApi](api/java/play/cache/DefaultSyncCacheApi.html), which simply wraps the async implementation.

To provide an implementation of the cache API in addition to the default implementation, you can either create a custom qualifier, or reuse the `NamedCache` qualifier to bind the implementation.
