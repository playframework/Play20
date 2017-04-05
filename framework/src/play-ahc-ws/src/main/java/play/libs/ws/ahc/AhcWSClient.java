/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.libs.ws.ahc;

import akka.stream.Materializer;
import play.api.libs.ws.ahc.AhcWSClientConfig;
import play.api.libs.ws.ahc.cache.EffectiveURIKey;
import play.api.libs.ws.ahc.cache.ResponseEntry;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;

import javax.inject.Inject;
import java.io.IOException;

/**
 * A WS client backed by AsyncHttpClient implementation.
 * <p>
 * See https://www.playframework.com/documentation/latest/JavaWS for documentation.
 */
public class AhcWSClient implements WSClient {

    private final StandaloneAhcWSClient client;

    @Inject
    public AhcWSClient(StandaloneAhcWSClient client) {
        this.client = client;
    }

    /**
     * Creates WS client manually from configuration, internally creating a new
     * instance of AsyncHttpClient and managing its own thread pool.
     * <p>
     * This client is not managed as part of Play's lifecycle, and <b>must</b>
     * be closed by calling ws.close(), otherwise you will run into memory leaks.
     *
     * @param config       a config object, usually from AhcWSClientConfigFactory
     * @param cache        if not null, provides HTTP caching.
     * @param materializer an Akka materializer
     * @return a new instance of AhcWSClient.
     */
    public static AhcWSClient create(AhcWSClientConfig config,
                                     javax.cache.Cache<EffectiveURIKey, ResponseEntry> cache,
                                     Materializer materializer) {
        final StandaloneAhcWSClient client = StandaloneAhcWSClient.create(config, cache, materializer);
        return new AhcWSClient(client);
    }

    @Override
    public Object getUnderlying() {
        return client.getUnderlying();
    }

    @Override
    public WSRequest url(String url) {
        final StandaloneAhcWSRequest plainWSRequest = client.url(url);
        return new AhcWSRequest(this, plainWSRequest);
    }

    @Override
    public void close() throws IOException {
        client.close();
    }
}
