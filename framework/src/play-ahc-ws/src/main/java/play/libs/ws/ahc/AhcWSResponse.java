/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package play.libs.ws.ahc;

import com.fasterxml.jackson.databind.JsonNode;
import org.w3c.dom.Document;
import play.libs.ws.WSCookie;
import play.libs.ws.WSResponse;
import play.libs.ws.StandaloneWSResponse;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A Play WS response backed by an AsyncHttpClient response.
 */
public class AhcWSResponse implements WSResponse {

    private final StandaloneWSResponse underlying;

    public AhcWSResponse(StandaloneWSResponse response) {
        this.underlying = response;
    }

    /**
     * @deprecated  Deprecated since 2.6.0. Use {@link #getHeaders()} instead.
     * @return the headers
     */
    @Deprecated
    @Override
    public Map<String, List<String>> getAllHeaders() {
        return underlying.getHeaders();
    }

    /**
     * @deprecated Deprecated since 2.6.0.  Use {@link #getSingleHeader(String)} instead.
     * @param key the header name
     * @return the header value, or null if no header is defined
     */
    @Deprecated
    @Override
    public String getHeader(String key) {
        return underlying.getHeader(key);
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return underlying.getHeaders();
    }

    @Override
    public List<String> getHeaderValues(String name) {
        return underlying.getHeaderValues(name);
    }

    @Override
    public Optional<String> getSingleHeader(String name) {
        return underlying.getSingleHeader(name);
    }

    @Override
    public Object getUnderlying() {
        return underlying.getUnderlying();
    }

    @Override
    public int getStatus() {
        return underlying.getStatus();
    }

    @Override
    public String getStatusText() {
        return underlying.getStatusText();
    }

    @Override
    public List<WSCookie> getCookies() {
        return underlying.getCookies();
    }

    @Override
    public WSCookie getCookie(String name) {
        return underlying.getCookie(name);
    }

    @Override
    public String getBody() {
        return underlying.getBody();
    }

    @Override
    public Document asXml() {
        return underlying.asXml();
    }

    @Override
    public JsonNode asJson() {
        return underlying.asJson();
    }

    @Override
    public InputStream getBodyAsStream() {
        return underlying.getBodyAsStream();
    }

    @Override
    public byte[] asByteArray() {
        return underlying.asByteArray();
    }

    @Override
    public URI getUri() {
        return underlying.getUri();
    }
}
