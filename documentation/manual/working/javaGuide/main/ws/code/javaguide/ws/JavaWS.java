/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package javaguide.ws;

import javaguide.testhelpers.MockJavaAction;

// #ws-imports
import play.libs.ws.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
// #ws-imports

// #json-imports
import com.fasterxml.jackson.databind.JsonNode;
import play.libs.Json;
// #json-imports

import scala.compat.java8.FutureConverters;

import java.io.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.*;

import org.w3c.dom.Document;
import play.mvc.Result;

import javax.inject.Inject;

import play.http.HttpEntity;
import play.mvc.Http.Status;

// #ws-custom-client-imports
import org.asynchttpclient.*;
import play.api.libs.ws.WSClientConfig;
import play.api.libs.ws.ning.NingWSClientConfig;
import play.api.libs.ws.ning.NingWSClientConfigFactory;
import play.api.libs.ws.ssl.SSLConfigFactory;
import play.api.libs.ws.ning.NingAsyncHttpClientConfigBuilder;
import scala.concurrent.duration.Duration;

import akka.stream.Materializer;
import akka.stream.javadsl.*;
import akka.util.ByteString;
// #ws-custom-client-imports

public class JavaWS {
    private static final String feedUrl = "http://localhost:3333/feed";

    public static class Controller0 extends MockJavaAction {

        private WSClient ws;
        private Materializer materializer;

        public void requestExamples() {
            // #ws-holder
            WSRequest request = ws.url("http://example.com");
            // #ws-holder

            // #ws-complex-holder
            WSRequest complexRequest = request.setHeader("headerKey", "headerValue")
                                                    .setRequestTimeout(1000)
                                                    .setQueryParameter("paramKey", "paramValue");
            // #ws-complex-holder

            // #ws-get
            CompletionStage<WSResponse> responsePromise = complexRequest.get();
            // #ws-get

            String url = "http://example.com";
            // #ws-auth
            ws.url(url).setAuth("user", "password", WSAuthScheme.BASIC).get();
            // #ws-auth

            // #ws-follow-redirects
            ws.url(url).setFollowRedirects(true).get();
            // #ws-follow-redirects

            // #ws-query-parameter
            ws.url(url).setQueryParameter("paramKey", "paramValue");
            // #ws-query-parameter

            // #ws-header
            ws.url(url).setHeader("headerKey", "headerValue").get();
            // #ws-header

            String jsonString = "{\"key1\":\"value1\"}";
            // #ws-header-content-type
            ws.url(url).setHeader("Content-Type", "application/json").post(jsonString);
            // OR
            ws.url(url).setContentType("application/json").post(jsonString);
            // #ws-header-content-type

            // #ws-timeout
            ws.url(url).setRequestTimeout(1000).get();
            // #ws-timeout

            // #ws-post-form-data
            ws.url(url).setContentType("application/x-www-form-urlencoded")
                       .post("key1=value1&key2=value2");
            // #ws-post-form-data

            // #ws-post-json
            JsonNode json = Json.newObject()
                                .put("key1", "value1")
                                .put("key2", "value2");

            ws.url(url).post(json);
            // #ws-post-json

            String value = IntStream.range(0,100).boxed().
                map(i -> "abcdefghij").reduce("", (a,b) -> a + b);
            ByteString seedValue = ByteString.fromString(value);
            Stream<ByteString> largeSource = IntStream.range(0,10).boxed().map(i -> seedValue);
            Source<ByteString, ?> largeImage = Source.from(largeSource.collect(Collectors.toList()));
            // #ws-stream-request
            CompletionStage<WSResponse> wsResponse = ws.url(url).setBody(largeImage).execute("PUT");
            // #ws-stream-request
        }

        public void responseExamples() {

            String url = "http://example.com";

            // #ws-response-json
            CompletionStage<JsonNode> jsonPromise = ws.url(url).get()
                    .thenApply(WSResponse::asJson);
            // #ws-response-json

            // #ws-response-xml
            CompletionStage<Document> documentPromise = ws.url(url).get()
                    .thenApply(WSResponse::asXml);
            // #ws-response-xml
        }

        public void streamSimpleRequest() {
            String url = "http://example.com";
            // #stream-count-bytes
            // Make the request
            CompletionStage<StreamedResponse> futureResponse = 
                ws.url(url).setMethod("GET").stream();

            CompletionStage<Long> bytesReturned = futureResponse.thenCompose(res -> {
                Source<ByteString, ?> responseBody = res.getBody();

                // Count the number of bytes returned
                Sink<ByteString, scala.concurrent.Future<Long>> bytesSum =
                    Sink.fold(0L, (total, bytes) -> total + bytes.length());

                // Converts the materialized Scala Future into a Java8 `CompletionStage`
                Sink<ByteString, CompletionStage<Long>> convertedBytesSum =
                    bytesSum.mapMaterializedValue(FutureConverters::toJava);

                return responseBody.runWith(convertedBytesSum, materializer);
            });
            // #stream-count-bytes
        }

        public void streamFile() throws IOException, FileNotFoundException, InterruptedException, ExecutionException {
            String url = "http://example.com";
            //#stream-to-file
            File file = File.createTempFile("stream-to-file-", ".txt");
            FileOutputStream outputStream = new FileOutputStream(file);

            // Make the request
            CompletionStage<StreamedResponse> futureResponse =
                ws.url(url).setMethod("GET").stream();

            CompletionStage<File> downloadedFile = futureResponse.thenCompose(res -> {
                Source<ByteString, ?> responseBody = res.getBody();

                // The sink that writes to the output stream
                Sink<ByteString,scala.concurrent.Future<scala.runtime.BoxedUnit>> outputWriter = 
                    Sink.<ByteString>foreach(bytes -> outputStream.write(bytes.toArray()));

                // Converts the materialized Scala Future into a Java8 `CompletionStage`
                Sink<ByteString, CompletionStage<?>> convertedOutputWriter =
                    outputWriter.mapMaterializedValue(FutureConverters::toJava);

                // materialize and run the stream
                CompletionStage<File> result = responseBody.runWith(convertedOutputWriter, materializer)
                    .whenComplete((value, error) -> {
                        // Close the output stream whether there was an error or not
                        try { outputStream.close(); }
                        catch(IOException e) {}
                    })
                    .thenApply(v -> file);
                return result;
            });
            //#stream-to-file
            downloadedFile.toCompletableFuture().get();
            file.delete();
        }

        public void streamResponse() {
            String url = "http://example.com";
            //#stream-to-result
            // Make the request
            CompletionStage<StreamedResponse> futureResponse = ws.url(url).setMethod("GET").stream();

            CompletionStage<Result> result = futureResponse.thenApply(response -> {
                WSResponseHeaders responseHeaders = response.getHeaders();
                Source<ByteString, ?> body = response.getBody();
                // Check that the response was successful
                if (responseHeaders.getStatus() == 200) {
                    // Get the content type
                    String contentType =
                            Optional.ofNullable(responseHeaders.getHeaders().get("Content-Type"))
                                    .map(contentTypes -> contentTypes.get(0)).
                                    orElse("application/octet-stream");

                    // If there's a content length, send that, otherwise return the body chunked
                    Optional<String> contentLength = Optional.ofNullable(responseHeaders.getHeaders()
                            .get("Content-Length"))
                            .map(contentLengths -> contentLengths.get(0));
                    if (contentLength.isPresent()) {
                        return ok().sendEntity(new HttpEntity.Streamed(
                                body,
                                Optional.of(Long.parseLong(contentLength.get())),
                                Optional.of(contentType)
                        ));
                    } else {
                        return ok().chunked(body).as(contentType);
                    }
                } else {
                    return new Result(Status.BAD_GATEWAY);
                }
            });
            //#stream-to-result
        }

        public void streamPut() {
            String url = "http://example.com";
            //#stream-put
            CompletionStage<StreamedResponse> futureResponse  =
                ws.url(url).setMethod("PUT").setBody("some body").stream();
            //#stream-put
        }
        public void patternExamples() {
            String urlOne = "http://localhost:3333/one";
            // #ws-composition
            final CompletionStage<WSResponse> responseThreePromise = ws.url(urlOne).get()
                    .thenCompose(responseOne -> ws.url(responseOne.getBody()).get())
                    .thenCompose(responseTwo -> ws.url(responseTwo.getBody()).get());
            // #ws-composition

            // #ws-recover
            CompletionStage<WSResponse> responsePromise = ws.url("http://example.com").get();
            CompletionStage<WSResponse> recoverPromise = responsePromise.handle((result, error) -> {
                if (error != null) {
                    return ws.url("http://backup.example.com").get();
                } else {
                    return CompletableFuture.completedFuture(result);
                }
            }).thenCompose(Function.identity());
            // #ws-recover
        }

        public void clientExamples() {
            // #ws-client
            WSClient client = WS.client();
            // #ws-client

            // #ws-custom-client
            // Set up the client config (you can also use a parser here):
            scala.Option<String> noneString = scala.None$.empty();
            WSClientConfig wsClientConfig = new WSClientConfig(
                    Duration.apply(120, TimeUnit.SECONDS), // connectionTimeout
                    Duration.apply(120, TimeUnit.SECONDS), // idleTimeout
                    Duration.apply(120, TimeUnit.SECONDS), // requestTimeout
                    true, // followRedirects
                    true, // useProxyProperties
                    noneString, // userAgent
                    true, // compressionEnabled / enforced
                    SSLConfigFactory.defaultConfig());

            NingWSClientConfig clientConfig = NingWSClientConfigFactory.forClientConfig(wsClientConfig);

            // Build a secure config out of the client config:
            NingAsyncHttpClientConfigBuilder secureBuilder = new NingAsyncHttpClientConfigBuilder(clientConfig);
            AsyncHttpClientConfig secureDefaults = secureBuilder.build();

            // You can directly use the builder for specific options once you have secure TLS defaults...
            AsyncHttpClientConfig customConfig = new AsyncHttpClientConfig.Builder(secureDefaults)
                            .setProxyServer(new org.asynchttpclient.proxy.ProxyServer("127.0.0.1", 38080))
                            .setCompressionEnforced(true)
                            .build();

            WSClient customClient = new play.libs.ws.ning.NingWSClient(customConfig, materializer);

            CompletionStage<WSResponse> responsePromise = customClient.url("http://example.com/feed").get();
            // #ws-custom-client

            // #ws-underlying-client
            org.asynchttpclient.AsyncHttpClient underlyingClient =
                (org.asynchttpclient.AsyncHttpClient) ws.getUnderlying();
            // #ws-underlying-client

        }
    }

    public static class Controller1 extends MockJavaAction {

        @Inject
        private WSClient ws;

        // #ws-action
        public CompletionStage<Result> index() {
            return ws.url(feedUrl).get().thenApply(response ->
                ok("Feed title: " + response.asJson().findPath("title").asText())
            );
        }
        // #ws-action
    }

    public static class Controller2 extends MockJavaAction {

        @Inject
        private WSClient ws;

        // #composed-call
        public CompletionStage<Result> index() {
            return ws.url(feedUrl).get()
                    .thenCompose(response -> ws.url(response.asJson().findPath("commentsUrl").asText()).get())
                    .thenApply(response -> ok("Number of comments: " + response.asJson().findPath("count").asInt()));
        }
        // #composed-call
    }
}