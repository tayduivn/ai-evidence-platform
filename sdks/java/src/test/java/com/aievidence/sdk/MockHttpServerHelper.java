package com.aievidence.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Embedded HTTP server helper for testing using pure Java standard library com.sun.net.httpserver.
 */
public class MockHttpServerHelper implements AutoCloseable {

    private final HttpServer server;
    private final int port;
    private final AtomicInteger requestCount = new AtomicInteger(0);
    private final ConcurrentHashMap<String, AtomicInteger> pathCounts = new ConcurrentHashMap<>();

    public MockHttpServerHelper() throws IOException {
        // Bind to dynamic ephemeral port
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.port = this.server.getAddress().getPort();
        this.server.setExecutor(Executors.newCachedThreadPool());
    }

    public int getPort() {
        return port;
    }

    public String getBaseUrl() {
        return "http://127.0.0.1:" + port;
    }

    public void registerHandler(String path, HttpHandler handler) {
        server.createContext(path, exchange -> {
            requestCount.incrementAndGet();
            pathCounts.computeIfAbsent(path, k -> new AtomicInteger(0)).incrementAndGet();
            handler.handle(exchange);
        });
    }

    public void start() {
        server.start();
    }

    public int getRequestCount() {
        return requestCount.get();
    }

    public int getPathCount(String path) {
        AtomicInteger count = pathCounts.get(path);
        return count != null ? count.get() : 0;
    }

    public static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public static void sendResponse(HttpExchange exchange, int statusCode, String responseJson) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            is.readAllBytes();
        } catch (Exception ignored) {}
        byte[] bytes = responseJson.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
