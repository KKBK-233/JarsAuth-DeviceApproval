/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.mojang.logging.LogUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import me.jissee.jarsauth.server_settings.SettingClientAuth;
import me.jissee.jarsauth.server_settings.Settings;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class ApprovalHttpServer {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static HttpServer server;

    public static synchronized void restart() {
        stop();
        SettingClientAuth setting = Settings.getClientAuthSetting();
        if (setting == null || !setting.isEnabled()) {
            return;
        }
        try {
            server = HttpServer.create(new InetSocketAddress(setting.getApprovalBindHost(), setting.getApprovalPort()), 0);
            server.createContext("/approve", exchange -> handleAction(exchange, true));
            server.createContext("/reject", exchange -> handleAction(exchange, false));
            server.setExecutor(null);
            server.start();
            LOGGER.info("Approval HTTP server started at {}:{}", setting.getApprovalBindHost(), setting.getApprovalPort());
        } catch (IOException e) {
            LOGGER.error("Cannot start approval HTTP server", e);
        }
    }

    public static synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    private static void handleAction(HttpExchange exchange, boolean approve) throws IOException {
        try {
            Map<String, String> query = parseQuery(exchange.getRequestURI());
            String token = query.get("token");
            String html;
            if (token == null || token.isBlank()) {
                html = buildHtml("Missing token", false);
            } else {
                boolean result = approve
                        ? CAPendingList.getInstance().approvePendingByToken(token)
                        : CAPendingList.getInstance().rejectPendingByToken(token);
                html = buildHtml(result ? (approve ? "Approved" : "Rejected") : "Request expired or not found", result);
            }
            writeHtml(exchange, html);
        } finally {
            exchange.close();
        }
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> query = new HashMap<>();
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isBlank()) {
            return query;
        }
        String[] pairs = rawQuery.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            query.put(pair.substring(0, idx), pair.substring(idx + 1));
        }
        return query;
    }

    private static String buildHtml(String message, boolean success) {
        String color = success ? "#1f7a1f" : "#9f1f1f";
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <title>JarsAuth Approval</title>
                </head>
                <body style="font-family:sans-serif;background:#101417;color:#f5f7fa;padding:32px;">
                  <div style="max-width:720px;margin:0 auto;padding:24px;border-radius:12px;background:#1b232b;">
                    <h1 style="margin-top:0;color:%s;">JarsAuth</h1>
                    <p style="font-size:18px;">%s</p>
                  </div>
                </body>
                </html>
                """.formatted(color, message);
    }

    private static void writeHtml(HttpExchange exchange, String html) throws IOException {
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }
}
