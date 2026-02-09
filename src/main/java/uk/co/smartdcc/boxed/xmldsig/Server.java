/*
 * Created on Thur Feb 5 2026
 *
 * Copyright (c) 2026 Smart DCC Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package uk.co.smartdcc.boxed.xmldsig;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.Map;

public final class Server {
  private static final Gson GSON = new Gson();
  private static final Type MAP_TYPE = new TypeToken<Map<String, String>>() {
  }.getType();
  private static final int PORT = 8080;
  private static boolean quiet = false;

  private static final int HTTP_NOT_FOUND = 404;
  private static final int HTTP_METHOD_NOT_ALLOWED = 405;
  private static final int HTTP_BAD_REQUEST = 400;
  private static final int HTTP_OK = 200;

  private Server() {
  }

  private static void log(final boolean error, final String message) {
    if (!quiet) {
      String code = "I";
      if (error) {
        code = "E";
      }
      System.err.println("[" + code + "] [" + ProcessHandle.current().pid() + "] " + message);
    }
  }

  public static HttpServer createServer(final int port) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/sign", Server::handleSign);
    server.createContext("/verify", Server::handleVerify);
    server.setExecutor(null);
    return server;
  }

  static void showHelp() {
    System.out.println(
        "Usage: java -cp xmldsign.jar uk.co.smartdcc.boxed.xmldsig.jar Server [-p port] [-q] [-h]"
    );
    System.out.println("  -p port  Server port (default: " + PORT + ")");
    System.out.println("  -q       Quiet mode (no logging)");
    System.out.println("  -h       Show this help");
  }

  public static void main(final String[] args) throws IOException {
    int port = PORT;

    for (int i = 0; i < args.length; i++) {
      switch (args[i]) {
        case "-p":
          if (i + 1 < args.length) {
            try {
              port = Integer.parseInt(args[++i]);
            } catch (NumberFormatException e) {
              showHelp();
              return;
            }
          } else {
            showHelp();
            return;
          }
          break;
        case "-q":
          quiet = true;
          break;
        case "-h":
        default:
          showHelp();
          return;
      }
    }

    HttpServer server = createServer(port);
    Object sync = new Object();
    Thread shutdownHook = new Thread(() -> {
      synchronized (sync) {
        sync.notifyAll();
      }
    });
    Runtime.getRuntime().addShutdownHook(shutdownHook);
    server.start();
    log(false, "Server started on port " + port);
    synchronized (sync) {
      try {
        sync.wait();
      } catch (InterruptedException ignored) {
      }
    }
    log(false, "Shutting down server...");
    server.stop(0);
  }

  static void handleSign(final HttpExchange exchange) throws IOException {
    if (!"/sign".equals(exchange.getRequestURI().getPath())) {
      exchange.sendResponseHeaders(HTTP_NOT_FOUND, 0);
      exchange.close();
      return;
    }
    if (!"POST".equals(exchange.getRequestMethod())) {
      sendResponse(exchange, HTTP_METHOD_NOT_ALLOWED, Map.of("error", "Method not allowed"));
      return;
    }
    log(false, "(" + exchange.getRemoteAddress() + ") Sign request received ");
    try {
      JsonObject request = JsonParser.parseString(
          new String(exchange.getRequestBody().readAllBytes())
      ).getAsJsonObject();
      byte[] xmlBytes = Base64.getDecoder().decode(request.get("message").getAsString());
      boolean preserveCounter = /* */
          request.has("preserveCounter")
              && request.get("preserveCounter").getAsBoolean();
      ByteArrayInputStream input = new ByteArrayInputStream(xmlBytes);
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      Sign.verify_and_sign_input_stream(
          preserveCounter,
          input,
          output,
          CertificateLibrary.getInstance()
      );
      String encoded = Base64.getEncoder().encodeToString(output.toByteArray());
      sendResponse(exchange, HTTP_OK, Map.of("message", encoded));
      log(false, "(" + exchange.getRemoteAddress() + ") Sign request completed successfully");
    } catch (Exception e) {
      sendResponse(
          exchange,
          HTTP_BAD_REQUEST,
          Map.of("error", e.getMessage(), "errorCode", e.getClass().getSimpleName())
      );
      log(true, "(" + exchange.getRemoteAddress() + ") Sign request failed: " + e.getMessage());
    }
  }

  static void handleVerify(final HttpExchange exchange) throws IOException {
    if (!"/verify".equals(exchange.getRequestURI().getPath())) {
      exchange.sendResponseHeaders(HTTP_NOT_FOUND, 0);
      exchange.close();
      return;
    }
    if (!"POST".equals(exchange.getRequestMethod())) {
      sendResponse(exchange, HTTP_METHOD_NOT_ALLOWED, Map.of("error", "Method not allowed"));
      return;
    }
    log(false, "(" + exchange.getRemoteAddress() + ") Verify request received");
    try {
      Map<String, String> request = GSON.fromJson(
          new String(exchange.getRequestBody().readAllBytes()),
          MAP_TYPE
      );
      byte[] xmlBytes = Base64.getDecoder().decode(request.get("message"));
      ByteArrayInputStream input = new ByteArrayInputStream(xmlBytes);
      byte[] validated = Validate.validate_input_stream(
          input,
          CertificateLibrary.getInstance()
      );
      /* response without signature */
      if (validated == null) {
        validated = xmlBytes;
      }
      String encoded = Base64.getEncoder().encodeToString(validated);
      sendResponse(exchange, HTTP_OK, Map.of("message", encoded));
      log(false, "(" + exchange.getRemoteAddress() + ") Verify request completed successfully");
    } catch (Exception e) {
      sendResponse(
          exchange,
          HTTP_BAD_REQUEST,
          Map.of("error", e.getMessage(), "errorCode", e.getClass().getSimpleName())
      );
      log(true, "(" + exchange.getRemoteAddress() + ") Verify request failed: " + e.getMessage());
    }
  }

  static void sendResponse(
      final HttpExchange exchange,
      final int status,
      final Map<String, String> body
  ) throws IOException {
    String json = GSON.toJson(body);
    byte[] bytes = json.getBytes();
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    OutputStream os = exchange.getResponseBody();
    os.write(bytes);
    os.close();
  }
}
