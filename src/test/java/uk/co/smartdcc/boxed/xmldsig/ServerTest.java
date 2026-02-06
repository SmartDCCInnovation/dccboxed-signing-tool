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
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Map;

public class ServerTest {
  private static final Gson GSON = new Gson();
  private static final Type MAP_TYPE = new TypeToken<Map<String, String>>() {
  }.getType();
  private static final int PORT = 18096;
  private static HttpServer server;

  @BeforeAll
  static void startServer() throws Exception {
    server = Server.createServer(PORT);
    server.start();
  }

  @AfterAll
  static void stopServer() {
    server.stop(0);
  }

  HttpURLConnection doPost(String fileName, int port, String endpoint) throws IOException, URISyntaxException {
    InputStream is = UtilTest.class.getClassLoader().getResourceAsStream(fileName);
    byte[] xmlBytes = is.readAllBytes();
    is.close();

    String encoded = Base64.getEncoder().encodeToString(xmlBytes);
    String requestJson = GSON.toJson(Map.of("message", encoded));

    HttpURLConnection conn = (HttpURLConnection) new URI("http://localhost:" + port + "/" + endpoint)
        .toURL().openConnection();
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/json");
    OutputStream os = conn.getOutputStream();
    os.write(requestJson.getBytes());
    os.close();

    return conn;
  }

  @Test
  void unknownEndpoint1_Valid() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", PORT, "signzz");
    Assertions.assertEquals(404, conn.getResponseCode());
  }

  @Test
  void unknownEndpoint2_Valid() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", PORT, "verifyzz");
    Assertions.assertEquals(404, conn.getResponseCode());
  }

  @Test
  void unknownEndpoint3_Valid() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", PORT, "asdf");
    Assertions.assertEquals(404, conn.getResponseCode());
  }

  @Test
  void signEndpoint_Valid() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", PORT, "sign");

    Assertions.assertEquals(200, conn.getResponseCode());
    String responseJson = new String(conn.getInputStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    String signedXml = new String(Base64.getDecoder().decode(response.get("message")));
    Assertions.assertTrue(signedXml.contains("</ds:Signature>"));
  }

  @Test
  void signEndpoint_Invalid() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-invalid.XML", PORT, "sign");

    Assertions.assertEquals(400, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("SAXParseException", response.get("errorCode"));
  }

  @Test
  void signEndpoint_MissingCertificate() throws Exception {
    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-nonexist-businessid.XML", PORT, "sign");

    Assertions.assertEquals(400, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("CertificateException", response.get("errorCode"));
  }

  @Test
  void verifyEndpoint_Valid() throws Exception {
    HttpURLConnection conn = doPost("readfw-response.xml", PORT, "verify");

    Assertions.assertEquals(200, conn.getResponseCode());
    String responseJson = new String(conn.getInputStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    String validatedXml = new String(Base64.getDecoder().decode(response.get("message")));
    Assertions.assertFalse(validatedXml.contains("</ds:Signature>"));
  }

  @Test
  void verifyEndpoint_Invalid() throws Exception {
    HttpURLConnection conn = doPost("readfw-response-invalid.xml", PORT, "verify");

    Assertions.assertEquals(400, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("SAXParseException", response.get("errorCode"));
  }

  @Test
  void verifyEndpoint_BadSignature() throws Exception {
    HttpURLConnection conn = doPost("readfw-response-badsignature.xml", PORT, "verify");

    Assertions.assertEquals(400, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("SignatureException", response.get("errorCode"));
  }

  @Test
  void verifyEndpoint_MissingCertificate() throws Exception {
    HttpURLConnection conn = doPost("readfw-response-nonexist-serial.xml", PORT, "verify");

    Assertions.assertEquals(400, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("CertificateException", response.get("errorCode"));
  }

  @Test
  void signEndpoint_GetMethod() throws Exception {
    HttpURLConnection conn = (HttpURLConnection) new URI("http://localhost:" + PORT + "/sign")
        .toURL().openConnection();
    conn.setRequestMethod("GET");

    Assertions.assertEquals(405, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("Method not allowed", response.get("error"));
  }

  @Test
  void verifyEndpoint_GetMethod() throws Exception {
    HttpURLConnection conn = (HttpURLConnection) new URI("http://localhost:" + PORT + "/verify")
        .toURL().openConnection();
    conn.setRequestMethod("GET");

    Assertions.assertEquals(405, conn.getResponseCode());
    String responseJson = new String(conn.getErrorStream().readAllBytes());
    Map<String, String> response = GSON.fromJson(responseJson, MAP_TYPE);
    Assertions.assertEquals("Method not allowed", response.get("error"));
  }
}