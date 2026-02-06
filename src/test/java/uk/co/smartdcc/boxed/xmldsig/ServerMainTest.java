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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Map;

public class ServerMainTest {
  private static final Gson GSON = new Gson();

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
  void mainMethod() throws Exception {
    PrintStream originalErr = System.err;
    ByteArrayOutputStream capturedErr = new ByteArrayOutputStream();
    System.setErr(new PrintStream(capturedErr));

    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] {});
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    HttpURLConnection conn = (HttpURLConnection) new URI("http://localhost:8080/sign")
        .toURL().openConnection();
    conn.setRequestMethod("GET");
    Assertions.assertEquals(405, conn.getResponseCode());

    serverThread.interrupt();
    serverThread.join();

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    System.setErr(originalErr);
    Assertions.assertNotEquals("", capturedErr.toString());
  }

  @Test
  void mainMethod_CustomPort() throws Exception {
    int port = 9090;
    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-p", "" + port });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", port, "sign");
    Assertions.assertEquals(200, conn.getResponseCode());
    conn = doPost("readfw-response.xml", port, "verify");
    Assertions.assertEquals(200, conn.getResponseCode());

    serverThread.interrupt();
    serverThread.join();
  }

  @Test
  void mainMethod_QuietMode() throws Exception {
    PrintStream originalErr = System.err;
    ByteArrayOutputStream capturedErr = new ByteArrayOutputStream();
    System.setErr(new PrintStream(capturedErr));

    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-q" });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    HttpURLConnection conn = doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    Assertions.assertEquals(200, conn.getResponseCode());
    conn = doPost("readfw-response.xml", 8080, "verify");
    Assertions.assertEquals(200, conn.getResponseCode());

    serverThread.interrupt();
    serverThread.join();

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    System.setErr(originalErr);
    Assertions.assertEquals("", capturedErr.toString());
  }

  @Test
  void mainMethod_Help() throws Exception {
    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-h" });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    serverThread.interrupt();
    serverThread.join();
  }

  @Test
  void mainMethod_OtherArgument() throws Exception {
    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-?" });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    serverThread.interrupt();
    serverThread.join();
  }

  @Test
  void mainMethod_PortMissing() throws Exception {
    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-p" });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    serverThread.interrupt();
    serverThread.join();
  }

  @Test
  void mainMethod_PortWrongType() throws Exception {
    Thread serverThread = new Thread(() -> {
      try {
        Server.main(new String[] { "-p", "-h" });
      } catch (IOException e) {
        // Expected when server stops
      }
    });
    serverThread.start();

    Thread.sleep(100);

    Assertions.assertThrows(java.net.ConnectException.class, () -> {
      doPost("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML", 8080, "sign");
    });

    serverThread.interrupt();
    serverThread.join();
  }
}