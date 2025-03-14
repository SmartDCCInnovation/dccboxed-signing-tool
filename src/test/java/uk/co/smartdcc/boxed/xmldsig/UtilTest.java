/*
 * Created on Mon Jul 04 2022
 *
 * Copyright (c) 2022 Smart DCC Limited
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.github.stefanbirkner.systemlambda.SystemLambda;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public class UtilTest {

  private static String DUIS_FILE_NAME;

  @BeforeAll
  public static void beforeAll() throws Exception {
    Field field = Util.class.getDeclaredField("DUIS_FILE_NAME");
    field.setAccessible(true);
    DUIS_FILE_NAME = (String) field.get(null);
  }

  @BeforeEach
  public void beforeEach() throws Exception {
    Field cert_names = Util.class.getDeclaredField("DUIS_FILE_NAME");
    cert_names.setAccessible(true);
    cert_names.set(null, DUIS_FILE_NAME);

    Field instance = Util.class.getDeclaredField("schema");
    instance.setAccessible(true);
    instance.set(null, null);
  }

  @Test
  public void loadDuisSchema() {
    Schema schema = Util.load_schema();
    Assertions.assertNotNull(schema);
  }

  @Test
  public void loadDuisSchema_Cache() {
    Schema schema = Util.load_schema();
    Schema schema2 = Util.load_schema();
    Assertions.assertSame(schema, schema2);
  }

  @Test
  public void loadDuisSchema_MissingFile() throws Exception {
    Field cert_names = Util.class.getDeclaredField("DUIS_FILE_NAME");
    cert_names.setAccessible(true);
    cert_names.set(null, "non-exist");

    Schema schema = Util.load_schema();
    Assertions.assertNull(schema);
  }

  @Test
  public void loadDuisSchema_BadFileContent() throws Exception {
    Field cert_names = Util.class.getDeclaredField("DUIS_FILE_NAME");
    cert_names.setAccessible(true);
    cert_names.set(null, "DUIS Schema V5.0-bad.xsd");

    Schema schema = Util.load_schema();
    Assertions.assertNull(schema);
  }

  @Test
  void createDocumentBuilderFactory() {
    Assertions.assertNotNull(Util.create_document_builder_factory());
  }

  @Test
  void createDocumentBuilderFactory_NoXXE() throws Exception {
    DocumentBuilderFactory dbf = Util.create_document_builder_factory();
    Assertions.assertTrue(dbf.getFeature("http://apache.org/xml/features/disallow-doctype-decl"));
    /* acid test, run through a basic xxe */
    InputStream is = UtilTest.class.getClassLoader().getResourceAsStream("duis-xxe.xml");
    Assertions.assertThrowsExactly(SAXParseException.class, () -> {
      dbf.newDocumentBuilder().parse(is);
    });
    is.close();
  }

  @Test
  void loadDuisFile_NonExist() throws Exception {
    Assertions.assertThrows(FileNotFoundException.class, () -> {
      Util.load_duis_file("non-exist");
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_duis_file_checked("non-exist");
    });
    Assertions.assertEquals(2, statusCode);
  }

  @Test
  void loadDuisFile_BadFile() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("null").getFile();
    Assertions.assertThrows(SAXException.class, () -> {
      Util.load_duis_file(file_name);
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_duis_file_checked(file_name);
    });
    Assertions.assertEquals(2, statusCode);
  }

  @Test
  void loadDuisFile_Valid() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Assertions.assertNotNull(Util.load_duis_file_checked(file_name));
  }

  @Test
  void loadDuisFile_InValid() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-invalid.XML").getFile();
    Assertions.assertNull(Util.load_duis_file_checked(file_name));
  }

  @Test
  void loadDuisFile_StdinValid() throws Exception {
    List<String> lines = Files.readAllLines(
        Paths.get(
            UtilTest.class.getClassLoader()
                .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").toURI()
        )
    );
    SystemLambda.withTextFromSystemIn((String[]) lines.toArray(new String[0])).execute(() -> {
      Assertions.assertNotNull(Util.load_duis_file_checked("-"));
    });
  }

  @Test
  void loadDuisFile_StdinExcept() throws Exception {
    List<String> lines = Files.readAllLines(
        Paths.get(
            UtilTest.class.getClassLoader()
                .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").toURI()
        )
    );
    SystemLambda.withTextFromSystemIn((String[]) lines.toArray(new String[0]))
        .andExceptionThrownOnInputEnd(new IOException()).execute(() -> {
          int statusCode = SystemLambda.catchSystemExit(() -> {
            Util.load_duis_file_checked("-");
          });
          Assertions.assertEquals(2, statusCode);
        });
  }

  @Test
  void createCertificateFactory() {
    Assertions.assertNotNull(Util.create_certificate_factory());
  }

  @Test
  void createKeyFactory() {
    Assertions.assertNotNull(Util.create_key_factory());
  }

  @Test
  void loadCertificate_NonExist() throws Exception {
    String file_name = "non-exist";
    CertificateFactory f = Util.create_certificate_factory();
    Assertions.assertThrows(FileNotFoundException.class, () -> {
      Util.load_certificate(f, file_name);
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_certificate_checked(f, file_name);
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void loadCertificate_BadFile() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("null").getFile();
    CertificateFactory f = Util.create_certificate_factory();
    Assertions.assertThrows(CertificateException.class, () -> {
      Util.load_certificate(f, file_name);
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_certificate_checked(f, file_name);
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void loadCertificate() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.pem").getFile();
    CertificateFactory f = Util.create_certificate_factory();
    Assertions.assertNotNull(Util.load_certificate_checked(f, file_name));
  }

  @Test
  void loadKey_NonExist() throws Exception {
    String file_name = "non-exist";
    KeyFactory f = Util.create_key_factory();
    Assertions.assertThrows(FileNotFoundException.class, () -> {
      Util.load_key(f, file_name);
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_key_checked(f, file_name);
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void loadKey_BadFile() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("null").getFile();
    KeyFactory f = Util.create_key_factory();
    Assertions.assertThrows(InvalidKeySpecException.class, () -> {
      Util.load_key(f, file_name);
    });
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Util.load_key_checked(f, file_name);
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void loadKey_pem() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.key.pem").getFile();
    KeyFactory f = Util.create_key_factory();
    Assertions.assertNotNull(Util.load_key_checked(f, file_name));
  }

  @Test
  void loadKey_der() throws Exception {
    String file_name = UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.key.der").getFile();
    KeyFactory f = Util.create_key_factory();
    Assertions.assertNotNull(Util.load_key_checked(f, file_name));
  }
}
