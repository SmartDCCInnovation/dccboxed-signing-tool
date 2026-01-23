/*
 * Created on Thu Jul 07 2022
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

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXParseException;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.XMLSignature;

import com.github.stefanbirkner.systemlambda.SystemLambda;

public class SignTest {

  @Test
  void signDocument_Valid() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Document doc = Util.load_duis_file(file_name);

    Assertions.assertNotNull(
        doc.getElementsByTagNameNS(
            "http://www.dccinterface.co.uk/ServiceUserGateway",
            "RequestID"
        ).item(0)
    );
    String reqid = doc.getElementsByTagNameNS(
        "http://www.dccinterface.co.uk/ServiceUserGateway",
        "RequestID"
    ).item(0).getTextContent();
    Assertions.assertNull(doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
    Eui64CredentialResolver resolver = CertificateLibrary.getInstance();
    X509Certificate cert = Sign.sign_document(false, doc, resolver);
    Assertions.assertNotNull(cert);
    Assertions.assertEquals(new BigInteger("14BE4AD2EA1D0E4EC7F7156BD24624A7", 16), cert.getSerialNumber());
    Assertions.assertNotNull(doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
    Assertions.assertNotEquals(
        reqid, doc.getElementsByTagNameNS(
            "http://www.dccinterface.co.uk/ServiceUserGateway",
            "RequestID"
        ).item(0).getTextContent()
    );
  }

  @Test
  void signDocument_PreserveCounter() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Document doc = Util.load_duis_file(file_name);
    String originalCounter = doc.getElementsByTagNameNS(
        "http://www.dccinterface.co.uk/ServiceUserGateway", "RequestID"
    ).item(0).getTextContent();

    Eui64CredentialResolver resolver = CertificateLibrary.getInstance();
    Sign.sign_document(true, doc, resolver);
    String newCounter = doc.getElementsByTagNameNS(
        "http://www.dccinterface.co.uk/ServiceUserGateway", "RequestID"
    ).item(0).getTextContent();
    Assertions.assertEquals(originalCounter, newCounter);
  }

  @Test
  void signDocument_CertificateNotFound() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Document doc = Util.load_duis_file(file_name);

    Eui64CredentialResolver resolver = new Eui64CredentialResolver() {
      @Override
      public X509Certificate lookup(String eui64) {
        return null;
      }

      @Override
      public PrivateKey lookup_key(String eui64) {
        return CertificateLibrary.getInstance().lookup_key(eui64);
      }
    };

    Assertions.assertThrows(java.security.cert.CertificateException.class, () -> {
      Sign.sign_document(false, doc, resolver);
    });
  }

  @Test
  void signDocument_KeyNotFound() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Document doc = Util.load_duis_file(file_name);

    Eui64CredentialResolver resolver = new Eui64CredentialResolver() {
      @Override
      public X509Certificate lookup(String eui64) {
        return CertificateLibrary.getInstance().lookup(eui64);
      }

      @Override
      public PrivateKey lookup_key(String eui64) {
        return null;
      }
    };

    Assertions.assertThrows(java.security.KeyException.class, () -> {
      Sign.sign_document(false, doc, resolver);
    });
  }

  @Test
  void verifyAndSignInputStream_Valid() throws Exception {
    InputStream is = UtilTest.class.getClassLoader()
        .getResourceAsStream("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML");
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    Eui64CredentialResolver resolver = CertificateLibrary.getInstance();
    X509Certificate cert = Sign.verify_and_sign_input_stream(false, is, os, resolver);
    Assertions.assertNotNull(cert);
    Assertions.assertTrue(os.toString().contains("</ds:Signature>"));
    is.close();
  }

  @Test
  void verifyAndSignInputStream_InvalidXml() throws Exception {
    InputStream is = UtilTest.class.getClassLoader()
        .getResourceAsStream("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-invalid.XML");
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    Eui64CredentialResolver resolver = CertificateLibrary.getInstance();
    Assertions.assertThrows(SAXParseException.class, () -> {
      Sign.verify_and_sign_input_stream(false, is, os, resolver);
    });
    is.close();
    Assertions.assertEquals(0, os.size());
  }

  @Test
  void verifyAndSignInputStream_KeyNotFound() throws Exception {
    InputStream is = UtilTest.class.getClassLoader()
        .getResourceAsStream("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML");
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    Eui64CredentialResolver resolver = new Eui64CredentialResolver() {
      @Override
      public X509Certificate lookup(String eui64) {
        return CertificateLibrary.getInstance().lookup(eui64);
      }

      @Override
      public PrivateKey lookup_key(String eui64) {
        return null;
      }
    };

    Assertions.assertThrows(java.security.KeyException.class, () -> {
      Sign.verify_and_sign_input_stream(false, is, os, resolver);
    });
    is.close();
    Assertions.assertEquals(0, os.size());
  }

  @Test
  void noArgs() throws Exception {
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(new String[] {});
    });
    Assertions.assertEquals(2, statusCode);
  }

  @Test
  void invalidDuis() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-invalid.XML").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(new String[] { file_name });
    });
    Assertions.assertEquals(10, statusCode);
  }

  @Test
  void missingBusinessIdCert() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-nonexist-businessid.XML").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(new String[] { file_name });
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void missingBusinessIdKey() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-nonexist-businessid.XML").getFile();
    String cert = UtilTest.class.getClassLoader()
        .getResource("Z1-supplier-ds.pem").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(new String[] { file_name, cert });
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void missingBusinessIdSuccess() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-nonexist-businessid.XML").getFile();
    String cert = UtilTest.class.getClassLoader()
        .getResource("Z1-supplier-ds.pem").getFile();
    String key = UtilTest.class.getClassLoader()
        .getResource("Z1-supplier-ds.key.pem").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { file_name, cert, key });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void alreadySigned() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS-signed.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertEquals(1, StringUtils.countMatches(out, "</ds:Signature>"));
  }

  @Test
  void nominal() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertFalse(out.contains("90-B3-D5-1F-30-01-00-00:00-07-81-D7-00-00-36-CE:1000"));
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void nominalPreserveCounter1() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { "--preserveCounter", file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("90-B3-D5-1F-30-01-00-00:00-07-81-D7-00-00-36-CE:1000"));
  }

  @Test
  void nominalPreserveCounter2() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { file_name, "--preserveCounter" });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("90-B3-D5-1F-30-01-00-00:00-07-81-D7-00-00-36-CE:1000"));
  }

  @Test
  void nominalOtherUser() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS50_9.1_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertFalse(out.contains("00-db-12-34-56-78-00-04:00-DB-12-34-56-78-90-A0:1000"));
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
    Assertions.assertTrue(out.contains("00-db-12-34-56-78-00-04:00-DB-12-34-56-78-90-A0:"));
  }

  @Test
  void nominalCertificateProvided() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(
            new String[] { file_name, UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.pem").getFile() }
        );
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertFalse(out.contains("90-B3-D5-1F-30-01-00-00:00-07-81-D7-00-00-36-CE:1000"));
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void invalidCertificateProvided() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(new String[] { file_name, UtilTest.class.getClassLoader().getResource("null").getFile() });
    });
    Assertions.assertEquals(ResultCode.MISSING_KEY.ordinal(), statusCode);
  }

  @Test
  void nominalKeyProvided() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Sign.main(
            new String[] { file_name, UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.pem").getFile(),
                UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.key.der").getFile() }
        );
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertFalse(out.contains("90-B3-D5-1F-30-01-00-00:00-07-81-D7-00-00-36-CE:1000"));
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void invalidKeyProvided() throws Exception {
    String file_name = UtilTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Sign.main(
          new String[] { file_name, UtilTest.class.getClassLoader().getResource("Z1-supplier-ds.pem").getFile(),
              UtilTest.class.getClassLoader().getResource("null").getFile() }
      );
    });
    Assertions.assertEquals(ResultCode.MISSING_KEY.ordinal(), statusCode);
  }
}
