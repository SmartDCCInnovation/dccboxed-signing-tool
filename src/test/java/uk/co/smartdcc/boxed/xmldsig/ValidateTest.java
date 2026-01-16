/*
 * Created on Thu Jan 16 2026
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import com.github.stefanbirkner.systemlambda.SystemLambda;

public class ValidateTest {
  @Test
  void validateInputStream_Valid() throws Exception {
    InputStream is = ValidateTest.class.getClassLoader()
        .getResourceAsStream("readfw-response.xml");

    SerialCredentialResolver resolver = CertificateLibrary.getInstance();
    byte[] signedXml = Validate.validate_input_stream(is, resolver);
    Assertions.assertNotNull(signedXml);
    Assertions.assertTrue(signedXml.length > 0);
    Assertions.assertTrue(new String(signedXml, "utf8").contains("<sr:Request"));
    Assertions.assertFalse(new String(signedXml, "utf8").contains("</ds:Signature>"));
    is.close();
  }

  @Test
  void validateDocument_Valid() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response.xml").getFile();
    Document doc = Util.load_duis_file(file_name);

    SerialCredentialResolver resolver = CertificateLibrary.getInstance();
    byte[] signedXml = Validate.validate_document(doc, resolver);
    Assertions.assertNotNull(signedXml);
    Assertions.assertTrue(signedXml.length > 0);
    Assertions.assertTrue(new String(signedXml, "utf8").contains("<sr:Request"));
    Assertions.assertFalse(new String(signedXml, "utf8").contains("</ds:Signature>"));
  }

  @Test
  void validateDocument_NoSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    Document doc = Util.load_duis_file(file_name);

    SerialCredentialResolver resolver = CertificateLibrary.getInstance();
    Assertions.assertThrows(java.security.SignatureException.class, () -> {
      Validate.validate_document(doc, resolver);
    });
  }

  @Test
  void validateDocument_ResponseNoSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("acknowledgement-error.xml").getFile();
    Document doc = Util.load_duis_file(file_name);

    SerialCredentialResolver resolver = CertificateLibrary.getInstance();
    byte[] signedXml = Validate.validate_document(doc, resolver);
    Assertions.assertNull(signedXml);
  }

  @Test
  void validateDocument_CertificateNotFound() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response.xml").getFile();
    Document doc = Util.load_duis_file(file_name);

    SerialCredentialResolver resolver = new SerialCredentialResolver() {
      @Override
      public X509Certificate lookup(BigInteger serial) {
        return null;
      }
    };

    Assertions.assertThrows(java.security.cert.CertificateException.class, () -> {
      Validate.validate_document(doc, resolver);
    });
  }

  @Test
  void validateDocument_InvalidSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-badsignature.xml").getFile();
    Document doc = Util.load_duis_file(file_name);

    SerialCredentialResolver resolver = CertificateLibrary.getInstance();

    Assertions.assertThrows(java.security.SignatureException.class, () -> {
      Validate.validate_document(doc, resolver);
    });
  }

  @Test
  void noArgs() throws Exception {
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] {});
    });
    Assertions.assertEquals(2, statusCode);
  }

  @Test
  void invalidDuis() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-invalid.xml").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name });
    });
    Assertions.assertEquals(10, statusCode);
  }

  @Test
  void missingSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("ECS17b_4.1.1_SINGLE_SUCCESS_REQUEST_DUIS.XML").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name });
    });
    Assertions.assertEquals(10, statusCode);
  }

  @Test
  void missingSerial() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-nonexist-serial.xml").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name });
    });
    Assertions.assertEquals(3, statusCode);
  }

  @Test
  void missingSerialSuccess() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-nonexist-serial.xml").getFile();
    String cert = ValidateTest.class.getClassLoader()
        .getResource("Z1-accessControlBroker-ds.pem").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name, cert });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void noSerial() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-no-serial.xml").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name });
    });
    Assertions.assertEquals(ResultCode.VALIDATION_FAIL.value(), statusCode);
  }

  @Test
  void noSerialSuccess() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-no-serial.xml").getFile();
    String cert = ValidateTest.class.getClassLoader()
        .getResource("Z1-accessControlBroker-ds.pem").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name, cert });
      });
      Assertions.assertEquals(ResultCode.VALIDATION_FAIL.value(), statusCode);
    });
    Assertions.assertFalse(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
  }

  @Test
  void badSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response.xml").getFile();
    String cert = ValidateTest.class.getClassLoader()
        .getResource("Z1-supplier-ds.pem").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name, cert });
    });
    Assertions.assertEquals(10, statusCode);
  }

  @Test
  void nominal() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response.xml").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertFalse(out.contains("</ds:Signature>"));
  }

  @Test
  void responseNoSignature() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("acknowledgement-error.xml").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("<sr:ResponseCode>E65</sr:ResponseCode>"));
    Assertions.assertFalse(out.contains("</ds:Signature>"));
  }

  @Test
  void responseDuis5_3ReadInventory4G() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("read-inventory-response-4g.xml").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("<sr:Response"));
    Assertions.assertFalse(out.contains("</ds:Signature>"));
  }

  @Test
  void responseDuis5_4ReadInventory() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("read-inventory-response-5.4.xml").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("<sr:Response"));
    Assertions.assertFalse(out.contains("</ds:Signature>"));
  }

  @Test
  void responseDuis5_3ReadFirmwareResigned() throws Exception {
    String file_name = ValidateTest.class.getClassLoader()
        .getResource("readfw-response-resigned.xml").getFile();
    String out = SystemLambda.tapSystemOut(() -> {
      int statusCode = SystemLambda.catchSystemExit(() -> {
        Validate.main(new String[] { file_name });
      });
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("<sr:Response"));
    Assertions.assertFalse(out.contains("</ds:Signature>"));
  }
}
