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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.stefanbirkner.systemlambda.SystemLambda;

public class ValidateTest {
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
        .getResource("readfw-response-no-signature.xml").getFile();
    int statusCode = SystemLambda.catchSystemExit(() -> {
      Validate.main(new String[] { file_name });
    });
    Assertions.assertEquals(1, statusCode);
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
    Assertions.assertEquals(3, statusCode);
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
      Assertions.assertEquals(0, statusCode);
    });
    Assertions.assertTrue(out.contains("xmlns:sr=\"http://www.dccinterface.co.uk/ServiceUserGateway\""));
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
}
