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

import com.github.stefanbirkner.systemlambda.SystemLambda;

public class SignTest {

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
}
