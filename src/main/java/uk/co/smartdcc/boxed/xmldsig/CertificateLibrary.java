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

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public final class CertificateLibrary {
  private static String[] certificate_names_xmlSign = {
      "dsp-xml-sign-90B3D51F30000002-ds",
      "dsp-xml-sign-90B3D51F30000002-ds-pre-1.4.1",
      "xml-sign-90B3D51F30020000-ds",
      "Z1-recovery-ds",
      "xml-sign-90B3D51F30010000-ds",
      "Z1-supplier2-ds",
      "Z1-transitionalCoS-ds",
      "Z1-wanProvider-ds",
      "xml-sign-00DB123456780004-ds"
  };
  private static String[] certificate_names = certificate_names_xmlSign;

  private static CertificateLibrary INSTANCE;

  public static CertificateLibrary getInstance() {
    if (INSTANCE == null) {
      try {
        INSTANCE = new CertificateLibrary();
      } catch (Exception e) {
        System.err.println("[E] failed to build certificate library: " + e.toString());
        System.exit(2);
      }
    }
    return INSTANCE;
  }

  private class Tuple {
    private String _businessId;
    private X509Certificate _certificate;
    private PrivateKey _key;

    public String getBusinessId() {
      return _businessId;
    }

    public X509Certificate getCertificate() {
      return _certificate;
    }

    public PrivateKey getKey() {
      return _key;
    }

    Tuple(final String businessId, final X509Certificate certificate, final PrivateKey key) {
      this._businessId = businessId;
      this._certificate = certificate;
      this._key = key;
    }
  }

  private List<Tuple> certificates = new ArrayList<Tuple>();

  private CertificateLibrary() throws Exception {
    CertificateFactory fact = Util.create_certificate_factory();
    KeyFactory keyFactory = Util.create_key_factory();

    for (String name : certificate_names) {
      X509Certificate cer = null;
      InputStream is = Validate.class.getClassLoader().getResourceAsStream(name + ".pem");
      cer = (X509Certificate) fact.generateCertificate(is);
      is.close();
      String principal = cer.getSubjectX500Principal().getName();
      if (!principal.contains(",")) {
        continue;
      }
      principal = principal.split(",")[0];
      if (!principal.contains("#030900")) {
        continue;
      }
      principal = principal.split("#030900")[1];

      PKCS8EncodedKeySpec privkeySpec = null;
      is = Validate.class.getClassLoader().getResourceAsStream(name + ".key");
      privkeySpec = new PKCS8EncodedKeySpec(is.readAllBytes());
      is.close();

      PrivateKey pkey = null;
      pkey = keyFactory.generatePrivate(privkeySpec);

      this.certificates.add(new Tuple(principal, cer, pkey));
    }
  }

  public X509Certificate lookup(final String businessId) {
    String id = businessId.replace("-", "").toLowerCase();
    for (Tuple t : this.certificates) {
      if (t.getBusinessId().equals(id)) {
        return t.getCertificate();
      }
    }
    return null;
  }

  public X509Certificate lookup(final BigInteger serial) {
    for (Tuple t : this.certificates) {
      if (t.getCertificate().getSerialNumber().equals(serial)) {
        return t.getCertificate();
      }
    }
    return null;
  }

  public PrivateKey lookup_key(final String businessId) {
    String id = businessId.replace("-", "").toLowerCase();
    for (Tuple t : this.certificates) {
      if (t.getBusinessId().equals(id)) {
        return t.getKey();
      }
    }
    return null;
  }

  public PrivateKey lookup_key(final BigInteger serial) {
    for (Tuple t : this.certificates) {
      if (t.getCertificate().getSerialNumber().equals(serial)) {
        return t.getKey();
      }
    }
    return null;
  }
}
