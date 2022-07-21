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
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class Validate {
  public static int main_aux(String[] args) {
    if (args.length < 1 || args.length > 2) {
      System.err.println("[I] usage: message.xml [signingcert.pem]");
      if (args.length == 0) {
        System.err.println("[E] message not provided");
        return 2;
      }
    }

    Document doc = Util.load_duis_file_checked(args[0]);
    if (doc == null) {
      System.err.println("[I] failed xsd validation");
      return 10;
    }
    System.err.println("[I] passed xsd validation");

    NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (signatureList.getLength() != 1) {
      System.err.println("[W] signature missing, validation check skipped");
      return 1;
    }

    CertificateFactory fact = Util.create_certificate_factory();
    X509Certificate cer = null;
    if (args.length >= 2) {
      cer = Util.load_certificate_checked(fact, args[1]);
    } else {
      System.err.println("[W] cert file not provided, looking up serial number");
      NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
      if (nl.getLength() >= 1) {
        cer = CertificateLibrary.getInstance().lookup(new BigInteger(nl.item(0).getTextContent()));
      }
      if (cer == null) {
        System.err.println(
            "[E] could not locate certificate for: " + (nl.getLength() >= 1 ? nl.item(0).getTextContent() : "unknown"));
        return 3;
      }
    }
    PublicKey key = cer.getPublicKey();
    System.err.println("[I] certificate serial number: " + cer.getSerialNumber());

    DOMValidateContext valContext = new DOMValidateContext(key, signatureList.item(0));
    valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    XMLSignature signature = null;
    boolean coreValidity = false;
    try {
      signature = fac.unmarshalXMLSignature(valContext);

      coreValidity = signature.validate(valContext);
      if (coreValidity) {
        Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
        while (i.hasNext()) {
          InputStream is = ((Reference) i.next()).getDigestInputStream();
          System.out.write(is.readAllBytes());
          System.out.println();
        }
      }
    } catch (Exception e) {
      System.err.println("[E] internal error: " + e.getMessage());
      return 2;
    }

    System.err.println("[I] " + (coreValidity ? "passed" : "failed") + " signature check");
    return coreValidity ? 0 : 10;
  }

  public static void main(String[] args) {
    System.exit(main_aux(args));
  }
}
