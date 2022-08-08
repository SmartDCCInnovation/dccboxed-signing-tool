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

import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Sign {
  public static int main_aux(String[] args) {
    if (args.length < 1 || args.length > 3) {
      System.err.println("[I] usage: message.xml [signingcert.pem] [signingkey.key]");
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

    /* if file already contains signatures, remove them */
    NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (signatureList.getLength() != 0) {
      System.err.println("[W] already signed, dropping signature");
      for (int i = 0; i < signatureList.getLength(); i++) {
        signatureList.item(i).getParentNode().removeChild(signatureList.item(i));
      }
    }

    Node requestId = doc.getElementsByTagNameNS("http://www.dccinterface.co.uk/ServiceUserGateway", "RequestID")
        .item(0);
    requestId.setTextContent(requestId.getTextContent().split("[0-9]*$", 2)[0] + System.currentTimeMillis());

    CertificateFactory fact = Util.create_certificate_factory();
    X509Certificate cer = null;
    if (args.length >= 2) {
      cer = Util.load_certificate_checked(fact, args[1]);
    } else {
      System.err.println("[W] cert file not provided, looking up from request id");
      String businessOriginatorId = requestId.getTextContent().split(":")[0];
      cer = CertificateLibrary.getInstance().lookup(businessOriginatorId);
      if (cer == null) {
        System.err.println("[E] could not locate certificate for: " + businessOriginatorId);
        return 3;
      }
    }
    System.err.println("[I] certificate serial number: " + cer.getSerialNumber());

    PrivateKey pkey = null;
    if (args.length >= 3) {
      pkey = Util.load_key_checked(Util.create_key_factory(), args[2]);
    } else {
      System.err.println("[W] private key file not provided, looking up from request id");
      String businessOriginatorId = requestId.getTextContent().split(":")[0];
      pkey = CertificateLibrary.getInstance().lookup_key(businessOriginatorId);
      if (pkey == null) {
        System.err.println("[E] could not locate private key for: " + businessOriginatorId);
        return 3;
      }
    }

    DOMSignContext dsc = new DOMSignContext(pkey, doc.getDocumentElement());
    dsc.setDefaultNamespacePrefix("ds");

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    Reference ref = null;
    try {
      ref = fac.newReference(
          "",
          fac.newDigestMethod(DigestMethod.SHA256, null),
          Collections.singletonList(
              fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
          null, null);

      SignedInfo si = null;
      si = fac.newSignedInfo(
          fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
          fac.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null),
          Collections.singletonList(ref));

      KeyInfoFactory kif = fac.getKeyInfoFactory();
      List<Object> x509Content = new ArrayList<Object>();
      x509Content.add(kif.newX509IssuerSerial(cer.getIssuerX500Principal().getName(), cer.getSerialNumber()));
      X509Data xd = kif.newX509Data(x509Content);
      KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

      XMLSignature signature = fac.newXMLSignature(si, ki);

      signature.sign(dsc);

      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer trans = tf.newTransformer();
      trans.transform(new DOMSource(doc), new StreamResult(System.out));
    } catch (Exception e) {
      System.err.println("[E] internal error: " + e.getMessage());
      return 2;
    }
    return 0;
  }

  public static void main(String[] args) {
    System.exit(main_aux(args));
  }
}
