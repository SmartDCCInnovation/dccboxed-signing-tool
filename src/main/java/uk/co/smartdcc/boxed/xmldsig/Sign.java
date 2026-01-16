/*
 * Created on Mon Jan 16 2026
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

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import java.security.cert.CertificateException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class Sign {
  private Sign() {
  }

  public static X509Certificate verify_and_sign_input_stream(
      final boolean preserveCounter, final InputStream is, final Eui64CredentialResolver resolver
  )
      throws IOException, SAXException, ParserConfigurationException, CertificateException,
      KeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
      MarshalException, XMLSignatureException {
    Document doc = Util.parse_duis_stream(is);
    return sign_document(preserveCounter, doc, resolver);
  }

  public static X509Certificate sign_document(
      final boolean preserveCounter, final Document doc, final Eui64CredentialResolver resolver
  )
      throws CertificateException, KeyException, NoSuchAlgorithmException,
      InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
    /* if stream already contains signatures, remove them */
    NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (signatureList.getLength() != 0) {
      for (int i = 0; i < signatureList.getLength(); i++) {
        signatureList.item(i).getParentNode().removeChild(signatureList.item(i));
      }
    }

    Node requestId = doc.getElementsByTagNameNS(
        "http://www.dccinterface.co.uk/ServiceUserGateway",
        "RequestID"
    )
        .item(0);
    if (!preserveCounter) {
      requestId.setTextContent(
          requestId.getTextContent().split("[0-9]*$", 2)[0] + System.currentTimeMillis()
      );
    }

    String businessOriginatorId = requestId.getTextContent().split(":")[0].replace("-", "");
    X509Certificate cer = resolver.lookup(businessOriginatorId);
    if (cer == null) {
      throw new CertificateException("Certificate for " + businessOriginatorId + "not found");
    }
    PrivateKey pkey = resolver.lookup_key(businessOriginatorId);
    if (pkey == null) {
      throw new KeyException("Private key for " + businessOriginatorId + " not found");
    }

    DOMSignContext dsc = new DOMSignContext(pkey, doc.getDocumentElement());
    dsc.setDefaultNamespacePrefix("ds");

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    Reference ref = null;
    ref = fac.newReference(
        "",
        fac.newDigestMethod(DigestMethod.SHA256, null),
        Collections.singletonList(
            fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)
        ),
        null, null
    );

    SignedInfo si = null;
    si = fac.newSignedInfo(
        fac.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE,
            (C14NMethodParameterSpec) null
        ),
        fac.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null),
        Collections.singletonList(ref)
    );

    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List<Object> x509Content = new ArrayList<Object>();
    x509Content.add(
        kif.newX509IssuerSerial(
            cer.getIssuerX500Principal().getName(),
            cer.getSerialNumber()
        )
    );
    X509Data xd = kif.newX509Data(x509Content);
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

    XMLSignature signature = fac.newXMLSignature(si, ki);

    signature.sign(dsc);
    return cer;
  }

  public static ResultCode main_aux(final String[] arguments) {
    Boolean preserveCounter = Arrays.stream(arguments).anyMatch("--preserveCounter"::equals);
    String[] args = Arrays
        .stream(arguments)
        .filter(x -> !("--preserveCounter".equals(x)))
        .toArray(String[]::new);
    if (args.length < 1 || args.length > 3) {
      System.err.println(
          "[I] usage: message.xml [--preserveCounter] [signingcert.pem] [signingkey.key]"
      );
      if (args.length == 0) {
        System.err.println("[E] message not provided");
        return ResultCode.GENERIC_ERROR;
      }
    }

    Document doc = Util.load_duis_file_checked(args[0]);
    if (doc == null) {
      System.err.println("[I] failed xsd validation");
      return ResultCode.VALIDATION_FAIL;
    }
    System.err.println("[I] passed xsd validation");

    Eui64CredentialResolver resolver = new Eui64CredentialResolver() {
      @Override
      public X509Certificate lookup(final String eui64) {
        if (args.length >= 2) {
          return Util.load_certificate_checked(Util.create_certificate_factory(), args[1]);
        }
        return CertificateLibrary.getInstance().lookup(eui64);
      }

      @Override
      public PrivateKey lookup_key(final String eui64) {
        if (args.length >= 3) {
          return Util.load_key_checked(Util.create_key_factory(), args[2]);
        }
        return CertificateLibrary.getInstance().lookup_key(eui64);
      }
    };

    X509Certificate cer;
    try {
      cer = sign_document(preserveCounter, doc, resolver);
    } catch (CertificateException e) {
      System.err.println("[E] could not load certificate: " + e.getMessage());
      return ResultCode.MISSING_KEY;
    } catch (KeyException e) {
      System.err.println("[E] could not load private key: " + e.getMessage());
      return ResultCode.MISSING_KEY;
    } catch (Exception e) {
      System.err.println("[E] internal error: " + e.getMessage());
      return ResultCode.GENERIC_ERROR;
    }
    System.err.println("[I] certificate serial number: " + cer.getSerialNumber());

    TransformerFactory tf = TransformerFactory.newInstance();
    try {
      Transformer trans = tf.newTransformer();
      trans.transform(new DOMSource(doc), new StreamResult(System.out));
    } catch (Exception e) {
      System.err.println("[E] internal error: " + e.getMessage());
      return ResultCode.GENERIC_ERROR;
    }

    return ResultCode.SUCCESS;
  }

  public static void main(final String[] args) {
    System.exit(main_aux(args).value());
  }
}
