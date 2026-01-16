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

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class Validate {
  private static final int HEX = 16;

  private Validate() {
  }

  public static byte[] validate_input_stream(
      final InputStream is,
      final SerialCredentialResolver resolver
  )
      throws IOException, SAXException, ParserConfigurationException, SignatureException,
      CertificateException, MarshalException, XMLSignatureException {
    Document doc = Util.parse_duis_stream(is);
    return validate_document(doc, resolver);
  }

  public static byte[] validate_document(
      final Document doc,
      final SerialCredentialResolver resolver
  )
      throws SignatureException, CertificateException, MarshalException, XMLSignatureException,
      IOException {
    NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (signatureList.getLength() != 1) {
      NodeList root = doc.getChildNodes();
      if (root.getLength() == 1 && root.item(0).getLocalName().equals("Response")) {
        return null;
      }
      throw new SignatureException("No signature found");
    }

    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    if (nl.getLength() != 1) {
      throw new SignatureException("X509SerialNumber missing from signature");
    }
    BigInteger serial = new BigInteger(nl.item(0).getTextContent());
    X509Certificate cer = resolver.lookup(serial);
    if (cer == null) {
      throw new CertificateException("Certificate for " + serial.toString(HEX) + "not found");
    }

    PublicKey key = cer.getPublicKey();

    DOMValidateContext valContext = new DOMValidateContext(key, signatureList.item(0));
    valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    XMLSignature signature = null;

    signature = fac.unmarshalXMLSignature(valContext);

    if (signature.validate(valContext)) {
      Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
      InputStream is = ((Reference) i.next()).getDigestInputStream();
      return is.readAllBytes();
    }
    throw new SignatureException("Signature is not valid");
  }

  public static ResultCode main_aux(final String[] args) {
    if (args.length < 1 || args.length > 2) {
      System.err.println("[I] usage: message.xml [signingcert.pem]");
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

    SerialCredentialResolver resolver = new SerialCredentialResolver() {
      @Override
      public X509Certificate lookup(final BigInteger serial) {
        if (args.length >= 2) {
          return Util.load_certificate_checked(Util.create_certificate_factory(), args[1]);
        }
        return CertificateLibrary.getInstance().lookup(serial);
      }
    };

    byte[] signedXml = null;
    try {
      signedXml = validate_document(doc, resolver);
    } catch (CertificateException e) {
      System.err.println("[E] could not load certificate: " + e.getMessage());
      return ResultCode.MISSING_KEY;
    } catch (SignatureException e) {
      System.err.println("[E] validation failed: " + e.getMessage());
      return ResultCode.VALIDATION_FAIL;
    } catch (Exception e) {
      System.err.println("[E] internal error: " + e.getMessage());
      return ResultCode.GENERIC_ERROR;
    }

    if (signedXml == null) {
      System.err.println("[I] response without signature, validation check skipped");
      try {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(doc), new StreamResult(System.out));
      } catch (Exception e) {
        System.err.println("[E] internal error");
        return ResultCode.GENERIC_ERROR;
      }
      return ResultCode.SUCCESS;
    }

    System.err.println("[I] passed signature check");
    try {
      System.out.write(signedXml);
      System.out.println();
    } catch (Exception e) {
      System.err.println("[E] internal error");
      return ResultCode.GENERIC_ERROR;
    }
    return ResultCode.SUCCESS;
  }

  public static void main(final String[] args) {
    System.exit(main_aux(args).value());
  }
}
