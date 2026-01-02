/*
 * Created on Mon Jul 04 2022
 *
 * Copyright (c) 2025 Smart DCC Limited
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

public final class Util {
  private Util() {
  }

  private static String DUIS_FILE_NAME = "DUIS Schema V5.4.xsd";
  private static Schema schema = null;
  private static DOMImplementationRegistry registry = null;
  private static DOMImplementationLS factoryLS = null;

  public static Schema load_schema() {
    if (registry == null) {
      try {
        registry = DOMImplementationRegistry.newInstance();
      } catch (Exception e) {
        System.err.println("[E] internal error building DOM registry: " + e.getMessage());
        return null;
      }
    }
    if (factoryLS == null) {
      factoryLS = (DOMImplementationLS) registry.getDOMImplementation("LS");
    }
    if (schema != null) {
      return schema;
    }
    SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    URL url = Util.class.getClassLoader().getResource(DUIS_FILE_NAME);
    if (url == null) {
      System.err.println("[E] internal error loading schema, not found");
      return null;
    }

    try {
      /*
       * below ensures that XMLSchema.dtd and datatyes.dtd are loaded locally
       * instead of from w3.org
       */
      sf.setResourceResolver(new LSResourceResolver() {
        @Override
        public LSInput resolveResource(
            final String type, final String namespace, final String publicId, final String systemId,
            final String baseURI
        ) {
          try {
            if (systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")
                || systemId.equals("datatypes.dtd")) {
              String[] nameParts = systemId.split("/");
              String basename = nameParts[nameParts.length - 1];
              LSInput input = factoryLS.createLSInput();
              InputStream stream = Util.class.getClassLoader().getResource(basename)
                  .openStream();
              input.setPublicId(publicId);
              input.setSystemId(systemId);
              input.setBaseURI(baseURI);
              input.setCharacterStream(new InputStreamReader(stream));
              return input;
            }
          } catch (Exception e) {
            System.err.println(
                "[W] internal error loading " + systemId + " from local store: " + e.getMessage()
            );
          }
          /* return null for default resolver */
          return null;
        }
      });
      schema = sf.newSchema(url);
    } catch (Exception e) {
      System.err.println("[E] internal error loading schema: " + e.getMessage());
      schema = null;
    }
    return schema;
  }

  public static DocumentBuilderFactory create_document_builder_factory() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    dbf.setSchema(load_schema());
    dbf.setIgnoringElementContentWhitespace(true);
    try {
      dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    } catch (Exception e) {
      System.err.println("[W] could not disable doctype, system is possibly vulnerable to xxe");
    }
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    return dbf;
  }

  public static Document load_duis_file_checked(final String file_name) {
    try {
      return load_duis_file(file_name);
    } catch (FileNotFoundException e) {
      System.err.println("[E] message file not found");
    } catch (IOException e) {
      System.err.println("[E] message file could not be read");
    } catch (SAXException e) {
      System.err.println("[E] message file could not parse");
    } catch (ParserConfigurationException e) {
      System.err.println("[E] internal error while loading duis");
    }
    System.exit(2);
    return null;
  }

  public static Document load_duis_file(final String file_name)
      throws FileNotFoundException, IOException, SAXException, ParserConfigurationException {
    DocumentBuilderFactory dbf = create_document_builder_factory();
    Document doc = null;
    InputStream is = null;
    try {
      if (file_name.equals("-")) {
        is = System.in;
      } else {
        is = new FileInputStream(file_name);
      }
      doc = dbf.newDocumentBuilder().parse(is);
    } finally {
      try {
        is.close();
      } catch (Exception e) {
      }
    }

    Validator validator = load_schema().newValidator();
    DOMSource source = new DOMSource(doc);
    try {
      validator.validate(source);
    } catch (Exception e) {
      return null;
    }

    return doc;
  }

  public static CertificateFactory create_certificate_factory() {
    CertificateFactory fact = null;
    try {
      fact = CertificateFactory.getInstance("X.509");
    } catch (Exception e) {
      System.err.println("[E] internal error creating certificate factory");
      System.exit(2);
    }
    return fact;
  }

  public static KeyFactory create_key_factory() {
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("EC");
    } catch (Exception e) {
      System.err.println("[E] internal error creating key factory");
      System.exit(2);
    }
    return keyFactory;
  }

  public static X509Certificate load_certificate_checked(
      final CertificateFactory f,
      final String file_name
  ) {
    try {
      return load_certificate(f, file_name);
    } catch (FileNotFoundException e) {
      System.err.println("[E] cert file not found");
    } catch (CertificateException e) {
      System.err.println("[E] cert file could not be loaded");
    }
    System.exit(ResultCode.MISSING_KEY.value());
    return null;
  }

  public static X509Certificate load_certificate(
      final CertificateFactory f,
      final String file_name
  )
      throws FileNotFoundException, CertificateException {
    X509Certificate cer = null;
    FileInputStream is = null;
    try {
      is = new FileInputStream(file_name);
      cer = (X509Certificate) f.generateCertificate(is);
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (Exception e) {
        }
      }
    }
    return cer;
  }

  public static PrivateKey load_key_checked(final KeyFactory f, final String file_name) {
    try {
      return load_key(f, file_name);
    } catch (FileNotFoundException e) {
      System.err.println("[E] privkey file not found");
    } catch (IOException e) {
      System.err.println("[E] privkey file could not be loaded");
    } catch (InvalidKeySpecException e) {
      System.err.println("[E] privkey could not be parsed");
    }
    System.exit(ResultCode.MISSING_KEY.value());
    return null;
  }

  public static byte[] base64ToBytes(final String base64String) {
    try {
      return Base64.getDecoder().decode(base64String);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  public static PrivateKey load_key(final KeyFactory f, final String file_name)
      throws FileNotFoundException, IOException, InvalidKeySpecException {
    try (FileInputStream is = new FileInputStream(file_name)) {
      byte[] privkey = is.readAllBytes();
      String keyContent = new String(privkey, StandardCharsets.UTF_8)
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s+", "");

      byte[] b = base64ToBytes(keyContent);
      if (b == null) {
        b = privkey;
      }

      return f.generatePrivate(new PKCS8EncodedKeySpec(b));
    }
  }
}
