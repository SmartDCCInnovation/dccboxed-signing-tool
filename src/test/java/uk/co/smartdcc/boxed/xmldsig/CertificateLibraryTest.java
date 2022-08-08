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

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.javatuples.Triplet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.stefanbirkner.systemlambda.SystemLambda;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public class CertificateLibraryTest {

        private List<Triplet<String, String, BigInteger>> testData_xmlSign = Arrays.asList(
                        new Triplet<>("Z1-accessControlBroker-ds.pem", "90B3D51F30000002",
                                        new BigInteger("587FE59553E2675B0C0E2A5C402A9F61", 16)),
                        new Triplet<>("Z1-networkOperator-ds.pem", "90B3D51F30020000",
                                        new BigInteger("1ECC6ED40F92A82835DB58174B4A666D", 16)),
                        new Triplet<>("Z1-recovery-ds.pem", "90B3D51F30000001",
                                        new BigInteger("469AFEC2E7C0CAAEC8A400769B702BC8", 16)),
                        new Triplet<>("Z1-supplier-ds.pem", "90B3D51F30010000",
                                        new BigInteger("14BE4AD2EA1D0E4EC7F7156BD24624A7", 16)),
                        new Triplet<>("Z1-supplier2-ds.pem", "90B3D51F30030000",
                                        new BigInteger("39EAFF0055CE4DAF085AC874C7C84BD3", 16)),
                        new Triplet<>("Z1-transitionalCoS-ds.pem", "90B3D51F30000004",
                                        new BigInteger("3CE369AB08F102975C5490D6B88FC066", 16)),
                        new Triplet<>("Z1-wanProvider-ds.pem", "90B3D51F30000007",
                                        new BigInteger("7C758B23CC7FE6923B01921F557D8B0A", 16)));

        private List<Triplet<String, String, BigInteger>> testData = testData_xmlSign;

        private static String[] certificate_names;

        @BeforeAll
        public static void beforeAll() throws Exception {
                Field field = CertificateLibrary.class.getDeclaredField("certificate_names");
                field.setAccessible(true);
                certificate_names = ((String[]) field.get(null)).clone();
        }

        @BeforeEach
        public void beforeEach() throws Exception {
                Field cert_names = CertificateLibrary.class.getDeclaredField("certificate_names");
                cert_names.setAccessible(true);
                cert_names.set(null, certificate_names.clone());

                Field instance = CertificateLibrary.class.getDeclaredField("INSTANCE");
                instance.setAccessible(true);
                instance.set(null, null);
        }

        @Test
        public void certificateLibraryCreate() {
                Assertions.assertNotNull(CertificateLibrary.getInstance());
        }

        private void containsUserCertificate(String businessId, Triplet<String, String, BigInteger> triple) {
                X509Certificate cert = CertificateLibrary.getInstance().lookup(businessId);
                Assertions.assertNotNull(cert, triple.getValue0());
                Assertions.assertEquals(triple.getValue2(), cert.getSerialNumber(), triple.getValue0());
        }

        @Test
        public void containsUserCertificatesByBusinessIDNoHyphan() {
                testData.forEach(triple -> {
                        String businessId = String.join("-", triple.getValue1());
                        containsUserCertificate(businessId, triple);
                });
        }

        @Test
        public void containsUserCertificatesByBusinessIDHyphan() {
                testData.forEach(triple -> {
                        String businessId = String.join("-", triple.getValue1().split("(?<=\\G.{2})"));
                        containsUserCertificate(businessId, triple);
                });
        }

        @Test
        public void containsUserCertificatesByBusinessIDNoHyphanLower() {
                testData.forEach(triple -> {
                        String businessId = triple.getValue1().toLowerCase();
                        containsUserCertificate(businessId, triple);
                });
        }

        @Test
        public void containsUserCertificatesByBusinessIDHyphanLower() {
                testData.forEach(triple -> {
                        String businessId = String.join("-", triple.getValue1().split("(?<=\\G.{2})")).toLowerCase();
                        containsUserCertificate(businessId, triple);
                });
        }

        @Test
        public void containsUserCertificatesBySerial() {
                testData.forEach(triple -> {
                        X509Certificate cert = CertificateLibrary.getInstance().lookup(triple.getValue2());
                        Assertions.assertNotNull(cert, triple.getValue0());
                        Assertions.assertEquals(triple.getValue2(), cert.getSerialNumber(), triple.getValue0());
                });
        }

        private void containsUserKey(String businessId, Triplet<String, String, BigInteger> triple) {
                byte[] data = "hello".getBytes();
                X509Certificate cert = CertificateLibrary.getInstance().lookup(businessId);
                Assertions.assertNotNull(cert, triple.getValue0());
                Assertions.assertEquals(triple.getValue2(), cert.getSerialNumber(), triple.getValue0());
                PublicKey pubKey = cert.getPublicKey();
                PrivateKey privKey = CertificateLibrary.getInstance().lookup_key(businessId);

                try {
                        Signature signer = Signature.getInstance("SHA256withECDSA");
                        signer.initSign(privKey);
                        signer.update(data);
                        byte[] signature = signer.sign();

                        Signature verifier = Signature.getInstance("SHA256withECDSA");
                        verifier.initVerify(pubKey);
                        verifier.update(data);
                        Assertions.assertTrue(verifier.verify(signature),
                                        "pub/private key check failed for " + triple.getValue0());
                } catch (Exception exception) {
                        Assertions.fail(exception.toString());
                }
        }

        @Test
        public void containsUserKeyByBusinessIDNoHyphan() {
                testData.forEach(triple -> {
                        String businessId = triple.getValue1();
                        containsUserKey(businessId, triple);
                });
        }

        @Test
        public void containsUserKeyByBusinessIDHyphan() {
                testData.forEach(triple -> {
                        String businessId = String.join("-", triple.getValue1().split("(?<=\\G.{2})"));
                        containsUserKey(businessId, triple);
                });
        }

        public void containsUserKeyByBusinessIDNoHyphanLower() {
                testData.forEach(triple -> {
                        String businessId = triple.getValue1().toLowerCase();
                        containsUserKey(businessId, triple);
                });
        }

        @Test
        public void containsUserKeyByBusinessIDHyphanLower() {
                testData.forEach(triple -> {
                        String businessId = String.join("-", triple.getValue1().split("(?<=\\G.{2})")).toLowerCase();
                        containsUserKey(businessId, triple);
                });
        }

        @Test
        public void containsUserKeyBySerial() {
                byte[] data = "hello".getBytes();
                testData.forEach(triple -> {
                        String businessId = triple.getValue1();
                        X509Certificate cert = CertificateLibrary.getInstance().lookup(businessId);
                        Assertions.assertNotNull(cert, triple.getValue0());
                        Assertions.assertEquals(triple.getValue2(), cert.getSerialNumber(), triple.getValue0());
                        PublicKey pubKey = cert.getPublicKey();
                        PrivateKey privKey = CertificateLibrary.getInstance().lookup_key(triple.getValue2());

                        try {
                                Signature signer = Signature.getInstance("SHA256withECDSA");
                                signer.initSign(privKey);
                                signer.update(data);
                                byte[] signature = signer.sign();

                                Signature verifier = Signature.getInstance("SHA256withECDSA");
                                verifier.initVerify(pubKey);
                                verifier.update(data);
                                Assertions.assertTrue(verifier.verify(signature),
                                                "pub/private key check failed for " + triple.getValue0());
                        } catch (Exception exception) {
                                Assertions.fail(exception.toString());
                        }
                });
        }

        @Test
        public void doesNotContainsUserKeyBySerial() {
                Assertions.assertNull(CertificateLibrary.getInstance().lookup_key(new BigInteger("123")));
        }

        @Test
        public void doesNotContainsUserKeyByBusinessId() {
                Assertions.assertNull(CertificateLibrary.getInstance().lookup_key("non-exist"));
        }

        @Test
        public void doesNotContainsUserCertificateBySerial() {
                Assertions.assertNull(CertificateLibrary.getInstance().lookup(new BigInteger("123")));
        }

        @Test
        public void doesNotContainsUserCertificateByBusinessId() {
                Assertions.assertNull(CertificateLibrary.getInstance().lookup("non-exist"));
        }

        @Test
        public void invalidFile() throws Exception {
                Field cert_names = CertificateLibrary.class.getDeclaredField("certificate_names");
                cert_names.setAccessible(true);
                cert_names.set(null, new String[] { "bad-file-name" });
                int statusCode = SystemLambda.catchSystemExit(() -> {
                        CertificateLibrary.getInstance();
                });
                Assertions.assertEquals(2, statusCode);
        }
}
