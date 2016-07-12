/**
* OpenCPS PKI is the open source PKI Integration software
* Copyright (C) 2016-present OpenCPS community

* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>
*/
package org.opencps.pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfVerifierTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";
    private static final String signImagePath = "./src/test/java/resources/signature.png";

    X509Certificate cert;
    CertificateFactory cf;
    PdfVerifier verifier;
    PdfSigner signer;

    /**
     * Create the test case
     */
    public PdfVerifierTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(PdfVerifierTest.class);
    }

    protected void setUp() throws IOException, OperatorCreationException, PKCSException, GeneralSecurityException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new PdfSigner(pdfPath, cert);
        verifier = new PdfVerifier();
        signer.setSignatureGraphic(signImagePath);
        signer.setHashAlgorithm(HashAlgorithm.SHA1);
        byte[] hash = signer.computeHash();

        Security.addProvider(new BouncyCastleProvider());
        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(keyPath)));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = factory.generatePrivate(privKeySpec);
        pemReader.close();
        
        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");
        
        byte[] extSignature = signature.sign(hash);
        signer.sign(extSignature);
    }
    
    public void testVerifySignature() throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(signer.getSignedFilePath());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        assertTrue(names.size() > 0);
        assertEquals(names.get(0), signer.getSignatureFieldName());
        for (String name : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            assertTrue(pkcs7.verify());
        }
        
        assertFalse(verifier.verifySignature(signer.getSignedFilePath()));
    }
    
    public void testGetSignatureInfo() {
        List<SignatureInfo> infors = verifier.getSignatureInfo(signer.getSignedFilePath());
        SignatureInfo infor = infors.size() > 0 ? infors.get(0) : null;
        assertEquals("OpenCPS PKI", infor.getCertificateInfo().getCommonName());
    }

//    public void testBycSignature() throws IOException, GeneralSecurityException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
//        String signedPath = "./src/test/java/resources/signed.pdf";
//        List<SignatureInfo> infors = verifier.getSignatureInfo(signedPath);
//        SignatureInfo infor = infors.size() > 0 ? infors.get(0) : null;
//        if (infor != null) {
//            System.out.println(infor.getCertificateInfo().getCommonName());
//            System.out.println(infor.getCertificateInfo().getOrganizationUnit());
//            System.out.println(infor.getCertificateInfo().getOrganization());
//            RSAPublicKey rsaKey = (RSAPublicKey) infor.getCertificateInfo().getCertificate().getPublicKey();
//            System.out.println("Public key length: " + rsaKey.getModulus().bitLength() / 8);
//        }
//
//        PdfReader reader = new PdfReader(signedPath);
//        AcroFields fields = reader.getAcroFields();
//        ArrayList<String> names = fields.getSignatureNames();
//        for (String name : names) {
//            PdfPKCS7 pkcs7 = fields.verifySignature(name);
//            System.out.println("Digest algorithm: " + pkcs7.getDigestAlgorithm());
//            System.out.println("Hash algorithm: " + pkcs7.getHashAlgorithm());
//            //Field sigAttrField = PdfPKCS7.class.getDeclaredField("sigAttr");
//            Field sigAttrField = PdfPKCS7.class.getDeclaredField("digest");
//            sigAttrField.setAccessible(true);
//            byte[] digestAttr = (byte[]) sigAttrField.get(pkcs7);
//            System.out.printf("Signature: %s\n", Helper.binToHex(digestAttr));
//            System.out.println("Byte length: " + digestAttr.length);
//            
//            assertTrue(pkcs7.verify());
//        }
//    }

}
