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

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSignerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";
    private static final String signImagePath = "./src/test/java/resources/signature.png";

    X509Certificate cert;
    CertificateFactory cf;
    PdfSigner signer;

    /**
     * Create the test case
     */
    public PdfSignerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(PdfSignerTest.class);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new PdfSigner(pdfPath, cert);
    }

    public void testGetFilePaths() {
        assertEquals(pdfPath, signer.getOriginFilePath());
        assertEquals("./src/test/java/resources/opencps.temp.pdf", signer.getTempFilePath());
        assertEquals("./src/test/java/resources/opencps.signed.pdf", signer.getSignedFilePath());
    }

    public void testIsVisible() {
        assertEquals(signer, signer.setIsVisible(false));
        assertFalse(signer.getIsVisible());

        assertEquals(signer, signer.setIsVisible(true));
        assertTrue(signer.getIsVisible());
    }

    public void testSignatureFieldName() {
        assertEquals(signer, signer.setSignatureFieldName("OpenCPS-Signature"));
        assertEquals("OpenCPS-Signature", signer.getSignatureFieldName());
    }

    public void testSignatureGraphic() {
        assertEquals(signer, signer.setSignatureGraphic(signImagePath));
        assertTrue(signer.getSignatureGraphic().getImage() instanceof Image);
        BufferedImage bufferedImage = signer.getSignatureGraphic().getBufferedImage();
        assertEquals(300, bufferedImage.getWidth());
        assertEquals(128, bufferedImage.getHeight());
    }

    public void testComputeHash() throws IOException, SignatureException {
        signer.setSignatureGraphic(signImagePath);
        byte[] hash = signer.computeHash();
        assertTrue(hash.length > 0);

        PdfReader reader = new PdfReader(signer.getTempFilePath());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        assertTrue(names.size() > 0);
        assertEquals(names.get(0), signer.getSignatureFieldName());
        for (String name : names) {
            try {
                fields.verifySignature(name);
                fail("Missing exception");
            }
            catch (Exception ex) {
                assertEquals("can't decode PKCS7SignedData object", ex.getMessage());
            }
        }
    }

    public void testNotSetsignatureField() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
            PdfSigner signer = new PdfSigner(pdfPath, cert);
            signer.sign(new byte[0]);

            fail("Missing exception");
        }
        catch (Exception ex) {
            assertEquals("You must set signature field name before sign the document", ex.getMessage());
        }
    }
    
    public void testSign() throws IOException, OperatorCreationException, PKCSException, GeneralSecurityException, DocumentException {
        signer.setSignatureGraphic(signImagePath);
        byte[] hash = signer.computeHash();
        assertTrue(hash.length > 0);

        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(keyPath)));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = factory.generatePrivate(privKeySpec);
        pemReader.close();

        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");

        byte[] extSignature = signature.sign(hash);
        assertTrue(signer.sign(extSignature));
    }
}
