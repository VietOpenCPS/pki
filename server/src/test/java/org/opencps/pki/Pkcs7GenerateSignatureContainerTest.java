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

import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.itextpdf.text.io.RASInputStream;
import com.itextpdf.text.io.RandomAccessSource;
import com.itextpdf.text.io.RandomAccessSourceFactory;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class Pkcs7GenerateSignatureContainerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";

    public Pkcs7GenerateSignatureContainerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(Pkcs7GenerateSignatureContainerTest.class);
    }
    
    public void testSignatureContainer() throws GeneralSecurityException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        PdfSigner signer = new PdfSigner(pdfPath, cert);

        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(keyPath)));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = factory.generatePrivate(privKeySpec);
        pemReader.close();
        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");
        byte[] extSignature = signature.sign(signer.computeHash());

        PdfReader reader = new PdfReader(signer.getTempFilePath());
        AcroFields af = reader.getAcroFields();
        PdfDictionary v = af.getSignatureDictionary(signer.getSignatureFieldName());
        PdfArray b = v.getAsArray(PdfName.BYTERANGE);
        long[] gaps = b.asLongArray();

        RandomAccessSource readerSource = reader.getSafeFile().createSourceView();
        @SuppressWarnings("resource")
		InputStream rg = new RASInputStream(new RandomAccessSourceFactory().createRanged(readerSource, gaps));

        ExternalSignatureContainer container = new Pkcs7GenerateSignatureContainer(signer, extSignature);
        assertTrue(container.sign(rg).length > 0);
    }
    
    public void testSignatureContainerWithInvalidSignature() throws IOException, SignatureException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        PdfSigner signer = new PdfSigner(pdfPath, cert);

        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(keyPath)));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = factory.generatePrivate(privKeySpec);
        pemReader.close();
        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");
        byte[] extSignature = signature.sign(signer.computeHash());
        ExternalSignatureContainer container = new Pkcs7GenerateSignatureContainer(signer, extSignature);
        try {
            container.sign(mock(InputStream.class));
            fail("Missing exception");
        }
        catch (Exception ex) {
            assertEquals("Signature is not correct", ex.getMessage());
        }
    }
    
    public void testSignatureContainerWithEmptySignature() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        PdfSigner signer = new PdfSigner(pdfPath, cert);
        ExternalSignatureContainer container = new Pkcs7GenerateSignatureContainer(signer, new byte[0]);
        try {
            container.sign(mock(InputStream.class));
            fail("Missing exception");
        }
        catch (Exception ex) {
            assertEquals("Signature length not correct", ex.getMessage());
        }
    }
}
