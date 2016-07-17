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
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.codec.Base64;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class Pksc7SignatureContainerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";
    private static final String encodedPkcs7 = "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";

    public Pksc7SignatureContainerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(Pksc7SignatureContainerTest.class);
    }
    
    public void testSignatureContainer() throws FileNotFoundException, GeneralSecurityException {
        PdfPKCS7 sgn = new PdfPKCS7(Base64.decode(encodedPkcs7), PdfName.ADBE_PKCS7_DETACHED, "BC");
        X509Certificate cert = sgn.getSigningCertificate();

        PdfPkcs7Signer signer = new PdfPkcs7Signer(pdfPath, cert);
        ExternalSignatureContainer container = new Pksc7SignatureContainer(signer, Base64.decode(encodedPkcs7));
        assertEquals(encodedPkcs7, Base64.encodeBytes(container.sign(mock(InputStream.class))));
    }
    
    public void testInvalidSignatureContainer() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        PdfPkcs7Signer signer = new PdfPkcs7Signer(pdfPath, cert);
        ExternalSignatureContainer container = new Pksc7SignatureContainer(signer, Base64.decode(encodedPkcs7));
        try {
            container.sign(mock(InputStream.class));
            fail("Missing exception");
        } catch (Exception ex) {
            assertEquals("Encoded pkcs7 is invalid. The certificate from signer not equal pkcs7's certificate", ex.getMessage());
        }
    }

}
