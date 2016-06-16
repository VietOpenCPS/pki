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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSignerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";

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
    public static Test suite()
    {
        return new TestSuite(PdfSignerTest.class);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new PdfSigner(pdfPath, cert);
    }
    
    public void testFilePath() {
    	assertEquals(pdfPath, signer.getOriginFilePath());
    	assertEquals("./src/test/java/resources/opencps.temp.pdf", signer.getTempFilePath());
    	assertEquals("./src/test/java/resources/opencps.signed.pdf", signer.getSignedFilePath());
    }
}
