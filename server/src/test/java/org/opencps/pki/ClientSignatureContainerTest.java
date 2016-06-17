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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;

import com.itextpdf.text.pdf.security.ExternalSignatureContainer;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class ClientSignatureContainerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";

    public ClientSignatureContainerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(ClientSignatureContainerTest.class);
    }
    
    public void testSignatureContainer() throws GeneralSecurityException, FileNotFoundException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        PdfSigner signer = new PdfSigner(pdfPath, cert);
        ExternalSignatureContainer container = new ClientSignatureContainer(signer, b);
        assertTrue(container.sign(mock(InputStream.class)).length > 0);
    }
}
