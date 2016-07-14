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

import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class BaseSignerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";

    private BaseSigner signer;
    private X509Certificate cert;

    /**
     * Create the test case
     */
    public BaseSignerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(BaseSignerTest.class);
    }
    
    protected void setUp() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new MockBaseSigner("opencps.pdf", cert, "opencps.temp.pdf", "opencps.signed.pdf");
    }
    
    public void testHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA1, signer.getHashAlgorithm());
        signer.setHashAlgorithm(HashAlgorithm.SHA512);
        assertEquals(HashAlgorithm.SHA512, signer.getHashAlgorithm());
    }
    
    public void testGetCertificate() {
        assertEquals(cert, signer.getCertificate());
    }
    
    public void testGetFilePaths() {
        assertEquals("opencps.pdf", signer.getOriginFilePath());
        assertEquals("opencps.temp.pdf", signer.getTempFilePath());
        assertEquals("opencps.signed.pdf", signer.getSignedFilePath());
    }
    
    private class MockBaseSigner extends BaseSigner {

        public MockBaseSigner(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath) {
            super(filePath, cert, tempFilePath, signedFilePath);
        }

        @Override
        public byte[] computeHash() throws SignatureException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Boolean sign(byte[] signature) throws SignatureException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Boolean sign(byte[] signature, String filePath) throws SignatureException {
            // TODO Auto-generated method stub
            return null;
        }
        
    }

}
