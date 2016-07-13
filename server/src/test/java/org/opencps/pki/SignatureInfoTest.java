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
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class SignatureInfoTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private SignatureInfo signInfo;
    private X509Certificate cert;

    /**
     * Create the test case
     */
    public SignatureInfoTest(String testName) {
        super(testName);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));

        signInfo = new MockSignatureInfo(cert);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(SignatureInfoTest.class);
    }
    
    public void testGetCertificate() {
        assertEquals(cert, signInfo.getCertificate());
    }
    
    public void testGetCertificateInfo() {
        assertTrue(signInfo.getCertificateInfo() instanceof CertificateInfo);
    }
    
    public void testGetSignDate() {
        Calendar now = Calendar.getInstance();
        Calendar signDate = signInfo.getSignDate();
        assertEquals(signDate.get(Calendar.YEAR), now.get(Calendar.YEAR));
        assertEquals(signDate.get(Calendar.MONTH), now.get(Calendar.MONTH));
        assertEquals(signDate.get(Calendar.DAY_OF_YEAR), now.get(Calendar.DAY_OF_YEAR));
    }
    
    public void testGetTimeStamp() {
        Calendar now = Calendar.getInstance();
        Calendar timeStamp = signInfo.getTimeStamp();
        assertEquals(timeStamp.get(Calendar.YEAR), now.get(Calendar.YEAR));
        assertEquals(timeStamp.get(Calendar.MONTH), now.get(Calendar.MONTH));
        assertEquals(timeStamp.get(Calendar.DAY_OF_YEAR), now.get(Calendar.DAY_OF_YEAR));
    }
    
    public void testGetDigestAlgorithm() {
        assertEquals("RSA", signInfo.getDigestAlgorithm());
    }
    
    public void testGetHashAlgorithm() {
        assertEquals("SHA1", signInfo.getHashAlgorithm());
    }
    
    public void testIsVerify() throws GeneralSecurityException {
        assertFalse(signInfo.isVerify());
    }

    public class MockSignatureInfo extends SignatureInfo {

        public MockSignatureInfo(X509Certificate cert) {
            this.cert = cert;
            certInfo = new CertificateInfo(cert);
            signDate = Calendar.getInstance();
            timeStamp = Calendar.getInstance();
            digestAlgorithm = "RSA";
            hashAlgorithm = "SHA1";
        }

        @Override
        public Boolean isVerify() throws GeneralSecurityException {
            return false;
        }
        
    }
    
}
