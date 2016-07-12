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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class CertificateInfoTest extends TestCase {

    private static final String certPath = "./src/test/java/resources/cert.pem";
    private CertificateInfo certInfo;
    private X509Certificate cert;
    
    /**
     * Create the test case
     */
    public CertificateInfoTest(String testName) {
        super(testName);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        certInfo = new CertificateInfo(cert);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(CertificateInfoTest.class);
    }
    
    public void testGetCommonName() {
        assertEquals("OpenCPS PKI", certInfo.getCommonName());
    }
    
    public void testGetOrganizationUnit() {
        assertEquals("OpenCPS Technical Committee", certInfo.getOrganizationUnit());
    }
    
    public void testGetOrganization() {
        assertEquals("OpenCPS Community", certInfo.getOrganization());
    }
    
    public void testGetEmail() {
        assertEquals("demo@opencps.org.vn", certInfo.getEmail());
    }
    
    public void testGetSerialNumber() {
        assertEquals("17284444107497658335", certInfo.getSerialNumber());
    }
    
    public void testGetIssuer() {
        assertEquals("EMAILADDRESS=demo@opencps.org.vn, CN=OpenCPS PKI, OU=OpenCPS Technical Committee, O=OpenCPS Community, L=Hanoi, ST=Hanoi, C=VN", certInfo.getIssuer());
    }
    
    public void testGetValid() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
        assertEquals("2016-06-15", df.format(certInfo.getValidFrom()));
        assertEquals("2019-03-12", df.format(certInfo.getValidTo()));
    }
    
    public void testGetCertificate() {
        assertEquals(cert, certInfo.getCertificate());
    }
}
