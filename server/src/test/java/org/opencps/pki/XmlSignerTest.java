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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.itextpdf.text.pdf.codec.Base64;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class XmlSignerTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
//    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String xmlPath = "./src/test/java/resources/document.xml";

    X509Certificate cert;
    CertificateFactory cf;
    XmlSigner signer;

    /**
     * Create the test case
     */
    public XmlSignerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(XmlSignerTest.class);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new XmlSigner(xmlPath, cert);
    }

    public void testComputeHash() throws SignatureException {
        byte[] hash = signer.computeHash();
        System.out.println("Hash value:" + Base64.encodeBytes(hash));
        System.out.println("Hash length:" + hash.length);
    }

}
