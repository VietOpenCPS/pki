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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;

import com.itextpdf.text.pdf.security.PdfPKCS7;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSignatureInfoTest extends TestCase {

    private PdfSignatureInfo signInfo;

    /**
     * Create the test case
     */
    public PdfSignatureInfoTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(PdfSignatureInfoTest.class);
    }
    
    public void testGetPdfPKCS7() {
        assertTrue(signInfo.getPdfPKCS7() instanceof PdfPKCS7);
    }
    
    protected void setUp() {
        PdfPKCS7 pkcs7 = mock(PdfPKCS7.class, CALLS_REAL_METHODS);
        signInfo = new PdfSignatureInfo(pkcs7);
    }
    
}
