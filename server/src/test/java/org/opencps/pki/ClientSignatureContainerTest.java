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

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Random;

import com.itextpdf.text.pdf.security.ExternalSignatureContainer;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class ClientSignatureContainerTest extends TestCase {

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
    
    public void testSignatureContainer() throws GeneralSecurityException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        ExternalSignatureContainer container = new ClientSignatureContainer(b);
        assertEquals(b, container.sign(mock(InputStream.class)));
    }
}
