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

import java.io.InputStream;
import java.security.GeneralSecurityException;

import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;

/**
 * Produces a signed data from client. Useful for deferred signing
 * 
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class ClientSignatureContainer implements ExternalSignatureContainer {

    private byte[] signedData;

    /**
     * Constructor
     */
    public ClientSignatureContainer(byte[] data) {
        signedData = data;
    }

    @Override
    public void modifySigningDictionary(PdfDictionary pd) {
    }

    @Override
    public byte[] sign(InputStream is) throws GeneralSecurityException {
        return signedData;
    }

}
