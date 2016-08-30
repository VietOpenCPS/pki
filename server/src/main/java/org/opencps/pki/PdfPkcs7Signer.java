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

import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * Signer for pdf document using encoded pkcs7
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfPkcs7Signer extends PdfSigner {

    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert) {
        super(filePath, cert);
    }
    
    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath, boolean isVisible) {
        super(filePath, cert, tempFilePath, signedFilePath, isVisible);
    }

    /**
     * Compute hash key with corner coordinates of rectangle
     */
    @Override
    public byte[] computeHash(float llx, float lly, float urx, float ury) throws SignatureException {
        return computeDigest(llx, lly, urx, ury);
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        return signExternal(new Pksc7SignatureContainer(this, signature), filePath);
    }
}
