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
 * Signer for json document
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class JsonSigner extends BaseSigner {

    /**
     * Constructor
     */
    public JsonSigner(String filePath, X509Certificate cert) {
        this(
            filePath,
            cert,
            Helper.stripFileExtension(filePath) + ".signed.pdf"
        );
    }

    /**
     * Constructor
     *
     * @param filePath The path of json document
     * @param cert The certificate of user
     * @param signedFilePath Signed json document file path
     */
    public JsonSigner(String filePath, X509Certificate cert, String signedFilePath) {
        super(filePath, cert, null, signedFilePath);
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#computeHash()
     */
    @Override
    public byte[] computeHash() throws SignatureException {
        return null;
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature) throws SignatureException {
        return null;
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        return null;
    }

}
