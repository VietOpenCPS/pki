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
 * Signer for xml document
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class XmlSigner extends BaseSigner {

    /**
     * Constructor
     */
    public XmlSigner(String filePath, X509Certificate cert) {
        this(
            filePath,
            cert,
            Helper.stripFileExtension(filePath) + ".temp.xml",
            Helper.stripFileExtension(filePath) + ".signed.xml"
        );
    }

    /**
     * Constructor
     */
    public XmlSigner(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath) {
        super(filePath, cert, tempFilePath, signedFilePath);
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#computeHash()
     */
    @Override
    public byte[] computeHash() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature) throws SignatureException {
        return sign(signature, getTempFilePath());
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        // TODO Auto-generated method stub
        return null;
    }

}
