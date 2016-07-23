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

import java.security.KeyStore;
import java.security.SignatureException;
import java.util.List;

/**
 * Verifier for json document
 * 
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class JsonVerifier extends BaseVerifier {

    /**
     * Constructor
     */
    public JsonVerifier() {
        super();
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Verifier#getSignatureInfo()
     */
    @Override
    public List<SignatureInfo> getSignatureInfo(String filePath) {
        return null;
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    @Override
    public Boolean verifySignature(String filePath) throws SignatureException {
        return null;
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    @Override
    public Boolean verifySignature(String filePath, KeyStore ks) throws SignatureException {
        return null;
    }

}
