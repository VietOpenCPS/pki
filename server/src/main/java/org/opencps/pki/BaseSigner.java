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

import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Base abstract class for singer
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public abstract class BaseSigner implements Signer {

    /**
     * X509 certificate
     */
    private X509Certificate cert;
    
    /**
     * Hash algorithm
     */
    private HashAlgorithm hashAlgorithm;
    
    /**
     * Origin Pdf document file path
     */
    private String originFilePath;
    
    /**
     * Temporary Pdf document file path after generate hash key
     */
    private String tempFilePath;

    /**
     * Signed Pdf document file path
     */
    private String signedFilePath;

    /**
     * Constructor
     */
    public BaseSigner(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath) {
        Security.addProvider(new BouncyCastleProvider());
        hashAlgorithm = HashAlgorithm.SHA1;
        this.originFilePath = filePath;
        this.cert = cert;
        this.tempFilePath = tempFilePath;
        this.signedFilePath = signedFilePath;
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#getHashAlgorithm()
     */
    @Override
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Set hash algorithm
     * @param hashAlgorithm
     */
    public BaseSigner setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /**
     * Get certificate 
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /**
     * Get origin file path of pdf document
     */
    public String getOriginFilePath() {
        return originFilePath;
    }

    /**
     * Get temporary file path of pdf document
     */
    public String getTempFilePath() {
        return tempFilePath;
    }

    /**
     * Get file path of signed pdf document
     */
    public String getSignedFilePath() {
        return signedFilePath;
    }

}
