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
import java.security.cert.X509Certificate;

/**
 * Server signer interface
 *
 * This interface class defines the standard functions that any
 * server signer needs to define.
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public interface ServerSigner {

    /**
     * Read certificate
     */
    public CertificateInfo readCertificate(byte[] bytes);

    /**
     * Read certificate
     */
    public CertificateInfo readCertificate(String cert);
    
    /**
     * Validate X509 certificate
     */
    public Boolean validateCertificate(X509Certificate cert);
    
    /**
     * Validate X509 certificate
     */
    public Boolean validateCertificate(X509Certificate cert, KeyStore ks);
    
    /**
     * Verify signature of document
     */
    public Boolean verifySignature(String filePath);

    /**
     * Verify signature of document
     */
    public Boolean verifySignature(String filePath, KeyStore ks);

    /**
     * Compute hash key
     */
    public byte[] computeHash();
    
    /**
     * Get hash algorithm
     */
    public HashAlgorithm getHashAlgorithm();
    
    /**
     * Attach signature to document
     */
    public Boolean sign(byte[] signature);

    /**
     * Attach signature to document
     */
    public Boolean sign(byte[] signature, String filePath);
}
