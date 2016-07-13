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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.VerificationException;

/**
 * Base abstract class for verifier
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public abstract class BaseVerifier implements Verifier {
    
    /**
     * Java key store
     */
    private KeyStore ks;

    /**
     * Constructor
     */
    public BaseVerifier() {
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Verifier#readCertificate()
     */
    @Override
    public CertificateInfo readCertificate(byte[] bytes) {
        try {
            InputStream is = new ByteArrayInputStream(bytes);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            return new CertificateInfo(cert);
        } catch (CertificateException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Verifier#readCertificate()
     */
    @Override
    public CertificateInfo readCertificate(String cert) {
        return readCertificate(cert.getBytes());
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#validateCertificate()
     */
    @Override
    public Boolean validateCertificate(X509Certificate cert) {
        return validateCertificate(cert, getKeyStore());
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#validateCertificate()
     */
    @Override
    public Boolean validateCertificate(X509Certificate cert, KeyStore ks) {
        try {
            List<VerificationException> errors = CertificateVerification.verifyCertificates(new Certificate[] { cert }, ks, Calendar.getInstance());
            if (errors.size() == 0) {
                CRL crl = CertificateUtil.getCRL(cert);
                if (crl != null) {
                    return !crl.isRevoked(cert);
                }
                return true;
            }
            else {
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Get java key store
     */
    public KeyStore getKeyStore() {
        return ks;
    }

    /**
     * Set java key store
     */
    public BaseVerifier setKeyStore(KeyStore ks) {
        this.ks = ks;
        return this;
    }

    /**
     * Load key store from file
     */
    public KeyStore loadKeyStore(String filePath, String password) throws NoSuchAlgorithmException, CertificateException, IOException {
        InputStream is = new FileInputStream(filePath);
        loadKeyStore(is, password);
        is.close();
        return ks;
    }
    
    /**
     * Load key store from input stream
     */
    public KeyStore loadKeyStore(InputStream is, String password) throws NoSuchAlgorithmException, CertificateException, IOException {
        ks.load(is, password.toCharArray());
        return ks;
    }

}
