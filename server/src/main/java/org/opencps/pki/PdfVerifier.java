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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CRLVerifier;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OCSPVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.security.VerificationOK;

/**
 * Verifier for pdf document
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfVerifier extends BaseVerifier {

    /**
     * Constructor
     */
    public PdfVerifier() {
        super();
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    @Override
    public List<SignatureInfo> getSignatureInfo(String filePath) {
        List<SignatureInfo> list = new ArrayList<SignatureInfo>();
        try {
            InputStream is = new FileInputStream(filePath);
            list = getSignatureInfo(is);
            is.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return list;
    }
    
    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    public List<SignatureInfo> getSignatureInfo(InputStream inputStream) {
        List<SignatureInfo> list = new ArrayList<SignatureInfo>();
        try {
            PdfReader reader = new PdfReader(inputStream);
            AcroFields fields = reader.getAcroFields();
            ArrayList<String> names = fields.getSignatureNames();
            for (String name : names) {
                PdfPKCS7 pkcs7 = fields.verifySignature(name);
                list.add(new SignatureInfo(pkcs7));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return list;
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    @Override
    public Boolean verifySignature(String filePath) throws SignatureException {
        return verifySignature(filePath, getKeyStore());
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    public Boolean verifySignature(InputStream inputStream) throws SignatureException {
        return verifySignature(inputStream, getKeyStore());
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    @Override
    public Boolean verifySignature(String filePath, KeyStore ks) throws SignatureException {
        Boolean verified = false;
        try {
            InputStream is = new FileInputStream(filePath);
            verified = verifySignature(is, ks);
            is.close();
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        return verified;
    }
    
    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Verifier#verifySignature()
     */
    public Boolean verifySignature(InputStream inputStream, KeyStore ks) throws SignatureException {
        Boolean verified = false;
        try {
            PdfReader reader = new PdfReader(inputStream);
            AcroFields fields = reader.getAcroFields();
            ArrayList<String> names = fields.getSignatureNames();
            for (String name : names) {
                PdfPKCS7 pkcs7 = fields.verifySignature(name);
                if (pkcs7.verify()) {
                    Certificate[] certs = pkcs7.getSignCertificateChain();
                    Calendar cal = pkcs7.getSignDate();
                    List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
                    if (errors.size() == 0) {
                        X509Certificate signCert = (X509Certificate)certs[0];
                        X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate)certs[1] : null);
                        verified = checkSignatureRevocation(pkcs7, signCert, issuerCert, cal.getTime()) && checkSignatureRevocation(pkcs7, signCert, issuerCert, new Date());
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        return verified;
    }

    /**
     * Check signature revocation
     */
    protected Boolean checkSignatureRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date) throws GeneralSecurityException, IOException {
        List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
        if (pkcs7.getOcsp() != null) {
            ocsps.add(pkcs7.getOcsp());
        }
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
        List<VerificationOK> verification = ocspVerifier.verify(signCert, issuerCert, date);
        if (verification.size() == 0) {
            List<X509CRL> crls = new ArrayList<X509CRL>();
            if (pkcs7.getCRLs() != null) {
                for (CRL crl : pkcs7.getCRLs()) {
                    crls.add((X509CRL)crl);
                }
            }
            CRLVerifier crlVerifier = new CRLVerifier(null, crls);
            verification.addAll(crlVerifier.verify(signCert, issuerCert, date));
        }
        return verification.size() > 0;
    }
}
