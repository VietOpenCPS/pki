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

import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import com.itextpdf.text.pdf.security.PdfPKCS7;

/**
 * Signature information of document
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSignatureInfo {

    private PdfPKCS7 pkcs7;

    private CertificateInfo certInfo;

    private Calendar signDate;

    private Calendar timeStamp;

    /**
     * Constructor
     * @throws CertificateEncodingException 
     */
    public PdfSignatureInfo(PdfPKCS7 pkcs7) throws CertificateEncodingException {
        this.pkcs7 = pkcs7;
        X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();
        if (cert != null) {
            certInfo = new CertificateInfo(cert);
            signDate = pkcs7.getSignDate();
            timeStamp = pkcs7.getTimeStampDate();
        }
    }

    /**
     * Get Pdf PKCS#7
     */
    public PdfPKCS7 getPdfPKCS7() {
        return pkcs7;
    }

    /**
     * Get certificate information
     */
    public CertificateInfo getCertificateInfo() {
        return certInfo;
    }

    /**
     * Get signature date
     */
    public Calendar getSignDate() {
        return signDate;
    }

    /**
     * Get signature time stamp
     */
    public Calendar getTimeStamp() {
        return timeStamp;
    }

    /**
     * Check signature is verified
     */
    public Boolean isVerify() throws GeneralSecurityException {
        return pkcs7.verify();
    }

}
