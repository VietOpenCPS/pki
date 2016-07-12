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

import com.itextpdf.text.pdf.security.PdfPKCS7;

/**
 * Signature information of pdf document
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSignatureInfo extends SignatureInfo {

    private PdfPKCS7 pkcs7;

	/**
	 * Constructor
	 */
	public PdfSignatureInfo(PdfPKCS7 pkcs7) {
        this.pkcs7 = pkcs7;
        cert = pkcs7.getSigningCertificate();
        certInfo = new CertificateInfo(cert);
        signDate = pkcs7.getSignDate();
        timeStamp = pkcs7.getTimeStampDate();
        digestAlgorithm = pkcs7.getDigestAlgorithm();
        hashAlgorithm = pkcs7.getHashAlgorithm();
    }

    /**
     * Get Pdf PKCS#7
     */
    public PdfPKCS7 getPdfPKCS7() {
        return pkcs7;
    }

    /**
     * Check signature is verified
     */
	@Override
	public Boolean isVerify() throws GeneralSecurityException {
		return pkcs7.verify();
	}
}
