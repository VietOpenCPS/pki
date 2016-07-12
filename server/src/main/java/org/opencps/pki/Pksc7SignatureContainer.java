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

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.PdfPKCS7;

/**
 * Produces a pkcs7 signed data from client. Useful for deferred signing
 * 
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class Pksc7SignatureContainer implements ExternalSignatureContainer {

    private byte[] encodedPkcs7;

    private PdfPkcs7Signer signer;

    /**
     * Constructor
     */
    public Pksc7SignatureContainer(PdfPkcs7Signer signer, byte[] encodedPkcs7) {
        this.signer = signer;
        this.encodedPkcs7 = encodedPkcs7;
    }

    @Override
    public void modifySigningDictionary(PdfDictionary pd) {
    }

    @Override
    public byte[] sign(InputStream is) throws GeneralSecurityException {
        X509Certificate cert = signer.getCertificate();
        PdfPKCS7 sgn = new PdfPKCS7(encodedPkcs7, PdfName.ADBE_PKCS7_DETACHED, null);
        X509Certificate signingCert = sgn.getSigningCertificate();

        if (!signingCert.getSerialNumber().equals(cert.getSerialNumber())) {
            throw new SignatureException("Encoded pkcs7 is invalid. The certificate from signer not equal pkcs7's certificate");
        }

        return encodedPkcs7;
    }

}
