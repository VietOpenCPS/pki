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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

/**
 * Produces a signed data from client. Useful for deferred signing
 * 
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class ClientSignatureContainer implements ExternalSignatureContainer {

    private byte[] signedData;
    
    private PdfSigner signer;

    /**
     * Constructor
     */
    public ClientSignatureContainer(PdfSigner signer, byte[] data) {
    	this.signer = signer;
        signedData = data;
    }

    @Override
    public void modifySigningDictionary(PdfDictionary pd) {
    }

    @Override
    public byte[] sign(InputStream is) throws GeneralSecurityException {
    	X509Certificate cert = signer.getCertificate();
		BouncyCastleDigest digest = new BouncyCastleDigest();
		PdfPKCS7 sgn = new PdfPKCS7(null, new Certificate[] { cert }, signer.getHashAlgorithm().toString(), null, digest, false);
		sgn.setExternalDigest(signedData, null, cert.getPublicKey().getAlgorithm());

		byte[] hash = null;
		try {
			hash = DigestAlgorithms.digest(is, digest.getMessageDigest(signer.getHashAlgorithm().toString()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		TSAClient tsaClient = null;
        String tsaUrl = CertificateUtil.getTSAURL(cert);
        if (tsaUrl != null) {
            tsaClient = new TSAClientBouncyCastle(tsaUrl);
        }

        return sgn.getEncodedPKCS7(hash, tsaClient, null, null, CryptoStandard.CMS);
    }

}
