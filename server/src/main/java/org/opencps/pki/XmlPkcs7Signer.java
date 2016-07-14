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
import java.util.Collection;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import com.itextpdf.text.pdf.codec.Base64;

/**
 * Signer for xml document by parsing encoded pkcs7
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class XmlPkcs7Signer extends XmlSigner {

    /**
     * Constructor
     */
    public XmlPkcs7Signer(String filePath, X509Certificate cert) {
        super(filePath, cert);
    }
    
    /**
     * Constructor
     */
    public XmlPkcs7Signer(String filePath, X509Certificate cert, String signedFilePath) {
        super(filePath, cert, signedFilePath);
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        return signPkcs7(signature, filePath);
    }

    /**
     * Sign with encoded pkcs7
     */
    protected Boolean signPkcs7(byte[] encodedPkcs7, String filePath) throws SignatureException {
        try {
            CMSSignedData signedData = new CMSSignedData(encodedPkcs7);
            Collection<SignerInformation> ss = signedData.getSignerInfos().getSigners();
            SignerInformation si = (SignerInformation) ss.iterator().next();
            byte[] signature = si.getSignature();
            System.out.println("Signature value: " + Base64.encodeBytes(signature));
            System.out.println("Signature length: " + signature.length);
        } catch (CMSException e) {
            throw new SignatureException(e.getMessage(), e);
        }
        return null;
    }

}
