/**
 * 
 */
package org.opencps.pki;

import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * @author nguyennv
 *
 */
public class PdfPkcs7Signer extends PdfSigner {

    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert) {
        super(filePath, cert);
    }
    
    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath, boolean isVisible) {
        super(filePath, cert, tempFilePath, signedFilePath, isVisible);
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#computeHash()
     */
    @Override
    public byte[] computeHash() throws SignatureException {
        float llx = 36.0f;
        float lly = 48.0f;
        SignatureImage signatureImage = getSignatureGraphic();
        if (signatureImage != null) {
            int signatureImageWidth = signatureImage.getBufferedImage().getWidth();
            int signatureImageHeight = signatureImage.getBufferedImage().getHeight();
            float urx = llx + signatureImageWidth;
            float ury = lly + signatureImageHeight;
            return computeDigest(llx, lly, urx, ury);
        }
        else {
            return computeDigest(llx, lly, 144, 80);
        }
    }

    /**
     * Compute hash key with corner coordinates of rectangle
     */
    @Override
    public byte[] computeHash(float llx, float lly, float urx, float ury) throws SignatureException {
        return computeDigest(llx, lly, urx, ury);
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature) throws SignatureException {
        return sign(signature, getTempFilePath());
    }

    /**
     * (non-Javadoc)
     * @throws SignatureException 
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        return signExternal(new Pksc7SignatureContainer(this, signature), filePath);
    }
}
