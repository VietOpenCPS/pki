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

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.imageio.ImageIO;

import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalBlankSignatureContainer;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.LtvTimestamp;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

/**
 * Signer for pdf document
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSigner extends BaseSigner {

    /**
     * X509 certificate
     */
    private X509Certificate cert;

    /**
     * Signature image
     */
    private SignatureImage signatureImage;

    /**
     * signature field name
     */
    private String signatureFieldName;
    
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
     * Sign date
     */
    private Calendar signDate;

    /**
     * Signature is visible
     */
    private Boolean isVisible;

    /**
     * Constructor
     *
     * @param filePath The path of pdf document
     * @param cert The certificate of user
     */
    public PdfSigner(String filePath, X509Certificate cert) {
        super();
        originFilePath = filePath;
        tempFilePath = Helper.stripFileExtension(filePath) + ".temp.pdf";
        signedFilePath = Helper.stripFileExtension(filePath) + ".signed.pdf";
        isVisible = true;
        signDate = Calendar.getInstance();
        this.cert= cert;
    }

    /**
     * Constructor
     *
     * @param filePath The path of pdf document
     * @param cert The certificate of user
     * @param tempFilePath Temporary Pdf document file path after generate hash key
     * @param signedFilePath Signed Pdf document file path
     * @param isVisible Signature is visible
     */
    public PdfSigner(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath, boolean isVisible) {
        super();
        originFilePath = filePath;
        this.tempFilePath = tempFilePath;
        this.signedFilePath = signedFilePath;
        this.isVisible = isVisible;
        signDate = Calendar.getInstance();
        this.cert= cert;
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#computeHash()
     */
    @Override
    public byte[] computeHash() {
        float llx = 36.0f;
        float lly = 48.0f;
        if (signatureImage != null) {
            int signatureImageWidth = signatureImage.getBufferedImage().getWidth();
            int signatureImageHeight = signatureImage.getBufferedImage().getHeight();
            float urx = llx + signatureImageWidth;
            float ury = lly + signatureImageHeight;
            return computeHash(llx, lly, urx, ury);
        }
        else {
            return computeHash(llx, lly, 144, 80);
        }
    }

    /**
     * Compute hash key with corner coordinates of rectangle
     *
     * @param llx lower left x
     * @param lly lower left y
     * @param urx upper right x
     * @param ury upper right y
     */
    public byte[] computeHash(float llx, float lly, float urx, float ury) {
        byte hash[] = null;
        int contentEstimated = 8192;
        try {
            PdfReader reader = new PdfReader(this.originFilePath);
            FileOutputStream os = new FileOutputStream(tempFilePath);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            signatureFieldName = appearance.getNewSigName();
            TSAClient tsaClient = null;
            appearance.setCertificate(cert);
            String tsaUrl = CertificateUtil.getTSAURL(cert);
            if (tsaUrl != null) {
                tsaClient = new TSAClientBouncyCastle(tsaUrl);
            }
            if (tsaClient != null) {
                LtvTimestamp.timestamp(appearance, tsaClient, signatureFieldName);
                contentEstimated += 4096;
            }

            appearance.setSignDate(signDate);
            appearance.setLocation("OpenCPS PKI");
            appearance.setContact("OpenCPS PKI");
            if (!isVisible) {
                appearance.setVisibleSignature(new Rectangle(0, 0, 0, 0), 1, signatureFieldName);
            }
            else {
                if (signatureImage != null) {
                    appearance.setSignatureGraphic(signatureImage.getImage());
                    appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
                    appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, signatureFieldName);
                }
                else {
                    if (cert != null) {
                        CertificateInfo certInfo = new CertificateInfo(cert);
                        appearance.setLayer2Text(certInfo.getCommonName());
                    }
                    appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, signatureFieldName);
                }
            }

            ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.signExternalContainer(appearance, external, contentEstimated);
            
            ExternalDigest digest = new BouncyCastleDigest();
            byte[] digestHash = DigestAlgorithms.digest(appearance.getRangeStream(), digest.getMessageDigest(getHashAlgorithm().toString()));
            PdfPKCS7 sgn = new PdfPKCS7(null, new Certificate[] { cert }, getHashAlgorithm().toString(), null, digest, false);
            hash = sgn.getAuthenticatedAttributeBytes(digestHash, null, null, CryptoStandard.CMS);
            reader.close();
            os.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return hash;
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature) {
        return sign(signature, tempFilePath);
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) {
        if (signatureFieldName == null || signatureFieldName.length() == 0) {
            throw new RuntimeException("You must set signature field name before sign the document");
        }
        Boolean signed = false;
        try {
            FileOutputStream os = new FileOutputStream(signedFilePath);
            PdfReader reader = new PdfReader(filePath);
            if (!reader.isEncrypted()) {
                ExternalSignatureContainer container = new ClientSignatureContainer(this, signature);
                MakeSignature.signDeferred(reader, signatureFieldName, os, container);
                reader.close();
                os.close();
                signed = true;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return signed;
    }

    /**
     * Get certificate 
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /**
     * Get sign date
     */
    public Calendar getSignDate() {
        return signDate;
    }

    /**
     * Set sign date
     */
    public PdfSigner setSignDate(Calendar signDate) {
        this.signDate = signDate;
        return this;
    }

    /**
     * Get signature is visible
     */
    public Boolean getIsVisible() {
        return isVisible;
    }

    /**
     * Set signature is visible
     */
    public PdfSigner setIsVisible(Boolean isVisible) {
        this.isVisible = isVisible;
        return this;
    }

    /**
     * Set signature graphic
     */
    public PdfSigner setSignatureGraphic(String imagePath) {
        signatureImage = new SignatureImage(imagePath);
        return this;
    }
    
    /**
     * Get signature graphic
     */
    public SignatureImage getSignatureGraphic() {
        return signatureImage;
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

    /**
     * Get signature field name pdf document
     */
    public String getSignatureFieldName() {
        return signatureFieldName;
    }

    public PdfSigner setSignatureFieldName(String fieldName) {
        signatureFieldName = fieldName;
        return this;
    }
    
    /**
     * Signature image class
     */
    class SignatureImage {
        private BufferedImage bufferedImage;

        private Image image;

        /**
         * Constructor
         */
        public SignatureImage(String imagePath) {
            try {
                image = Image.getInstance(imagePath);
                InputStream is = new FileInputStream(new File(imagePath));
                bufferedImage = ImageIO.read(is);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        
        /**
         * Get buffered image object
         */
        public BufferedImage getBufferedImage() {
            return bufferedImage;
        }
        
        /**
         * Get image object
         */
        public Image getImage() {
            return image;
        }
    }
}
