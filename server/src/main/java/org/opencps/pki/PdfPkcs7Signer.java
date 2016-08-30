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
import java.io.OutputStream;
import java.security.SignatureException;
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
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

/**
 * Signer for pdf document using encoded pkcs7
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfPkcs7Signer extends BaseSigner {
    /**
     * Signature image
     */
    private SignatureImage signatureImage;

    /**
     * signature field name
     */
    private String signatureFieldName;
    
    /**
     * Sign date
     */
    private Calendar signDate;

    /**
     * Signature is visible
     */
    private Boolean isVisible;
    
    /**
     * External digest
     */
    private ExternalDigest digest;

    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert) {
        this(
                filePath,
                cert,
                Helper.stripFileExtension(filePath) + ".temp.pdf",
                Helper.stripFileExtension(filePath) + ".signed.pdf",
                true
            );
    }
    
    /**
     * Constructor
     */
    public PdfPkcs7Signer(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath, boolean isVisible) {
        super(filePath, cert, tempFilePath, signedFilePath);
        this.isVisible = isVisible;
        signDate = Calendar.getInstance();
        digest = new BouncyCastleDigest();
    }

	@Override
	public byte[] computeHash() throws SignatureException {
        float llx = 36.0f;
        float lly = 48.0f;
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
    public byte[] computeHash(float llx, float lly, float urx, float ury) throws SignatureException {
        return computeDigest(llx, lly, urx, ury);
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

	@Override
	public Boolean sign(byte[] signature) throws SignatureException {
        return sign(signature, getTempFilePath());
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
    public PdfPkcs7Signer setSignDate(Calendar signDate) {
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
    public PdfPkcs7Signer setIsVisible(Boolean isVisible) {
        this.isVisible = isVisible;
        return this;
    }

    /**
     * Set signature graphic
     */
    public PdfPkcs7Signer setSignatureGraphic(String imagePath) {
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
     * Get signature field name pdf document
     */
    public String getSignatureFieldName() {
        return signatureFieldName;
    }

    public PdfPkcs7Signer setSignatureFieldName(String fieldName) {
        signatureFieldName = fieldName;
        return this;
    }
    
    /**
     * Get external digest
     */
    public ExternalDigest getExternalDigest() {
        return digest;
    }

    /**
     * Compute digest hash
     */
    protected byte[] computeDigest(float llx, float lly, float urx, float ury) throws SignatureException {
        byte digestHash[] = null;
        int contentEstimated = 8192;
        try {
            PdfReader reader = new PdfReader(getOriginFilePath());
            FileOutputStream os = new FileOutputStream(getTempFilePath());
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            signatureFieldName = appearance.getNewSigName();
            TSAClient tsaClient = null;
            appearance.setCertificate(getCertificate());
            String tsaUrl = CertificateUtil.getTSAURL(getCertificate());
            if (tsaUrl != null) {
                tsaClient = new TSAClientBouncyCastle(tsaUrl);
            }
            if (tsaClient != null) {
                LtvTimestamp.timestamp(appearance, tsaClient, signatureFieldName);
                contentEstimated += 4096;
            }

            appearance.setSignDate(signDate);
            CertificateInfo certInfo = new CertificateInfo(getCertificate());
            appearance.setLocation(certInfo.getOrganizationUnit());
            appearance.setReason("Document is signed by " + certInfo.getCommonName());
            appearance.setContact(certInfo.getCommonName());
            if (!isVisible) {
                appearance.setVisibleSignature(new Rectangle(0, 0, 0, 0), 1, signatureFieldName);
            }
            else {
                if (signatureImage != null) {
                    appearance.setSignatureGraphic(signatureImage.getImage());
                    appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
                }
                else {
                    appearance.setLayer2Text(certInfo.getCommonName());
                }
                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, signatureFieldName);
            }

            ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.signExternalContainer(appearance, external, contentEstimated);
            
            digestHash = DigestAlgorithms.digest(appearance.getRangeStream(), digest.getMessageDigest(getHashAlgorithm().toString()));

            reader.close();
            os.close();
        } catch (Exception e) {
            throw new SignatureException(e.getMessage(), e);
        }
        return digestHash;
    }
    
    /**
     * Sign document with external signature container
     */
    protected Boolean signExternal(ExternalSignatureContainer container, String filePath) throws SignatureException {
        if (signatureFieldName == null || signatureFieldName.length() == 0) {
            throw new SignatureException("You must set signature field name before sign the document");
        }
        Boolean signed = false;
        try {
            OutputStream os = new FileOutputStream(getSignedFilePath());
            PdfReader reader = new PdfReader(filePath);
            if (!reader.isEncrypted()) {
                MakeSignature.signDeferred(reader, signatureFieldName, os, container);
                reader.close();
                os.close();
                signed = true;
            }
        } catch (Exception e) {
            throw new SignatureException(e.getMessage(), e);
        }
        return signed;
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
                throw new RuntimeException(e.getMessage(), e);
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
