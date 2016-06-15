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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Calendar;

import javax.imageio.ImageIO;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalBlankSignatureContainer;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfSigner implements ServerSigner {

    private Certificate cert;

    private SignatureImage signatureImage;

    private String signatureFieldName;
    
    private String originFilePath;
    
    private String tempFilePath;

    private String signedFilePath;
    
    private HashAlgorithm hashAlgorithm;

    /**
     * Constructor
     *
     * @param filePath The path of pdf document
     */
    public PdfSigner(String filePath) {
        originFilePath = filePath;
        tempFilePath = Helper.stripFileExtension(filePath) + ".temp.pdf";
        signedFilePath = Helper.stripFileExtension(filePath) + ".signed.pdf";
        hashAlgorithm = HashAlgorithm.SHA256;
    }

    /**
     * Constructor
     *
     * @param filePath The path of pdf document
     * @param cert The certificate of user
     */
    public PdfSigner(String filePath, Certificate cert) {
        originFilePath = filePath;
        tempFilePath = Helper.stripFileExtension(filePath) + ".temp.pdf";
        signedFilePath = Helper.stripFileExtension(filePath) + ".signed.pdf";
        hashAlgorithm = HashAlgorithm.SHA256;
        this.cert= cert;
    }

    @Override
    public Certificate readCertificate(byte[] cert) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Boolean validateCertificate(Certificate cert) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Get hash algorithm
     */
    @Override
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Set hash algorithm
     * @param hashAlgorithm
     */
    public PdfSigner setHashAlgorithm(HashAlgorithm hashAlgorithm) {
    	this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    @Override
    public byte[] computeHash() {
        byte hash[] = null;
        try {
            PdfReader reader = new PdfReader(this.originFilePath);
            FileOutputStream os = new FileOutputStream(tempFilePath);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            signatureFieldName = appearance.getNewSigName();
            if (cert != null) {
                appearance.setCertificate(cert);
            }
            appearance.setSignDate(Calendar.getInstance());
            appearance.setLocation("OpenCPS PKI");
            appearance.setContact("OpenCPS PKI");
            if (signatureImage != null) {
                appearance.setSignatureGraphic(signatureImage.getImage());
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
                
                int signatureImageWidth = signatureImage.getBufferedImage().getWidth();
                int signatureImageHeight = signatureImage.getBufferedImage().getHeight();
                float llx = 36.0f;
                float lly = 748.0f;
                float urx = llx + signatureImageWidth;
                float ury = lly + signatureImageHeight;
                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, signatureFieldName);
            }
            else {
                appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, signatureFieldName);
            }
            ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.signExternalContainer(appearance, external, 8192);
            
            ExternalDigest digest = new BouncyCastleDigest();
            hash = DigestAlgorithms.digest(appearance.getRangeStream(), digest.getMessageDigest(hashAlgorithm.toString()));
            reader.close();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return hash;
    }

    @Override
    public Boolean sign(byte[] signature) {
        return sign(signature, tempFilePath);
    }

    @Override
    public Boolean sign(byte[] signature, String filePath) {
        Boolean signed = false;
        File file = new File(filePath);
        if (file.exists()) {
            try {
                FileOutputStream os = new FileOutputStream(signedFilePath);
                PdfReader reader = new PdfReader(filePath);
                if (reader.isEncrypted()) {
                    signed = false;
                }
                ExternalSignatureContainer container = new ClientSignatureContainer(signature);
                MakeSignature.signDeferred(reader, signatureFieldName, os, container);
                reader.close();
                os.close();
                signed = true;
            } catch (IOException e) {
                signed = false;
            } catch (DocumentException e) {
                signed = false;
            } catch (GeneralSecurityException e) {
                signed = false;
            }
        }
        return signed;
    }
    
    public void setSignatureGraphic(String imagePath) {
        signatureImage = new SignatureImage(imagePath);
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
    
    class SignatureImage {
        private BufferedImage bufferedImage;

        private Image image;

        public SignatureImage(String imagePath) {
            try {
                image = Image.getInstance(imagePath);
                InputStream is = new FileInputStream(new File(imagePath));
                bufferedImage = ImageIO.read(is);
            }
            catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
            catch (BadElementException e) {
                e.printStackTrace();
            }
        }
        
        public BufferedImage getBufferedImage() {
            return bufferedImage;
        }
        
        public Image getImage() {
            return image;
        }
    }
}
