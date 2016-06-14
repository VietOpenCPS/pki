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
import com.itextpdf.text.pdf.security.ExternalBlankSignatureContainer;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;

/**
 * @author nguyennv
 *
 */
public class PdfSigner implements ServerSigner {

    private Certificate cert;
    private PdfReader reader;
    private SignatureImage signatureImage;
    private String signatureFieldName;

    /**
     * 
     */
    public PdfSigner(String filePath) {
        try {
            reader = new PdfReader(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PdfSigner(Certificate cert, String filePath) {
        try {
            reader = new PdfReader(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.cert= cert;
    }

    @Override
    public byte[] computeHash() {
        return new byte[0];
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

    @Override
    public String getHashAlgorithm() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String sign(byte[] signature) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String sign(byte[] signature, String filePath) {
        // TODO Auto-generated method stub
        return null;
    }
    
    public void setSignatureGraphic(String imagePath) {
        signatureImage = new SignatureImage(imagePath);
    }

    protected void createEmptySignature(String dest) throws DocumentException, IOException, GeneralSecurityException {
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        signatureFieldName = appearance.getNewSigName();

        if (cert != null) {
            appearance.setCertificate(cert);
        }
        appearance.setSignDate(Calendar.getInstance());
        appearance.setLocation("OpenCPS");
        appearance.setContact("OpenCPS");
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
