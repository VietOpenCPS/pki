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

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;

import com.itextpdf.text.DocumentException;
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

    protected void createEmptySignature(String dest, String fieldName) throws DocumentException, IOException, GeneralSecurityException {
        // todo calculate size of image is it set
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, fieldName);
        if (cert != null) {
            appearance.setCertificate(cert);
        }
        ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        MakeSignature.signExternalContainer(appearance, external, 8192);
    }
}
