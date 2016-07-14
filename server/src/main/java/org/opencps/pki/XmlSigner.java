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

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;

/**
 * Signer for xml document
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class XmlSigner extends BaseSigner {

    private Document document;

    private XMLSignatureFactory factory;

    /**
     * Constructor
     */
    public XmlSigner(String filePath, X509Certificate cert) {
        this(
            filePath,
            cert,
            Helper.stripFileExtension(filePath) + ".temp.xml",
            Helper.stripFileExtension(filePath) + ".signed.xml"
        );
    }

    /**
     * Constructor
     */
    public XmlSigner(String filePath, X509Certificate cert, String tempFilePath, String signedFilePath) {
        super(filePath, cert, tempFilePath, signedFilePath);
        factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            document = dbf.newDocumentBuilder().parse(new FileInputStream(getOriginFilePath()));
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#computeHash()
     */
    @Override
    public byte[] computeHash() throws SignatureException {
        try {
            DigestMethod digestMethodSHA1 = factory.newDigestMethod(DigestMethod.SHA1, null);
            List<Transform> transforms = new ArrayList<Transform>();
            transforms.add(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            
            Reference reference = factory.newReference("", digestMethodSHA1, transforms, null, null);
            
            DOMSignedInfo signedInfo = (DOMSignedInfo) factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(reference)
            );
            
            DOMSignContext domSignContext = new DOMSignContext(XmlEmptyKey.getInstance(), document.getDocumentElement());
            
            ByteArrayOutputStream byteRange = new ByteArrayOutputStream();
            
            signedInfo.canonicalize(domSignContext, byteRange);
            return byteRange.toByteArray();
        } catch (Exception e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature) throws SignatureException {
        return sign(signature, getTempFilePath());
    }

    /**
     * (non-Javadoc)
     * @see org.opencps.pki.Signer#sign()
     */
    @Override
    public Boolean sign(byte[] signature, String filePath) throws SignatureException {
        // TODO Auto-generated method stub
        return null;
    }
    
    /**
     * Get xml document
     */
    public Document getDocument() {
        return document;
    }
    
    /**
     * Get xml signature factory
     * @return
     */
    public XMLSignatureFactory getSignatureFactory() {
        return factory;
    }

    private static class XmlEmptyKey implements Key {

        private static final long serialVersionUID = -3168182668957821211L;

        private XmlEmptyKey(){}

        private static XmlEmptyKey instance = new XmlEmptyKey();

        public static XmlEmptyKey getInstance() {
            return instance;
        }

        public String getAlgorithm() {
            return null;
        }

        public String getFormat() {
            return null;
        }

        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
