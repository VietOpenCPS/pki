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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Certificate information of user
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class CertificateInfo {

    private X509Certificate cert;

    /**
     * Constructor
     * @throws CertificateEncodingException 
     */
    public CertificateInfo(X509Certificate cert) throws CertificateEncodingException {
        this.cert = cert;
    }

    /**
     * Get common name of certificate
     */
    public String getCommonName() {
    	return com.itextpdf.text.pdf.security.CertificateInfo.getSubjectFields(cert).getField("CN");
    }

    /**
     * Get organization unit of certificate
     */
    public String getOrganizationUnit() {
    	return com.itextpdf.text.pdf.security.CertificateInfo.getSubjectFields(cert).getField("OU");
    }

    /**
     * Get organization of certificate
     */
    public String getOrganization() {
    	return com.itextpdf.text.pdf.security.CertificateInfo.getSubjectFields(cert).getField("O");
    }

    /**
     * Get email of certificate
     */
    public String getEmail() {
    	return com.itextpdf.text.pdf.security.CertificateInfo.getSubjectFields(cert).getField("E");
    }

    /**
     * Get serial number of certificate
     */
    public String getSerialNumber() {
        return cert.getSerialNumber().toString();
    }
    
    /**
     * Get Issuer distinguished name
     */
    public String getIssuer() {
        return cert.getIssuerDN().toString();
    }
    
    /**
     * Get valid from date
     */
    public Date getValidFrom() {
        return cert.getNotBefore();
    }

    /**
     * Get valid to date
     */
    public Date getValidTo() {
        return cert.getNotAfter();
    }

    /**
     * Get certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

}
