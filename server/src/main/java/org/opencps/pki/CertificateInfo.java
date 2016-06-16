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

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * Certificate information of user
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class CertificateInfo {

    private X509Certificate cert;

    private X500Name x500name;

    /**
     * Constructor
     * @throws CertificateEncodingException 
     */
    public CertificateInfo(X509Certificate cert) throws CertificateEncodingException {
        this.cert = cert;
        x500name = new JcaX509CertificateHolder(this.cert).getSubject();
    }

    /**
     * Get common name of certificate
     */
    public String getCommonName() {
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    /**
     * Get organization unit of certificate
     */
    public String getOrganizationUnit() {
        RDN cn = x500name.getRDNs(BCStyle.OU)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    /**
     * Get organization of certificate
     */
    public String getOrganization() {
        RDN cn = x500name.getRDNs(BCStyle.O)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    /**
     * Get email of certificate
     */
    public String getEmail() {
        RDN cn = x500name.getRDNs(BCStyle.E)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
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
