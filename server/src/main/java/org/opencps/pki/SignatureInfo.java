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

import java.security.GeneralSecurityException;
import java.util.Calendar;

/**
 * Signature information of document
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
abstract public class SignatureInfo {

	protected CertificateInfo certInfo;

    protected Calendar signDate;

    protected Calendar timeStamp;

    /**
     * Get certificate information
     */
    public CertificateInfo getCertificateInfo() {
        return certInfo;
    }

    /**
     * Get signature date
     */
    public Calendar getSignDate() {
        return signDate;
    }

    /**
     * Get signature time stamp
     */
    public Calendar getTimeStamp() {
        return timeStamp;
    }

    /**
     * Check signature is verified
     */
    abstract public Boolean isVerify() throws GeneralSecurityException;

}
