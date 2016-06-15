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

/**
 * Hash algorithm enum
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public enum HashAlgorithm {
	MD2("MD2"),
	MD5("MD5"),
	SHA1("SHA1"),
	SHA224("SHA224"),
	SHA256("SHA256"),
	SHA384("SHA384"),
	SHA512("SHA512"),
	RIPEMD128("RIPEMD128"),
	RIPEMD160("RIPEMD160"),
	RIPEMD256("RIPEMD256"),
	GOST3411("GOST3411");

	private final String name;

    private HashAlgorithm(String name) {
        this.name = name;
    }

    public String toString() {
    	return name;
    }
}
