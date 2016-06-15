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
 * This class defines various static utility functions that are in use
 * throughout the OpenCPS PKI system.
 *
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class Helper {

	/**
	 * Strip file extension
	 * @param filePath
	 */
    public static String stripFileExtension(String filePath) {
        if (filePath == null) {
            return null;
        }
        int n = filePath.lastIndexOf(".");
        if (n == -1) {
            return filePath;
        }
        return filePath.substring(0, n);
    }

}
