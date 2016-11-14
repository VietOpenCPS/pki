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
    final private static char[] hexArray = "0123456789ABCDEF".toCharArray();

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

    /**
     * Converts an array of bytes into an hexadecimal string
     * @attribution : http://stackoverflow.com/a/9855338
     * @original_question: http://stackoverflow.com/questions/9655181
     * @author: maybeWeCouldStealAVan
     * @author_detail: http://stackoverflow.com/users/1284661
     */
    public static String binToHex(byte[] data) {
        char[] hexChars = new char[data.length * 2];
        for ( int j = 0; j < data.length; j++ ) {
            int v = data[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
