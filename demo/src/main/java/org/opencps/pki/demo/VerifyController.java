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
package org.opencps.pki.demo;

import org.opencps.pki.PdfVerifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller class for verify signed pdf document
 * 
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
@Controller
public class VerifyController {

    private PdfVerifier verifier;
    
    public VerifyController() {
        
    }
    
    @RequestMapping("/verify")
    public String verify(Model model) {
        return "verify";
    }

}
