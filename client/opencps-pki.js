/*!
 * OpenCPS PKI; version: 0.0.1
 * https://github.com/VietOpenCPS/pki
 * Copyright (c) 2016 OpenCPS Community;
 * Licensed under the AGPL V3+.
 * https://www.gnu.org/licenses/agpl-3.0.html
 */
(function($) {
"use strict";

if (window.hwcrypto) {
    window.hwcrypto.use('auto');
    window.hwcrypto.debug().then(function(response) {
      console.log('Debug: ' + response);
    }, function(err) {
      console.log('debug() failed: ' + err);
      return;
    });
}

$.extend({
    getCertificate: function(){
        var cert = null;
        if (window.hwcrypto) {
            window.hwcrypto.getCertificate({lang: 'en'}).then(function(response) {
                cert = hexToPem(response.hex);
            }, function(err) {
              console.log("getCertificate() failed: " + err);
            });
        }
        return cert;
    },
    sign: function(options) {
      window.hwcrypto.sign(cert, {type: 'SHA-256', hex: hash}, {lang: 'en'}).then(function(response) {
        console.log("Generated signature:\n" + response.hex.match(/.{1,64}/g).join("\n"));
      }, function(err) {
        console.log("sign() failed: " + err);
      });
    }
});

})(jQuery);
