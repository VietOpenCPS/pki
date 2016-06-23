/*!
 * OpenCPS PKI; version: 1.0.0
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

$.signer = $.signer || {};
$.extend($.signer, {
    options: {
        hash: {
            type: 'sha512',
            hex: false,
            value: false
        },
        signature: {
            certificate: false,
            value: false
        },
        document: false,
        beforeSign: false,
        afterSign: false,
        onError: false
    },
    sign: function(options) {
        var signer = this;
        if (window.hwcrypto) {
            $.extend(signer.options, options);
            if (signer.options.beforeSign) {
                signer.options.beforeSign(signer, signer.options.hash);
            }

            window.hwcrypto.getCertificate({lang: 'en'}).then(function(certificate) {
                window.hwcrypto.sign(certificate, {type: signer.options.hash.type, hex: signer.options.hash.hex}, {lang: 'en'}).then(function(signature) {
                    signer.options.signature.certificate = certificate.hex;
                    signer.options.signature.value = signature.hex;
                    if (signer.options.afterSign) {
                        signer.options.afterSign(signer, signer.options.signature);
                    }
                }, function(err) {
                    if (signer.options.onError) {
                        signer.options.onError(signer, err);
                    }
                    console.log("sign() failed: " + err);
                });
            }, function(err) {
                console.log("getCertificate() failed: " + err);
                if (signer.options.onError) {
                    signer.options.onError(signer, err);
                }
            });
        }
        return signer;
    }
});

$.extend({
    getCertificate: function(){
        var cert = null;
        if (window.hwcrypto) {
            window.hwcrypto.getCertificate({lang: 'en'}).then(function(response) {
                cert = response.hex;
            }, function(err) {
                console.log("getCertificate() failed: " + err);
            });
        }
        return cert;
    },
    sign: function(options) {
        return $.signer.sign(options);
    }
});

})(jQuery);
