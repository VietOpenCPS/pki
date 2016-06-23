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
    }
    sign: function(options) {
        if (window.hwcrypto) {
            this.options = this.options || options;
            if (this.options.beforeSign) {
                this.options.beforeSign(this, this.options.hash);
            }

            window.hwcrypto.getCertificate({lang: 'en'}).then(function(certificate) {
                window.hwcrypto.sign(certificate, {type: this.options.hash.type, hex: this.options.hash.hex}, {lang: 'en'}).then(function(signature) {
                    this.options.signature.certificate = certificate.hex;
                    this.options.signature.value = signature.hex;
                    if (this.options.afterSign) {
                        this.options.afterSign(this, this.options.signature);
                    }
                }, function(err) {
                    if (this.options.onError) {
                        this.options.onError(this, err);
                    }
                    console.log("sign() failed: " + err);
                });
            }, function(err) {
                if (this.options.onError) {
                    this.options.onError(this, err);
                }
                console.log("getCertificate() failed: " + err);
            });
        }
        return this;
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
