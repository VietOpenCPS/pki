/*!
 * OpenCPS PKI; version: 1.0.0
 * https://github.com/VietOpenCPS/pki
 * Copyright (c) 2016 OpenCPS Community;
 * Licensed under the AGPL V3+.
 * https://www.gnu.org/licenses/agpl-3.0.html
 */
(function($) {
"use strict";
var digidoc_mime = 'application/x-digidoc';
var bcy_mime = 'application/x-cryptolib05plugin';

function hasPlugin(mime) {
    if(navigator.mimeTypes && mime in navigator.mimeTypes) {
        return true;
    }
    return false;
}

function loadSignaturePlugin(mime) {
    var element = mime.replace('/', '').replace('-', '');
    if(document.getElementById(element)) {
        return document.getElementById(element);
    }
    var objectTag = '<object id="' + element + '" type="' + mime + '" style="width: 1px; height: 1px; position: absolute; visibility: hidden;"></object>';
    var div = document.createElement("div");
    div.setAttribute("id", 'plugin' + element);
    document.body.appendChild(div);
    document.getElementById('plugin' + element).innerHTML = objectTag;
    return document.getElementById(element);
}

function signBcy(signer) {
    var plugin = loadSignaturePlugin(bcy_mime);
    if (plugin.valid) {
        var code = plugin.Sign(hexToBase64(signer.options.hash.hex));
        if (code === 0 || code === 7) {
            signer.options.signature.value = plugin.Signature;
            if (signer.options.afterSign) {
                signer.options.afterSign(signer, signer.options.signature);
            }
        }
        else {
            if (signer.options.onError) {
                console.log("sign() failed: " + plugin.ErrorMessage);
                signer.options.onError(signer, 'sign() failed: ' + plugin.ErrorMessage);
            }
        }
    }
}

if (window.hwcrypto) {
    window.hwcrypto.use('auto');
    window.hwcrypto.debug().then(function(response) {
        console.log('Debug: ' + response);
    }, function(err) {
        console.log('debug() failed: ' + err);
        return;
    });
}

function signHwCrypto(signer) {
    window.hwcrypto.getCertificate({lang: 'en'}).then(function(certificate) {
        window.hwcrypto.sign(certificate, {type: signer.options.hash.type, hex: signer.options.hash.hex}, {lang: 'en'}).then(function(signature) {
            signer.options.signature.certificate = hexToBase64(certificate.hex);
            signer.options.signature.value = hexToBase64(signature.hex);
            if (signer.options.afterSign) {
                signer.options.afterSign(signer, signer.options.signature);
            }
        }, function(err) {
            console.log("sign() failed: " + err);
            if (signer.options.onError) {
                signer.options.onError(signer, err);
            }
        });
    }, function(err) {
        console.log("getCertificate() failed: " + err);
        if (signer.options.onError) {
            signer.options.onError(signer, err);
        }
    });
}

$.signer = $.signer || {};
$.extend($.signer, {
    options: {
        hash: {
            type: 'sha256',
            hex: false,
            value: false
        },
        signature: {
            certificate: false,
            value: false
        },
        backend: 'hwcrypto',
        document: false,
        beforeSign: false,
        afterSign: false,
        onError: false
    },
    sign: function(options) {
        var signer = this;
        $.extend(signer.options, options);
        if (signer.options.beforeSign) {
            signer.options.beforeSign(signer, signer.options.hash);
        }

        if (window.hwcrypto && signer.options.backend === 'hwcrypto') {
            signHwCrypto(signer);
        }
        else if (hasPlugin(bcy_mime) && signer.options.backend === 'bcy') {
            signBcy(signer);
        }
        return signer;
    }
});

$.extend({
    getCertificate: function(){
        var cert = null;
        if (window.hwcrypto) {
            window.hwcrypto.getCertificate({lang: 'en'}).then(function(response) {
                cert = hexToBase64(response.hex);
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
