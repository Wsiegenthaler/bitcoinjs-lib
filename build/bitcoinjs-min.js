/**
 * BitcoinJS-lib v0.1.3-default
 * Copyright (c) 2011 BitcoinJS Project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license.
 */

if (typeof Crypto == "undefined" || !Crypto.util) {
    (function() {
        var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var Crypto = window.Crypto = {};
        var util = Crypto.util = {
            rotl: function(n, b) {
                return n << b | n >>> 32 - b;
            },
            rotr: function(n, b) {
                return n << 32 - b | n >>> b;
            },
            endian: function(n) {
                if (n.constructor == Number) {
                    return util.rotl(n, 8) & 16711935 | util.rotl(n, 24) & 4278255360;
                }
                for (var i = 0; i < n.length; i++) n[i] = util.endian(n[i]);
                return n;
            },
            randomBytes: function(n) {
                for (var bytes = []; n > 0; n--) bytes.push(Math.floor(Math.random() * 256));
                return bytes;
            },
            bytesToWords: function(bytes) {
                for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8) words[b >>> 5] |= (bytes[i] & 255) << 24 - b % 32;
                return words;
            },
            wordsToBytes: function(words) {
                for (var bytes = [], b = 0; b < words.length * 32; b += 8) bytes.push(words[b >>> 5] >>> 24 - b % 32 & 255);
                return bytes;
            },
            bytesToHex: function(bytes) {
                for (var hex = [], i = 0; i < bytes.length; i++) {
                    hex.push((bytes[i] >>> 4).toString(16));
                    hex.push((bytes[i] & 15).toString(16));
                }
                return hex.join("");
            },
            hexToBytes: function(hex) {
                for (var bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
                return bytes;
            },
            bytesToBase64: function(bytes) {
                for (var base64 = [], i = 0; i < bytes.length; i += 3) {
                    var triplet = bytes[i] << 16 | bytes[i + 1] << 8 | bytes[i + 2];
                    for (var j = 0; j < 4; j++) {
                        if (i * 8 + j * 6 <= bytes.length * 8) base64.push(base64map.charAt(triplet >>> 6 * (3 - j) & 63)); else base64.push("=");
                    }
                }
                return base64.join("");
            },
            base64ToBytes: function(base64) {
                base64 = base64.replace(/[^A-Z0-9+\/]/gi, "");
                for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
                    if (imod4 == 0) continue;
                    bytes.push((base64map.indexOf(base64.charAt(i - 1)) & Math.pow(2, -2 * imod4 + 8) - 1) << imod4 * 2 | base64map.indexOf(base64.charAt(i)) >>> 6 - imod4 * 2);
                }
                return bytes;
            }
        };
        var charenc = Crypto.charenc = {};
        var UTF8 = charenc.UTF8 = {
            stringToBytes: function(str) {
                return Binary.stringToBytes(unescape(encodeURIComponent(str)));
            },
            bytesToString: function(bytes) {
                return decodeURIComponent(escape(Binary.bytesToString(bytes)));
            }
        };
        var Binary = charenc.Binary = {
            stringToBytes: function(str) {
                for (var bytes = [], i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i) & 255);
                return bytes;
            },
            bytesToString: function(bytes) {
                for (var str = [], i = 0; i < bytes.length; i++) str.push(String.fromCharCode(bytes[i]));
                return str.join("");
            }
        };
    })();
}

(function() {
    var util = Crypto.util;
    util.u32 = function(n) {
        return n >>> 0;
    };
    util.add = function() {
        var result = this.u32(arguments[0]);
        for (var i = 1; i < arguments.length; i++) result = this.u32(result + this.u32(arguments[i]));
        return result;
    };
    util.mult = function(m, n) {
        return this.add((n & 4294901760) * m, (n & 65535) * m);
    };
    util.gt = function(m, n) {
        return this.u32(m) > this.u32(n);
    };
    util.lt = function(m, n) {
        return this.u32(m) < this.u32(n);
    };
})();

(function(C) {
    var C_pad = C.pad = {};
    function _requiredPadding(cipher, message) {
        var blockSizeInBytes = cipher._blocksize * 4;
        var reqd = blockSizeInBytes - message.length % blockSizeInBytes;
        return reqd;
    }
    var _unpadLength = function(cipher, message, alg, padding) {
        var pad = message.pop();
        if (pad == 0) {
            throw new Error("Invalid zero-length padding specified for " + alg + ". Wrong cipher specification or key used?");
        }
        var maxPad = cipher._blocksize * 4;
        if (pad > maxPad) {
            throw new Error("Invalid padding length of " + pad + " specified for " + alg + ". Wrong cipher specification or key used?");
        }
        for (var i = 1; i < pad; i++) {
            var b = message.pop();
            if (padding != undefined && padding != b) {
                throw new Error("Invalid padding byte of 0x" + b.toString(16) + " specified for " + alg + ". Wrong cipher specification or key used?");
            }
        }
    };
    C_pad.NoPadding = {
        pad: function(cipher, message) {},
        unpad: function(cipher, message) {}
    };
    C_pad.ZeroPadding = {
        pad: function(cipher, message) {
            var blockSizeInBytes = cipher._blocksize * 4;
            var reqd = message.length % blockSizeInBytes;
            if (reqd != 0) {
                for (reqd = blockSizeInBytes - reqd; reqd > 0; reqd--) {
                    message.push(0);
                }
            }
        },
        unpad: function(cipher, message) {
            while (message[message.length - 1] == 0) {
                message.pop();
            }
        }
    };
    C_pad.iso7816 = {
        pad: function(cipher, message) {
            var reqd = _requiredPadding(cipher, message);
            message.push(128);
            for (;reqd > 1; reqd--) {
                message.push(0);
            }
        },
        unpad: function(cipher, message) {
            var padLength;
            for (padLength = cipher._blocksize * 4; padLength > 0; padLength--) {
                var b = message.pop();
                if (b == 128) return;
                if (b != 0) {
                    throw new Error("ISO-7816 padding byte must be 0, not 0x" + b.toString(16) + ". Wrong cipher specification or key used?");
                }
            }
            throw new Error("ISO-7816 padded beyond cipher block size. Wrong cipher specification or key used?");
        }
    };
    C_pad.ansix923 = {
        pad: function(cipher, message) {
            var reqd = _requiredPadding(cipher, message);
            for (var i = 1; i < reqd; i++) {
                message.push(0);
            }
            message.push(reqd);
        },
        unpad: function(cipher, message) {
            _unpadLength(cipher, message, "ANSI X.923", 0);
        }
    };
    C_pad.iso10126 = {
        pad: function(cipher, message) {
            var reqd = _requiredPadding(cipher, message);
            for (var i = 1; i < reqd; i++) {
                message.push(Math.floor(Math.random() * 256));
            }
            message.push(reqd);
        },
        unpad: function(cipher, message) {
            _unpadLength(cipher, message, "ISO 10126", undefined);
        }
    };
    C_pad.pkcs7 = {
        pad: function(cipher, message) {
            var reqd = _requiredPadding(cipher, message);
            for (var i = 0; i < reqd; i++) {
                message.push(reqd);
            }
        },
        unpad: function(cipher, message) {
            _unpadLength(cipher, message, "PKCS 7", message[message.length - 1]);
        }
    };
    var C_mode = C.mode = {};
    var Mode = C_mode.Mode = function(padding) {
        if (padding) {
            this._padding = padding;
        }
    };
    Mode.prototype = {
        encrypt: function(cipher, m, iv) {
            this._padding.pad(cipher, m);
            this._doEncrypt(cipher, m, iv);
        },
        decrypt: function(cipher, m, iv) {
            this._doDecrypt(cipher, m, iv);
            this._padding.unpad(cipher, m);
        },
        _padding: C_pad.iso7816
    };
    var ECB = C_mode.ECB = function() {
        Mode.apply(this, arguments);
    };
    var ECB_prototype = ECB.prototype = new Mode();
    ECB_prototype._doEncrypt = function(cipher, m, iv) {
        var blockSizeInBytes = cipher._blocksize * 4;
        for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
            cipher._encryptblock(m, offset);
        }
    };
    ECB_prototype._doDecrypt = function(cipher, c, iv) {
        var blockSizeInBytes = cipher._blocksize * 4;
        for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
            cipher._decryptblock(c, offset);
        }
    };
    ECB_prototype.fixOptions = function(options) {
        options.iv = [];
    };
    var CBC = C_mode.CBC = function() {
        Mode.apply(this, arguments);
    };
    var CBC_prototype = CBC.prototype = new Mode();
    CBC_prototype._doEncrypt = function(cipher, m, iv) {
        var blockSizeInBytes = cipher._blocksize * 4;
        for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
            if (offset == 0) {
                for (var i = 0; i < blockSizeInBytes; i++) m[i] ^= iv[i];
            } else {
                for (var i = 0; i < blockSizeInBytes; i++) m[offset + i] ^= m[offset + i - blockSizeInBytes];
            }
            cipher._encryptblock(m, offset);
        }
    };
    CBC_prototype._doDecrypt = function(cipher, c, iv) {
        var blockSizeInBytes = cipher._blocksize * 4;
        var prevCryptedBlock = iv;
        for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
            var thisCryptedBlock = c.slice(offset, offset + blockSizeInBytes);
            cipher._decryptblock(c, offset);
            for (var i = 0; i < blockSizeInBytes; i++) {
                c[offset + i] ^= prevCryptedBlock[i];
            }
            prevCryptedBlock = thisCryptedBlock;
        }
    };
    var CFB = C_mode.CFB = function() {
        Mode.apply(this, arguments);
    };
    var CFB_prototype = CFB.prototype = new Mode();
    CFB_prototype._padding = C_pad.NoPadding;
    CFB_prototype._doEncrypt = function(cipher, m, iv) {
        var blockSizeInBytes = cipher._blocksize * 4, keystream = iv.slice(0);
        for (var i = 0; i < m.length; i++) {
            var j = i % blockSizeInBytes;
            if (j == 0) cipher._encryptblock(keystream, 0);
            m[i] ^= keystream[j];
            keystream[j] = m[i];
        }
    };
    CFB_prototype._doDecrypt = function(cipher, c, iv) {
        var blockSizeInBytes = cipher._blocksize * 4, keystream = iv.slice(0);
        for (var i = 0; i < c.length; i++) {
            var j = i % blockSizeInBytes;
            if (j == 0) cipher._encryptblock(keystream, 0);
            var b = c[i];
            c[i] ^= keystream[j];
            keystream[j] = b;
        }
    };
    var OFB = C_mode.OFB = function() {
        Mode.apply(this, arguments);
    };
    var OFB_prototype = OFB.prototype = new Mode();
    OFB_prototype._padding = C_pad.NoPadding;
    OFB_prototype._doEncrypt = function(cipher, m, iv) {
        var blockSizeInBytes = cipher._blocksize * 4, keystream = iv.slice(0);
        for (var i = 0; i < m.length; i++) {
            if (i % blockSizeInBytes == 0) cipher._encryptblock(keystream, 0);
            m[i] ^= keystream[i % blockSizeInBytes];
        }
    };
    OFB_prototype._doDecrypt = OFB_prototype._doEncrypt;
    var CTR = C_mode.CTR = function() {
        Mode.apply(this, arguments);
    };
    var CTR_prototype = CTR.prototype = new Mode();
    CTR_prototype._padding = C_pad.NoPadding;
    CTR_prototype._doEncrypt = function(cipher, m, iv) {
        var blockSizeInBytes = cipher._blocksize * 4;
        var counter = iv.slice(0);
        for (var i = 0; i < m.length; ) {
            var keystream = counter.slice(0);
            cipher._encryptblock(keystream, 0);
            for (var j = 0; i < m.length && j < blockSizeInBytes; j++, i++) {
                m[i] ^= keystream[j];
            }
            if (++counter[blockSizeInBytes - 1] == 256) {
                counter[blockSizeInBytes - 1] = 0;
                if (++counter[blockSizeInBytes - 2] == 256) {
                    counter[blockSizeInBytes - 2] = 0;
                    if (++counter[blockSizeInBytes - 3] == 256) {
                        counter[blockSizeInBytes - 3] = 0;
                        ++counter[blockSizeInBytes - 4];
                    }
                }
            }
        }
    };
    CTR_prototype._doDecrypt = CTR_prototype._doEncrypt;
})(Crypto);

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    var K = [ 1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298 ];
    var SHA256 = C.SHA256 = function(message, options) {
        var digestbytes = util.wordsToBytes(SHA256._sha256(message));
        return options && options.asBytes ? digestbytes : options && options.asString ? Binary.bytesToString(digestbytes) : util.bytesToHex(digestbytes);
    };
    SHA256._sha256 = function(message) {
        if (message.constructor == String) message = UTF8.stringToBytes(message);
        var m = util.bytesToWords(message), l = message.length * 8, H = [ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 ], w = [], a, b, c, d, e, f, g, h, i, j, t1, t2;
        m[l >> 5] |= 128 << 24 - l % 32;
        m[(l + 64 >> 9 << 4) + 15] = l;
        for (var i = 0; i < m.length; i += 16) {
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];
            for (var j = 0; j < 64; j++) {
                if (j < 16) w[j] = m[j + i]; else {
                    var gamma0x = w[j - 15], gamma1x = w[j - 2], gamma0 = (gamma0x << 25 | gamma0x >>> 7) ^ (gamma0x << 14 | gamma0x >>> 18) ^ gamma0x >>> 3, gamma1 = (gamma1x << 15 | gamma1x >>> 17) ^ (gamma1x << 13 | gamma1x >>> 19) ^ gamma1x >>> 10;
                    w[j] = gamma0 + (w[j - 7] >>> 0) + gamma1 + (w[j - 16] >>> 0);
                }
                var ch = e & f ^ ~e & g, maj = a & b ^ a & c ^ b & c, sigma0 = (a << 30 | a >>> 2) ^ (a << 19 | a >>> 13) ^ (a << 10 | a >>> 22), sigma1 = (e << 26 | e >>> 6) ^ (e << 21 | e >>> 11) ^ (e << 7 | e >>> 25);
                t1 = (h >>> 0) + sigma1 + ch + K[j] + (w[j] >>> 0);
                t2 = sigma0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + t1 >>> 0;
                d = c;
                c = b;
                b = a;
                a = t1 + t2 >>> 0;
            }
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }
        return H;
    };
    SHA256._blocksize = 16;
    SHA256._digestsize = 32;
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    var SHA1 = C.SHA1 = function(message, options) {
        var digestbytes = util.wordsToBytes(SHA1._sha1(message));
        return options && options.asBytes ? digestbytes : options && options.asString ? Binary.bytesToString(digestbytes) : util.bytesToHex(digestbytes);
    };
    SHA1._sha1 = function(message) {
        if (message.constructor == String) message = UTF8.stringToBytes(message);
        var m = util.bytesToWords(message), l = message.length * 8, w = [], H0 = 1732584193, H1 = -271733879, H2 = -1732584194, H3 = 271733878, H4 = -1009589776;
        m[l >> 5] |= 128 << 24 - l % 32;
        m[(l + 64 >>> 9 << 4) + 15] = l;
        for (var i = 0; i < m.length; i += 16) {
            var a = H0, b = H1, c = H2, d = H3, e = H4;
            for (var j = 0; j < 80; j++) {
                if (j < 16) w[j] = m[i + j]; else {
                    var n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
                    w[j] = n << 1 | n >>> 31;
                }
                var t = (H0 << 5 | H0 >>> 27) + H4 + (w[j] >>> 0) + (j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 : j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 : j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 : (H1 ^ H2 ^ H3) - 899497514);
                H4 = H3;
                H3 = H2;
                H2 = H1 << 30 | H1 >>> 2;
                H1 = H0;
                H0 = t;
            }
            H0 += a;
            H1 += b;
            H2 += c;
            H3 += d;
            H4 += e;
        }
        return [ H0, H1, H2, H3, H4 ];
    };
    SHA1._blocksize = 16;
    SHA1._digestsize = 20;
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    var MD5 = C.MD5 = function(message, options) {
        var digestbytes = util.wordsToBytes(MD5._md5(message));
        return options && options.asBytes ? digestbytes : options && options.asString ? Binary.bytesToString(digestbytes) : util.bytesToHex(digestbytes);
    };
    MD5._md5 = function(message) {
        if (message.constructor == String) message = UTF8.stringToBytes(message);
        var m = util.bytesToWords(message), l = message.length * 8, a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
        for (var i = 0; i < m.length; i++) {
            m[i] = (m[i] << 8 | m[i] >>> 24) & 16711935 | (m[i] << 24 | m[i] >>> 8) & 4278255360;
        }
        m[l >>> 5] |= 128 << l % 32;
        m[(l + 64 >>> 9 << 4) + 14] = l;
        var FF = MD5._ff, GG = MD5._gg, HH = MD5._hh, II = MD5._ii;
        for (var i = 0; i < m.length; i += 16) {
            var aa = a, bb = b, cc = c, dd = d;
            a = FF(a, b, c, d, m[i + 0], 7, -680876936);
            d = FF(d, a, b, c, m[i + 1], 12, -389564586);
            c = FF(c, d, a, b, m[i + 2], 17, 606105819);
            b = FF(b, c, d, a, m[i + 3], 22, -1044525330);
            a = FF(a, b, c, d, m[i + 4], 7, -176418897);
            d = FF(d, a, b, c, m[i + 5], 12, 1200080426);
            c = FF(c, d, a, b, m[i + 6], 17, -1473231341);
            b = FF(b, c, d, a, m[i + 7], 22, -45705983);
            a = FF(a, b, c, d, m[i + 8], 7, 1770035416);
            d = FF(d, a, b, c, m[i + 9], 12, -1958414417);
            c = FF(c, d, a, b, m[i + 10], 17, -42063);
            b = FF(b, c, d, a, m[i + 11], 22, -1990404162);
            a = FF(a, b, c, d, m[i + 12], 7, 1804603682);
            d = FF(d, a, b, c, m[i + 13], 12, -40341101);
            c = FF(c, d, a, b, m[i + 14], 17, -1502002290);
            b = FF(b, c, d, a, m[i + 15], 22, 1236535329);
            a = GG(a, b, c, d, m[i + 1], 5, -165796510);
            d = GG(d, a, b, c, m[i + 6], 9, -1069501632);
            c = GG(c, d, a, b, m[i + 11], 14, 643717713);
            b = GG(b, c, d, a, m[i + 0], 20, -373897302);
            a = GG(a, b, c, d, m[i + 5], 5, -701558691);
            d = GG(d, a, b, c, m[i + 10], 9, 38016083);
            c = GG(c, d, a, b, m[i + 15], 14, -660478335);
            b = GG(b, c, d, a, m[i + 4], 20, -405537848);
            a = GG(a, b, c, d, m[i + 9], 5, 568446438);
            d = GG(d, a, b, c, m[i + 14], 9, -1019803690);
            c = GG(c, d, a, b, m[i + 3], 14, -187363961);
            b = GG(b, c, d, a, m[i + 8], 20, 1163531501);
            a = GG(a, b, c, d, m[i + 13], 5, -1444681467);
            d = GG(d, a, b, c, m[i + 2], 9, -51403784);
            c = GG(c, d, a, b, m[i + 7], 14, 1735328473);
            b = GG(b, c, d, a, m[i + 12], 20, -1926607734);
            a = HH(a, b, c, d, m[i + 5], 4, -378558);
            d = HH(d, a, b, c, m[i + 8], 11, -2022574463);
            c = HH(c, d, a, b, m[i + 11], 16, 1839030562);
            b = HH(b, c, d, a, m[i + 14], 23, -35309556);
            a = HH(a, b, c, d, m[i + 1], 4, -1530992060);
            d = HH(d, a, b, c, m[i + 4], 11, 1272893353);
            c = HH(c, d, a, b, m[i + 7], 16, -155497632);
            b = HH(b, c, d, a, m[i + 10], 23, -1094730640);
            a = HH(a, b, c, d, m[i + 13], 4, 681279174);
            d = HH(d, a, b, c, m[i + 0], 11, -358537222);
            c = HH(c, d, a, b, m[i + 3], 16, -722521979);
            b = HH(b, c, d, a, m[i + 6], 23, 76029189);
            a = HH(a, b, c, d, m[i + 9], 4, -640364487);
            d = HH(d, a, b, c, m[i + 12], 11, -421815835);
            c = HH(c, d, a, b, m[i + 15], 16, 530742520);
            b = HH(b, c, d, a, m[i + 2], 23, -995338651);
            a = II(a, b, c, d, m[i + 0], 6, -198630844);
            d = II(d, a, b, c, m[i + 7], 10, 1126891415);
            c = II(c, d, a, b, m[i + 14], 15, -1416354905);
            b = II(b, c, d, a, m[i + 5], 21, -57434055);
            a = II(a, b, c, d, m[i + 12], 6, 1700485571);
            d = II(d, a, b, c, m[i + 3], 10, -1894986606);
            c = II(c, d, a, b, m[i + 10], 15, -1051523);
            b = II(b, c, d, a, m[i + 1], 21, -2054922799);
            a = II(a, b, c, d, m[i + 8], 6, 1873313359);
            d = II(d, a, b, c, m[i + 15], 10, -30611744);
            c = II(c, d, a, b, m[i + 6], 15, -1560198380);
            b = II(b, c, d, a, m[i + 13], 21, 1309151649);
            a = II(a, b, c, d, m[i + 4], 6, -145523070);
            d = II(d, a, b, c, m[i + 11], 10, -1120210379);
            c = II(c, d, a, b, m[i + 2], 15, 718787259);
            b = II(b, c, d, a, m[i + 9], 21, -343485551);
            a = a + aa >>> 0;
            b = b + bb >>> 0;
            c = c + cc >>> 0;
            d = d + dd >>> 0;
        }
        return util.endian([ a, b, c, d ]);
    };
    MD5._ff = function(a, b, c, d, x, s, t) {
        var n = a + (b & c | ~b & d) + (x >>> 0) + t;
        return (n << s | n >>> 32 - s) + b;
    };
    MD5._gg = function(a, b, c, d, x, s, t) {
        var n = a + (b & d | c & ~d) + (x >>> 0) + t;
        return (n << s | n >>> 32 - s) + b;
    };
    MD5._hh = function(a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + (x >>> 0) + t;
        return (n << s | n >>> 32 - s) + b;
    };
    MD5._ii = function(a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
        return (n << s | n >>> 32 - s) + b;
    };
    MD5._blocksize = 16;
    MD5._digestsize = 16;
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8;
    var SBOX = [ 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 ];
    for (var INVSBOX = [], i = 0; i < 256; i++) INVSBOX[SBOX[i]] = i;
    var MULT2 = [], MULT3 = [], MULT9 = [], MULTB = [], MULTD = [], MULTE = [];
    function xtime(a, b) {
        for (var result = 0, i = 0; i < 8; i++) {
            if (b & 1) result ^= a;
            var hiBitSet = a & 128;
            a = a << 1 & 255;
            if (hiBitSet) a ^= 27;
            b >>>= 1;
        }
        return result;
    }
    for (var i = 0; i < 256; i++) {
        MULT2[i] = xtime(i, 2);
        MULT3[i] = xtime(i, 3);
        MULT9[i] = xtime(i, 9);
        MULTB[i] = xtime(i, 11);
        MULTD[i] = xtime(i, 13);
        MULTE[i] = xtime(i, 14);
    }
    var RCON = [ 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 ];
    var state = [ [], [], [], [] ], keylength, nrounds, keyschedule;
    var AES = C.AES = {
        encrypt: function(message, password, options) {
            options = options || {};
            var mode = options.mode || new C.mode.OFB();
            if (mode.fixOptions) mode.fixOptions(options);
            var m = message.constructor == String ? UTF8.stringToBytes(message) : message, iv = options.iv || util.randomBytes(AES._blocksize * 4), k = password.constructor == String ? C.PBKDF2(password, iv, 32, {
                asBytes: true
            }) : password;
            AES._init(k);
            mode.encrypt(AES, m, iv);
            m = options.iv ? m : iv.concat(m);
            return options && options.asBytes ? m : util.bytesToBase64(m);
        },
        decrypt: function(ciphertext, password, options) {
            options = options || {};
            var mode = options.mode || new C.mode.OFB();
            if (mode.fixOptions) mode.fixOptions(options);
            var c = ciphertext.constructor == String ? util.base64ToBytes(ciphertext) : ciphertext, iv = options.iv || c.splice(0, AES._blocksize * 4), k = password.constructor == String ? C.PBKDF2(password, iv, 32, {
                asBytes: true
            }) : password;
            AES._init(k);
            mode.decrypt(AES, c, iv);
            return options && options.asBytes ? c : UTF8.bytesToString(c);
        },
        _blocksize: 4,
        _encryptblock: function(m, offset) {
            for (var row = 0; row < AES._blocksize; row++) {
                for (var col = 0; col < 4; col++) state[row][col] = m[offset + col * 4 + row];
            }
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[col][row];
            }
            for (var round = 1; round < nrounds; round++) {
                for (var row = 0; row < 4; row++) {
                    for (var col = 0; col < 4; col++) state[row][col] = SBOX[state[row][col]];
                }
                state[1].push(state[1].shift());
                state[2].push(state[2].shift());
                state[2].push(state[2].shift());
                state[3].unshift(state[3].pop());
                for (var col = 0; col < 4; col++) {
                    var s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
                    state[0][col] = MULT2[s0] ^ MULT3[s1] ^ s2 ^ s3;
                    state[1][col] = s0 ^ MULT2[s1] ^ MULT3[s2] ^ s3;
                    state[2][col] = s0 ^ s1 ^ MULT2[s2] ^ MULT3[s3];
                    state[3][col] = MULT3[s0] ^ s1 ^ s2 ^ MULT2[s3];
                }
                for (var row = 0; row < 4; row++) {
                    for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[round * 4 + col][row];
                }
            }
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] = SBOX[state[row][col]];
            }
            state[1].push(state[1].shift());
            state[2].push(state[2].shift());
            state[2].push(state[2].shift());
            state[3].unshift(state[3].pop());
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[nrounds * 4 + col][row];
            }
            for (var row = 0; row < AES._blocksize; row++) {
                for (var col = 0; col < 4; col++) m[offset + col * 4 + row] = state[row][col];
            }
        },
        _decryptblock: function(c, offset) {
            for (var row = 0; row < AES._blocksize; row++) {
                for (var col = 0; col < 4; col++) state[row][col] = c[offset + col * 4 + row];
            }
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[nrounds * 4 + col][row];
            }
            for (var round = 1; round < nrounds; round++) {
                state[1].unshift(state[1].pop());
                state[2].push(state[2].shift());
                state[2].push(state[2].shift());
                state[3].push(state[3].shift());
                for (var row = 0; row < 4; row++) {
                    for (var col = 0; col < 4; col++) state[row][col] = INVSBOX[state[row][col]];
                }
                for (var row = 0; row < 4; row++) {
                    for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[(nrounds - round) * 4 + col][row];
                }
                for (var col = 0; col < 4; col++) {
                    var s0 = state[0][col], s1 = state[1][col], s2 = state[2][col], s3 = state[3][col];
                    state[0][col] = MULTE[s0] ^ MULTB[s1] ^ MULTD[s2] ^ MULT9[s3];
                    state[1][col] = MULT9[s0] ^ MULTE[s1] ^ MULTB[s2] ^ MULTD[s3];
                    state[2][col] = MULTD[s0] ^ MULT9[s1] ^ MULTE[s2] ^ MULTB[s3];
                    state[3][col] = MULTB[s0] ^ MULTD[s1] ^ MULT9[s2] ^ MULTE[s3];
                }
            }
            state[1].unshift(state[1].pop());
            state[2].push(state[2].shift());
            state[2].push(state[2].shift());
            state[3].push(state[3].shift());
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] = INVSBOX[state[row][col]];
            }
            for (var row = 0; row < 4; row++) {
                for (var col = 0; col < 4; col++) state[row][col] ^= keyschedule[col][row];
            }
            for (var row = 0; row < AES._blocksize; row++) {
                for (var col = 0; col < 4; col++) c[offset + col * 4 + row] = state[row][col];
            }
        },
        _init: function(k) {
            keylength = k.length / 4;
            nrounds = keylength + 6;
            AES._keyexpansion(k);
        },
        _keyexpansion: function(k) {
            keyschedule = [];
            for (var row = 0; row < keylength; row++) {
                keyschedule[row] = [ k[row * 4], k[row * 4 + 1], k[row * 4 + 2], k[row * 4 + 3] ];
            }
            for (var row = keylength; row < AES._blocksize * (nrounds + 1); row++) {
                var temp = [ keyschedule[row - 1][0], keyschedule[row - 1][1], keyschedule[row - 1][2], keyschedule[row - 1][3] ];
                if (row % keylength == 0) {
                    temp.push(temp.shift());
                    temp[0] = SBOX[temp[0]];
                    temp[1] = SBOX[temp[1]];
                    temp[2] = SBOX[temp[2]];
                    temp[3] = SBOX[temp[3]];
                    temp[0] ^= RCON[row / keylength];
                } else if (keylength > 6 && row % keylength == 4) {
                    temp[0] = SBOX[temp[0]];
                    temp[1] = SBOX[temp[1]];
                    temp[2] = SBOX[temp[2]];
                    temp[3] = SBOX[temp[3]];
                }
                keyschedule[row] = [ keyschedule[row - keylength][0] ^ temp[0], keyschedule[row - keylength][1] ^ temp[1], keyschedule[row - keylength][2] ^ temp[2], keyschedule[row - keylength][3] ^ temp[3] ];
            }
        }
    };
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    C.PBKDF2 = function(password, salt, keylen, options) {
        if (password.constructor == String) password = UTF8.stringToBytes(password);
        if (salt.constructor == String) salt = UTF8.stringToBytes(salt);
        var hasher = options && options.hasher || C.SHA1, iterations = options && options.iterations || 1;
        function PRF(password, salt) {
            return C.HMAC(hasher, salt, password, {
                asBytes: true
            });
        }
        var derivedKeyBytes = [], blockindex = 1;
        while (derivedKeyBytes.length < keylen) {
            var block = PRF(password, salt.concat(util.wordsToBytes([ blockindex ])));
            for (var u = block, i = 1; i < iterations; i++) {
                u = PRF(password, u);
                for (var j = 0; j < block.length; j++) block[j] ^= u[j];
            }
            derivedKeyBytes = derivedKeyBytes.concat(block);
            blockindex++;
        }
        derivedKeyBytes.length = keylen;
        return options && options.asBytes ? derivedKeyBytes : options && options.asString ? Binary.bytesToString(derivedKeyBytes) : util.bytesToHex(derivedKeyBytes);
    };
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    C.HMAC = function(hasher, message, key, options) {
        if (message.constructor == String) message = UTF8.stringToBytes(message);
        if (key.constructor == String) key = UTF8.stringToBytes(key);
        if (key.length > hasher._blocksize * 4) key = hasher(key, {
            asBytes: true
        });
        var okey = key.slice(0), ikey = key.slice(0);
        for (var i = 0; i < hasher._blocksize * 4; i++) {
            okey[i] ^= 92;
            ikey[i] ^= 54;
        }
        var hmacbytes = hasher(okey.concat(hasher(ikey.concat(message), {
            asBytes: true
        })), {
            asBytes: true
        });
        return options && options.asBytes ? hmacbytes : options && options.asString ? Binary.bytesToString(hmacbytes) : util.bytesToHex(hmacbytes);
    };
})();

(function() {
    var C = Crypto, util = C.util, charenc = C.charenc, UTF8 = charenc.UTF8, Binary = charenc.Binary;
    util.bytesToLWords = function(bytes) {
        var output = Array(bytes.length >> 2);
        for (var i = 0; i < output.length; i++) output[i] = 0;
        for (var i = 0; i < bytes.length * 8; i += 8) output[i >> 5] |= (bytes[i / 8] & 255) << i % 32;
        return output;
    };
    util.lWordsToBytes = function(words) {
        var output = [];
        for (var i = 0; i < words.length * 32; i += 8) output.push(words[i >> 5] >>> i % 32 & 255);
        return output;
    };
    var RIPEMD160 = C.RIPEMD160 = function(message, options) {
        var digestbytes = util.lWordsToBytes(RIPEMD160._rmd160(message));
        return options && options.asBytes ? digestbytes : options && options.asString ? Binary.bytesToString(digestbytes) : util.bytesToHex(digestbytes);
    };
    RIPEMD160._rmd160 = function(message) {
        if (message.constructor == String) message = UTF8.stringToBytes(message);
        var x = util.bytesToLWords(message), len = message.length * 8;
        x[len >> 5] |= 128 << len % 32;
        x[(len + 64 >>> 9 << 4) + 14] = len;
        var h0 = 1732584193;
        var h1 = 4023233417;
        var h2 = 2562383102;
        var h3 = 271733878;
        var h4 = 3285377520;
        for (var i = 0; i < x.length; i += 16) {
            var T;
            var A1 = h0, B1 = h1, C1 = h2, D1 = h3, E1 = h4;
            var A2 = h0, B2 = h1, C2 = h2, D2 = h3, E2 = h4;
            for (var j = 0; j <= 79; ++j) {
                T = safe_add(A1, rmd160_f(j, B1, C1, D1));
                T = safe_add(T, x[i + rmd160_r1[j]]);
                T = safe_add(T, rmd160_K1(j));
                T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
                A1 = E1;
                E1 = D1;
                D1 = bit_rol(C1, 10);
                C1 = B1;
                B1 = T;
                T = safe_add(A2, rmd160_f(79 - j, B2, C2, D2));
                T = safe_add(T, x[i + rmd160_r2[j]]);
                T = safe_add(T, rmd160_K2(j));
                T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
                A2 = E2;
                E2 = D2;
                D2 = bit_rol(C2, 10);
                C2 = B2;
                B2 = T;
            }
            T = safe_add(h1, safe_add(C1, D2));
            h1 = safe_add(h2, safe_add(D1, E2));
            h2 = safe_add(h3, safe_add(E1, A2));
            h3 = safe_add(h4, safe_add(A1, B2));
            h4 = safe_add(h0, safe_add(B1, C2));
            h0 = T;
        }
        return [ h0, h1, h2, h3, h4 ];
    };
    function rmd160_f(j, x, y, z) {
        return 0 <= j && j <= 15 ? x ^ y ^ z : 16 <= j && j <= 31 ? x & y | ~x & z : 32 <= j && j <= 47 ? (x | ~y) ^ z : 48 <= j && j <= 63 ? x & z | y & ~z : 64 <= j && j <= 79 ? x ^ (y | ~z) : "rmd160_f: j out of range";
    }
    function rmd160_K1(j) {
        return 0 <= j && j <= 15 ? 0 : 16 <= j && j <= 31 ? 1518500249 : 32 <= j && j <= 47 ? 1859775393 : 48 <= j && j <= 63 ? 2400959708 : 64 <= j && j <= 79 ? 2840853838 : "rmd160_K1: j out of range";
    }
    function rmd160_K2(j) {
        return 0 <= j && j <= 15 ? 1352829926 : 16 <= j && j <= 31 ? 1548603684 : 32 <= j && j <= 47 ? 1836072691 : 48 <= j && j <= 63 ? 2053994217 : 64 <= j && j <= 79 ? 0 : "rmd160_K2: j out of range";
    }
    var rmd160_r1 = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 ];
    var rmd160_r2 = [ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 ];
    var rmd160_s1 = [ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 ];
    var rmd160_s2 = [ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 ];
    function safe_add(x, y) {
        var lsw = (x & 65535) + (y & 65535);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return msw << 16 | lsw & 65535;
    }
    function bit_rol(num, cnt) {
        return num << cnt | num >>> 32 - cnt;
    }
})();

var scrypt_module_factory = function(requested_total_memory) {
    var Module = {
        TOTAL_MEMORY: requested_total_memory || 33554432
    };
    var scrypt_raw = Module;
    function g(a) {
        throw a;
    }
    var k = void 0, l = !0, m = null, p = !1;
    function aa() {
        return function() {};
    }
    var q, s;
    s || (s = eval("(function() { try { return Module || {} } catch(e) { return {} } })()"));
    var ba = {}, t;
    for (t in s) {
        s.hasOwnProperty(t) && (ba[t] = s[t]);
    }
    var ca = "object" === typeof process && "function" === typeof require, da = "object" === typeof window, ea = "function" === typeof importScripts, fa = !da && !ca && !ea;
    if (ca) {
        s.print = function(a) {
            process.stdout.write(a + "\n");
        };
        s.printErr = function(a) {
            process.stderr.write(a + "\n");
        };
        var ga = require("fs"), ha = require("path");
        s.read = function(a, b) {
            var a = ha.normalize(a), c = ga.readFileSync(a);
            !c && a != ha.resolve(a) && (a = path.join(__dirname, "..", "src", a), c = ga.readFileSync(a));
            c && !b && (c = c.toString());
            return c;
        };
        s.readBinary = function(a) {
            return s.read(a, l);
        };
        s.load = function(a) {
            ia(read(a));
        };
        s.arguments = process.argv.slice(2);
        module.ee = s;
    } else {
        fa ? (s.print = print, "undefined" != typeof printErr && (s.printErr = printErr), 
        s.read = read, s.readBinary = function(a) {
            return read(a, "binary");
        }, "undefined" != typeof scriptArgs ? s.arguments = scriptArgs : "undefined" != typeof arguments && (s.arguments = arguments), 
        this.Module = s) : da || ea ? (s.read = function(a) {
            var b = new XMLHttpRequest();
            b.open("GET", a, p);
            b.send(m);
            return b.responseText;
        }, "undefined" != typeof arguments && (s.arguments = arguments), da ? (s.print = function(a) {
            console.log(a);
        }, s.printErr = function(a) {
            console.log(a);
        }, this.Module = s) : ea && (s.print = aa(), s.load = importScripts)) : g("Unknown runtime environment. Where are we?");
    }
    function ia(a) {
        eval.call(m, a);
    }
    "undefined" == !s.load && s.read && (s.load = function(a) {
        ia(s.read(a));
    });
    s.print || (s.print = aa());
    s.printErr || (s.printErr = s.print);
    s.arguments || (s.arguments = []);
    s.print = s.print;
    s.P = s.printErr;
    s.preRun = [];
    s.postRun = [];
    for (t in ba) {
        ba.hasOwnProperty(t) && (s[t] = ba[t]);
    }
    function ja() {
        return u;
    }
    function ka(a) {
        u = a;
    }
    function la(a) {
        if (1 == ma) {
            return 1;
        }
        var b = {
            "%i1": 1,
            "%i8": 1,
            "%i16": 2,
            "%i32": 4,
            "%i64": 8,
            "%float": 4,
            "%double": 8
        }["%" + a];
        b || ("*" == a.charAt(a.length - 1) ? b = ma : "i" == a[0] && (a = parseInt(a.substr(1)), 
        w(0 == a % 8), b = a / 8));
        return b;
    }
    function na(a, b, c) {
        c && c.length ? (c.splice || (c = Array.prototype.slice.call(c)), c.splice(0, 0, b), 
        s["dynCall_" + a].apply(m, c)) : s["dynCall_" + a].call(m, b);
    }
    var oa;
    function pa() {
        var a = [], b = 0;
        this.oa = function(c) {
            c &= 255;
            b && (a.push(c), b--);
            if (0 == a.length) {
                if (128 > c) {
                    return String.fromCharCode(c);
                }
                a.push(c);
                b = 191 < c && 224 > c ? 1 : 2;
                return "";
            }
            if (0 < b) {
                return "";
            }
            var c = a[0], d = a[1], e = a[2], c = 191 < c && 224 > c ? String.fromCharCode((c & 31) << 6 | d & 63) : String.fromCharCode((c & 15) << 12 | (d & 63) << 6 | e & 63);
            a.length = 0;
            return c;
        };
        this.yb = function(a) {
            for (var a = unescape(encodeURIComponent(a)), b = [], e = 0; e < a.length; e++) {
                b.push(a.charCodeAt(e));
            }
            return b;
        };
    }
    function qa(a) {
        var b = u;
        u = u + a | 0;
        u = u + 7 >> 3 << 3;
        return b;
    }
    function ra(a) {
        var b = sa;
        sa = sa + a | 0;
        sa = sa + 7 >> 3 << 3;
        return b;
    }
    function ua(a) {
        var b = z;
        z = z + a | 0;
        z = z + 7 >> 3 << 3;
        z >= va && wa("Cannot enlarge memory arrays in asm.js. Either (1) compile with -s TOTAL_MEMORY=X with X higher than the current value, or (2) set Module.TOTAL_MEMORY before the program runs.");
        return b;
    }
    function xa(a, b) {
        return Math.ceil(a / (b ? b : 8)) * (b ? b : 8);
    }
    var ma = 4, ya = {}, za = p, Aa;
    function w(a, b) {
        a || wa("Assertion failed: " + b);
    }
    s.ccall = function(a, b, c, d) {
        return Ba(Ca(a), b, c, d);
    };
    function Ca(a) {
        try {
            var b = s["_" + a];
            b || (b = eval("_" + a));
        } catch (c) {}
        w(b, "Cannot call unknown function " + a + " (perhaps LLVM optimizations or closure removed it?)");
        return b;
    }
    function Ba(a, b, c, d) {
        function e(a, b) {
            if ("string" == b) {
                if (a === m || a === k || 0 === a) {
                    return 0;
                }
                f || (f = ja());
                var c = qa(a.length + 1);
                Da(a, c);
                return c;
            }
            return "array" == b ? (f || (f = ja()), c = qa(a.length), Ea(a, c), c) : a;
        }
        var f = 0, h = 0, d = d ? d.map(function(a) {
            return e(a, c[h++]);
        }) : [];
        a = a.apply(m, d);
        "string" == b ? b = Fa(a) : (w("array" != b), b = a);
        f && ka(f);
        return b;
    }
    s.cwrap = function(a, b, c) {
        var d = Ca(a);
        return function() {
            return Ba(d, b, c, Array.prototype.slice.call(arguments));
        };
    };
    function Ga(a, b, c) {
        c = c || "i8";
        "*" === c.charAt(c.length - 1) && (c = "i32");
        switch (c) {
          case "i1":
            A[a] = b;
            break;

          case "i8":
            A[a] = b;
            break;

          case "i16":
            Ha[a >> 1] = b;
            break;

          case "i32":
            B[a >> 2] = b;
            break;

          case "i64":
            Aa = [ b >>> 0, (Math.min(+Math.floor(b / 4294967296), 4294967295) | 0) >>> 0 ];
            B[a >> 2] = Aa[0];
            B[a + 4 >> 2] = Aa[1];
            break;

          case "float":
            Ia[a >> 2] = b;
            break;

          case "double":
            Ja[a >> 3] = b;
            break;

          default:
            wa("invalid type for setValue: " + c);
        }
    }
    s.setValue = Ga;
    s.getValue = function(a, b) {
        b = b || "i8";
        "*" === b.charAt(b.length - 1) && (b = "i32");
        switch (b) {
          case "i1":
            return A[a];

          case "i8":
            return A[a];

          case "i16":
            return Ha[a >> 1];

          case "i32":
            return B[a >> 2];

          case "i64":
            return B[a >> 2];

          case "float":
            return Ia[a >> 2];

          case "double":
            return Ja[a >> 3];

          default:
            wa("invalid type for setValue: " + b);
        }
        return m;
    };
    var Ka = 0, La = 1, E = 2, Na = 4;
    s.ALLOC_NORMAL = Ka;
    s.ALLOC_STACK = La;
    s.ALLOC_STATIC = E;
    s.ALLOC_DYNAMIC = 3;
    s.ALLOC_NONE = Na;
    function F(a, b, c, d) {
        var e, f;
        "number" === typeof a ? (e = l, f = a) : (e = p, f = a.length);
        var h = "string" === typeof b ? b : m, c = c == Na ? d : [ Oa, qa, ra, ua ][c === k ? E : c](Math.max(f, h ? 1 : b.length));
        if (e) {
            d = c;
            w(0 == (c & 3));
            for (a = c + (f & -4); d < a; d += 4) {
                B[d >> 2] = 0;
            }
            for (a = c + f; d < a; ) {
                A[d++ | 0] = 0;
            }
            return c;
        }
        if ("i8" === h) {
            return a.subarray || a.slice ? G.set(a, c) : G.set(new Uint8Array(a), c), c;
        }
        for (var d = 0, i, j; d < f; ) {
            var n = a[d];
            "function" === typeof n && (n = ya.fe(n));
            e = h || b[d];
            0 === e ? d++ : ("i64" == e && (e = "i32"), Ga(c + d, n, e), j !== e && (i = la(e), 
            j = e), d += i);
        }
        return c;
    }
    s.allocate = F;
    function Fa(a, b) {
        for (var c = p, d, e = 0; ;) {
            d = G[a + e | 0];
            if (128 <= d) {
                c = l;
            } else {
                if (0 == d && !b) {
                    break;
                }
            }
            e++;
            if (b && e == b) {
                break;
            }
        }
        b || (b = e);
        var f = "";
        if (!c) {
            for (;0 < b; ) {
                d = String.fromCharCode.apply(String, G.subarray(a, a + Math.min(b, 1024))), f = f ? f + d : d, 
                a += 1024, b -= 1024;
            }
            return f;
        }
        c = new pa();
        for (e = 0; e < b; e++) {
            d = G[a + e | 0], f += c.oa(d);
        }
        return f;
    }
    s.Pointer_stringify = Fa;
    var A, G, Ha, Pa, B, Qa, Ia, Ja, Ra = 0, sa = 0, Sa = 0, u = 0, Ta = 0, Ua = 0, z = 0, va = s.TOTAL_MEMORY || 33554432;
    w(!!Int32Array && !!Float64Array && !!new Int32Array(1).subarray && !!new Int32Array(1).set, "Cannot fallback to non-typed array case: Code is too specialized");
    var I = new ArrayBuffer(va);
    A = new Int8Array(I);
    Ha = new Int16Array(I);
    B = new Int32Array(I);
    G = new Uint8Array(I);
    Pa = new Uint16Array(I);
    Qa = new Uint32Array(I);
    Ia = new Float32Array(I);
    Ja = new Float64Array(I);
    B[0] = 255;
    w(255 === G[0] && 0 === G[3], "Typed arrays 2 must be run on a little-endian system");
    s.HEAP = k;
    s.HEAP8 = A;
    s.HEAP16 = Ha;
    s.HEAP32 = B;
    s.HEAPU8 = G;
    s.HEAPU16 = Pa;
    s.HEAPU32 = Qa;
    s.HEAPF32 = Ia;
    s.HEAPF64 = Ja;
    function Va(a) {
        for (;0 < a.length; ) {
            var b = a.shift();
            if ("function" == typeof b) {
                b();
            } else {
                var c = b.V;
                "number" === typeof c ? b.ha === k ? na("v", c) : na("vi", c, [ b.ha ]) : c(b.ha === k ? m : b.ha);
            }
        }
    }
    var Wa = [], Xa = [], Ya = [], Za = [], $a = [], ab = p;
    function bb(a) {
        Wa.unshift(a);
    }
    s.addOnPreRun = s.Vd = bb;
    s.addOnInit = s.Sd = function(a) {
        Xa.unshift(a);
    };
    s.addOnPreMain = s.Ud = function(a) {
        Ya.unshift(a);
    };
    s.addOnExit = s.Rd = function(a) {
        Za.unshift(a);
    };
    function cb(a) {
        $a.unshift(a);
    }
    s.addOnPostRun = s.Td = cb;
    function J(a, b, c) {
        a = new pa().yb(a);
        c && (a.length = c);
        b || a.push(0);
        return a;
    }
    s.intArrayFromString = J;
    s.intArrayToString = function(a) {
        for (var b = [], c = 0; c < a.length; c++) {
            var d = a[c];
            255 < d && (d &= 255);
            b.push(String.fromCharCode(d));
        }
        return b.join("");
    };
    function Da(a, b, c) {
        a = J(a, c);
        for (c = 0; c < a.length; ) {
            A[b + c | 0] = a[c], c += 1;
        }
    }
    s.writeStringToMemory = Da;
    function Ea(a, b) {
        for (var c = 0; c < a.length; c++) {
            A[b + c | 0] = a[c];
        }
    }
    s.writeArrayToMemory = Ea;
    function db(a, b) {
        return 0 <= a ? a : 32 >= b ? 2 * Math.abs(1 << b - 1) + a : Math.pow(2, b) + a;
    }
    function eb(a, b) {
        if (0 >= a) {
            return a;
        }
        var c = 32 >= b ? Math.abs(1 << b - 1) : Math.pow(2, b - 1);
        if (a >= c && (32 >= b || a > c)) {
            a = -2 * c + a;
        }
        return a;
    }
    Math.imul || (Math.imul = function(a, b) {
        var c = a & 65535, d = b & 65535;
        return c * d + ((a >>> 16) * d + c * (b >>> 16) << 16) | 0;
    });
    Math.ie = Math.imul;
    var L = 0, fb = {}, gb = p, hb = m;
    function ib(a) {
        L++;
        s.monitorRunDependencies && s.monitorRunDependencies(L);
        a ? (w(!fb[a]), fb[a] = 1) : s.P("warning: run dependency added without ID");
    }
    s.addRunDependency = ib;
    function jb(a) {
        L--;
        s.monitorRunDependencies && s.monitorRunDependencies(L);
        a ? (w(fb[a]), delete fb[a]) : s.P("warning: run dependency removed without ID");
        0 == L && (hb !== m && (clearInterval(hb), hb = m), !gb && kb && lb());
    }
    s.removeRunDependency = jb;
    s.preloadedImages = {};
    s.preloadedAudios = {};
    Ra = 8;
    sa = Ra + 1312;
    Xa.push({
        V: function() {
            mb();
        }
    });
    var nb, ob, pb;
    nb = nb = F([ 0, 0, 0, 0, 0, 0, 0, 0 ], "i8", E);
    ob = ob = F([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], "i8", E);
    pb = pb = F([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], "i8", E);
    F([ 111, 112, 116, 105, 111, 110, 32, 114, 101, 113, 117, 105, 114, 101, 115, 32, 97, 110, 32, 97, 114, 103, 117, 109, 101, 110, 116, 32, 45, 45, 32, 37, 115, 0, 0, 0, 0, 0, 0, 0, 111, 112, 116, 105, 111, 110, 32, 114, 101, 113, 117, 105, 114, 101, 115, 32, 97, 110, 32, 97, 114, 103, 117, 109, 101, 110, 116, 32, 45, 45, 32, 37, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 64, 0, 0, 0, 0, 0, 0, 89, 64, 0, 0, 0, 0, 0, 136, 195, 64, 0, 0, 0, 0, 132, 215, 151, 65, 0, 128, 224, 55, 121, 195, 65, 67, 23, 110, 5, 181, 181, 184, 147, 70, 245, 249, 63, 233, 3, 79, 56, 77, 50, 29, 48, 249, 72, 119, 130, 90, 60, 191, 115, 127, 221, 79, 21, 117, 56, 3, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 111, 112, 116, 105, 111, 110, 32, 100, 111, 101, 115, 110, 39, 116, 32, 116, 97, 107, 101, 32, 97, 110, 32, 97, 114, 103, 117, 109, 101, 110, 116, 32, 45, 45, 32, 37, 46, 42, 115, 0, 117, 110, 107, 110, 111, 119, 110, 32, 111, 112, 116, 105, 111, 110, 32, 45, 45, 32, 37, 115, 0, 0, 0, 0, 117, 110, 107, 110, 111, 119, 110, 32, 111, 112, 116, 105, 111, 110, 32, 45, 45, 32, 37, 99, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 97, 109, 98, 105, 103, 117, 111, 117, 115, 32, 111, 112, 116, 105, 111, 110, 32, 45, 45, 32, 37, 46, 42, 115, 0, 0, 0, 0, 0, 0, 0, 0, 37, 115, 58, 32, 0, 0, 0, 0, 80, 79, 83, 73, 88, 76, 89, 95, 67, 79, 82, 82, 69, 67, 84, 0, 115, 116, 100, 58, 58, 98, 97, 100, 95, 97, 108, 108, 111, 99, 0, 0, 37, 115, 58, 32, 0, 0, 0, 0, 37, 115, 10, 0, 0, 0, 0, 0, 37, 115, 10, 0, 0, 0, 0, 0, 105, 110, 32, 117, 115, 101, 32, 98, 121, 116, 101, 115, 32, 32, 32, 32, 32, 61, 32, 37, 49, 48, 108, 117, 10, 0, 0, 0, 0, 0, 0, 0, 37, 115, 58, 32, 0, 0, 0, 0, 37, 115, 58, 32, 0, 0, 0, 0, 98, 97, 100, 95, 97, 114, 114, 97, 121, 95, 110, 101, 119, 95, 108, 101, 110, 103, 116, 104, 0, 0, 0, 0, 58, 32, 0, 0, 0, 0, 0, 0, 58, 32, 0, 0, 0, 0, 0, 0, 115, 121, 115, 116, 101, 109, 32, 98, 121, 116, 101, 115, 32, 32, 32, 32, 32, 61, 32, 37, 49, 48, 108, 117, 10, 0, 0, 0, 0, 0, 0, 0, 109, 97, 120, 32, 115, 121, 115, 116, 101, 109, 32, 98, 121, 116, 101, 115, 32, 61, 32, 37, 49, 48, 108, 117, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 176, 2, 0, 0, 6, 0, 0, 0, 10, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 2, 0, 0, 6, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 116, 57, 101, 120, 99, 101, 112, 116, 105, 111, 110, 0, 0, 0, 0, 83, 116, 57, 98, 97, 100, 95, 97, 108, 108, 111, 99, 0, 0, 0, 0, 83, 116, 50, 48, 98, 97, 100, 95, 97, 114, 114, 97, 121, 95, 110, 101, 119, 95, 108, 101, 110, 103, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 2, 0, 0, 0, 0, 0, 0, 120, 2, 0, 0, 168, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 2, 0, 0, 176, 2, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], "i8", Na, 8);
    var qb = xa(F(12, "i8", E), 8);
    w(0 == qb % 8);
    var rb = 0;
    function M(a) {
        return B[rb >> 2] = a;
    }
    s._memcpy = sb;
    s._memset = tb;
    var N = {
        L: 1,
        ca: 2,
        Bd: 3,
        sc: 4,
        I: 5,
        za: 6,
        Jb: 7,
        Sc: 8,
        $: 9,
        Zb: 10,
        ua: 11,
        Ld: 11,
        $a: 12,
        Ya: 13,
        kc: 14,
        ed: 15,
        Wb: 16,
        va: 17,
        Md: 18,
        wa: 19,
        gd: 20,
        aa: 21,
        A: 22,
        Mc: 23,
        Za: 24,
        ld: 25,
        Id: 26,
        lc: 27,
        ad: 28,
        da: 29,
        yd: 30,
        Fc: 31,
        rd: 32,
        hc: 33,
        ab: 34,
        Wc: 35,
        pc: 36,
        $b: 37,
        vc: 38,
        wc: 39,
        xc: 40,
        Ec: 41,
        Jd: 42,
        Qc: 43,
        uc: 44,
        ec: 45,
        Tc: 46,
        Pb: 50,
        Sb: 51,
        Nd: 52,
        Oc: 53,
        Tb: 54,
        Ub: 55,
        fc: 56,
        Vb: 57,
        cd: 60,
        Rc: 61,
        Fd: 62,
        bd: 63,
        Xc: 64,
        Yc: 65,
        xd: 66,
        Uc: 67,
        Mb: 68,
        Cd: 69,
        ac: 70,
        td: 71,
        Hc: 74,
        yc: 75,
        ic: 76,
        Rb: 77,
        mc: 79,
        md: 80,
        Qb: 81,
        wd: 82,
        zc: 83,
        Ac: 84,
        Dc: 85,
        Cc: 86,
        Bc: 87,
        dd: 88,
        Nc: 89,
        ya: 90,
        Ic: 91,
        ba: 92,
        nd: 95,
        qd: 96,
        dc: 104,
        Pc: 105,
        Nb: 106,
        vd: 107,
        jd: 108,
        Zc: 109,
        zd: 110,
        cc: 111,
        Kb: 112,
        bc: 113,
        Lc: 114,
        Jc: 115,
        Gd: 116,
        nc: 117,
        oc: 118,
        rc: 119,
        Ob: 120,
        gc: 121,
        Gc: 122,
        ud: 123,
        Ad: 124,
        Lb: 125,
        Kc: 126,
        tc: 127,
        fd: 128,
        Hd: 129,
        sd: 130,
        Kd: 131,
        jc: 132,
        Dd: 133,
        kd: 134,
        Vc: 135,
        $c: 136,
        Yb: 137,
        qc: 138,
        od: 139,
        Xb: 140,
        hd: 141,
        pd: 142,
        Ed: 143
    }, ub = {
        "0": "Success",
        1: "Not super-user",
        2: "No such file or directory",
        3: "No such process",
        4: "Interrupted system call",
        5: "I/O error",
        6: "No such device or address",
        7: "Arg list too long",
        8: "Exec format error",
        9: "Bad file number",
        10: "No children",
        11: "No more processes",
        12: "Not enough core",
        13: "Permission denied",
        14: "Bad address",
        15: "Block device required",
        16: "Mount device busy",
        17: "File exists",
        18: "Cross-device link",
        19: "No such device",
        20: "Not a directory",
        21: "Is a directory",
        22: "Invalid argument",
        23: "Too many open files in system",
        24: "Too many open files",
        25: "Not a typewriter",
        26: "Text file busy",
        27: "File too large",
        28: "No space left on device",
        29: "Illegal seek",
        30: "Read only file system",
        31: "Too many links",
        32: "Broken pipe",
        33: "Math arg out of domain of func",
        34: "Math result not representable",
        35: "No message of desired type",
        36: "Identifier removed",
        37: "Channel number out of range",
        38: "Level 2 not synchronized",
        39: "Level 3 halted",
        40: "Level 3 reset",
        41: "Link number out of range",
        42: "Protocol driver not attached",
        43: "No CSI structure available",
        44: "Level 2 halted",
        45: "Deadlock condition",
        46: "No record locks available",
        50: "Invalid exchange",
        51: "Invalid request descriptor",
        52: "Exchange full",
        53: "No anode",
        54: "Invalid request code",
        55: "Invalid slot",
        56: "File locking deadlock error",
        57: "Bad font file fmt",
        60: "Device not a stream",
        61: "No data (for no delay io)",
        62: "Timer expired",
        63: "Out of streams resources",
        64: "Machine is not on the network",
        65: "Package not installed",
        66: "The object is remote",
        67: "The link has been severed",
        68: "Advertise error",
        69: "Srmount error",
        70: "Communication error on send",
        71: "Protocol error",
        74: "Multihop attempted",
        75: "Inode is remote (not really error)",
        76: "Cross mount point (not really error)",
        77: "Trying to read unreadable message",
        79: "Inappropriate file type or format",
        80: "Given log. name not unique",
        81: "f.d. invalid for this operation",
        82: "Remote address changed",
        83: "Can	 access a needed shared lib",
        84: "Accessing a corrupted shared lib",
        85: ".lib section in a.out corrupted",
        86: "Attempting to link in too many libs",
        87: "Attempting to exec a shared library",
        88: "Function not implemented",
        89: "No more files",
        90: "Directory not empty",
        91: "File or path name too long",
        92: "Too many symbolic links",
        95: "Operation not supported on transport endpoint",
        96: "Protocol family not supported",
        104: "Connection reset by peer",
        105: "No buffer space available",
        106: "Address family not supported by protocol family",
        107: "Protocol wrong type for socket",
        108: "Socket operation on non-socket",
        109: "Protocol not available",
        110: "Can't send after socket shutdown",
        111: "Connection refused",
        112: "Address already in use",
        113: "Connection aborted",
        114: "Network is unreachable",
        115: "Network interface is not configured",
        116: "Connection timed out",
        117: "Host is down",
        118: "Host is unreachable",
        119: "Connection already in progress",
        120: "Socket already connected",
        121: "Destination address required",
        122: "Message too long",
        123: "Unknown protocol",
        124: "Socket type not supported",
        125: "Address not available",
        126: "ENETRESET",
        127: "Socket is already connected",
        128: "Socket is not connected",
        129: "TOOMANYREFS",
        130: "EPROCLIM",
        131: "EUSERS",
        132: "EDQUOT",
        133: "ESTALE",
        134: "Not supported",
        135: "No medium (in tape drive)",
        136: "No such host or network path",
        137: "Filename exists with different case",
        138: "EILSEQ",
        139: "Value too large for defined data type",
        140: "Operation canceled",
        141: "State not recoverable",
        142: "Previous owner died",
        143: "Streams pipe error"
    };
    function vb(a, b, c) {
        var d = O(a, {
            parent: l
        }).d, a = "/" === a ? "/" : wb(a)[2], e = xb(d, a);
        e && g(new Q(e));
        d.l.Ta || g(new Q(N.L));
        return d.l.Ta(d, a, b, c);
    }
    function yb(a, b) {
        b = b & 4095 | 32768;
        return vb(a, b, 0);
    }
    function zb(a, b) {
        b = b & 1023 | 16384;
        return vb(a, b, 0);
    }
    function Ab(a, b, c) {
        return vb(a, b | 8192, c);
    }
    function Bb(a, b) {
        var c = O(b, {
            parent: l
        }).d, d = "/" === b ? "/" : wb(b)[2], e = xb(c, d);
        e && g(new Q(e));
        c.l.Wa || g(new Q(N.L));
        return c.l.Wa(c, d, a);
    }
    function Cb(a, b) {
        var c;
        c = "string" === typeof a ? O(a, {
            N: l
        }).d : a;
        c.l.Y || g(new Q(N.L));
        c.l.Y(c, {
            mode: b & 4095 | c.mode & -4096,
            timestamp: Date.now()
        });
    }
    function Db(a, b) {
        var c, a = Eb(a), d;
        "string" === typeof b ? (d = Fb[b], "undefined" === typeof d && g(Error("Unknown file open mode: " + b))) : d = b;
        b = d;
        c = b & 512 ? c & 4095 | 32768 : 0;
        var e;
        try {
            var f = O(a, {
                N: !(b & 65536)
            });
            e = f.d;
            a = f.path;
        } catch (h) {}
        b & 512 && (e ? b & 2048 && g(new Q(N.va)) : e = vb(a, c, 0));
        e || g(new Q(N.ca));
        8192 === (e.mode & 61440) && (b &= -1025);
        e ? 40960 === (e.mode & 61440) ? c = N.ba : 16384 === (e.mode & 61440) && (0 !== (b & 3) || b & 1024) ? c = N.aa : (c = [ "r", "w", "rw" ][b & 3], 
        b & 1024 && (c += "w"), c = Gb(e, c)) : c = N.ca;
        c && g(new Q(c));
        b & 1024 && (c = e, c = "string" === typeof c ? O(c, {
            N: l
        }).d : c, c.l.Y || g(new Q(N.L)), 16384 === (c.mode & 61440) && g(new Q(N.aa)), 
        32768 !== (c.mode & 61440) && g(new Q(N.A)), (f = Gb(c, "w")) && g(new Q(f)), c.l.Y(c, {
            size: 0,
            timestamp: Date.now()
        }));
        var i = {
            path: a,
            d: e,
            M: b,
            seekable: l,
            position: 0,
            e: e.e,
            Gb: [],
            error: p
        }, j;
        a: {
            e = k || 4096;
            for (c = k || 1; c <= e; c++) {
                if (!R[c]) {
                    j = c;
                    break a;
                }
            }
            g(new Q(N.Za));
        }
        i.s = j;
        Object.defineProperty(i, "object", {
            get: function() {
                return i.d;
            },
            set: function(a) {
                i.d = a;
            }
        });
        Object.defineProperty(i, "isRead", {
            get: function() {
                return 1 !== (i.M & 3);
            }
        });
        Object.defineProperty(i, "isWrite", {
            get: function() {
                return 0 !== (i.M & 3);
            }
        });
        Object.defineProperty(i, "isAppend", {
            get: function() {
                return i.M & 8;
            }
        });
        R[j] = i;
        i.e.open && i.e.open(i);
        return i;
    }
    function Hb(a) {
        try {
            a.e.close && a.e.close(a);
        } catch (b) {
            g(b);
        } finally {
            R[a.s] = m;
        }
    }
    function Ib(a, b, c, d, e) {
        (0 > d || 0 > e) && g(new Q(N.A));
        0 === (a.M & 3) && g(new Q(N.$));
        16384 === (a.d.mode & 61440) && g(new Q(N.aa));
        a.e.write || g(new Q(N.A));
        var f = l;
        "undefined" === typeof e ? (e = a.position, f = p) : a.seekable || g(new Q(N.da));
        a.M & 8 && ((!a.seekable || !a.e.na) && g(new Q(N.da)), a.e.na(a, 0, 2));
        b = a.e.write(a, b, c, d, e);
        f || (a.position += b);
        return b;
    }
    function wb(a) {
        return /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(a).slice(1);
    }
    function Jb(a, b) {
        for (var c = 0, d = a.length - 1; 0 <= d; d--) {
            var e = a[d];
            "." === e ? a.splice(d, 1) : ".." === e ? (a.splice(d, 1), c++) : c && (a.splice(d, 1), 
            c--);
        }
        if (b) {
            for (;c--; c) {
                a.unshift("..");
            }
        }
        return a;
    }
    function Eb(a) {
        var b = "/" === a.charAt(0), c = "/" === a.substr(-1), a = Jb(a.split("/").filter(function(a) {
            return !!a;
        }), !b).join("/");
        !a && !b && (a = ".");
        a && c && (a += "/");
        return (b ? "/" : "") + a;
    }
    function S() {
        var a = Array.prototype.slice.call(arguments, 0);
        return Eb(a.filter(function(a) {
            "string" !== typeof a && g(new TypeError("Arguments to path.join must be strings"));
            return a;
        }).join("/"));
    }
    function Kb() {
        for (var a = "", b = p, c = arguments.length - 1; -1 <= c && !b; c--) {
            var d = 0 <= c ? arguments[c] : "/";
            "string" !== typeof d && g(new TypeError("Arguments to path.resolve must be strings"));
            d && (a = d + "/" + a, b = "/" === d.charAt(0));
        }
        a = Jb(a.split("/").filter(function(a) {
            return !!a;
        }), !b).join("/");
        return (b ? "/" : "") + a || ".";
    }
    var Lb = [];
    function Mb(a, b) {
        Lb[a] = {
            input: [],
            H: [],
            O: b
        };
        Nb[a] = {
            e: Ob
        };
    }
    var Ob = {
        open: function(a) {
            Pb || (Pb = new pa());
            var b = Lb[a.d.X];
            b || g(new Q(N.wa));
            a.q = b;
            a.seekable = p;
        },
        close: function(a) {
            a.q.H.length && a.q.O.W(a.q, 10);
        },
        Q: function(a, b, c, d) {
            (!a.q || !a.q.O.Na) && g(new Q(N.za));
            for (var e = 0, f = 0; f < d; f++) {
                var h;
                try {
                    h = a.q.O.Na(a.q);
                } catch (i) {
                    g(new Q(N.I));
                }
                h === k && 0 === e && g(new Q(N.ua));
                if (h === m || h === k) {
                    break;
                }
                e++;
                b[c + f] = h;
            }
            e && (a.d.timestamp = Date.now());
            return e;
        },
        write: function(a, b, c, d) {
            (!a.q || !a.q.O.W) && g(new Q(N.za));
            for (var e = 0; e < d; e++) {
                try {
                    a.q.O.W(a.q, b[c + e]);
                } catch (f) {
                    g(new Q(N.I));
                }
            }
            d && (a.d.timestamp = Date.now());
            return e;
        }
    }, Pb, T = {
        z: function() {
            return T.ka(m, "/", 16895, 0);
        },
        ka: function(a, b, c, d) {
            (24576 === (c & 61440) || 4096 === (c & 61440)) && g(new Q(N.L));
            c = Qb(a, b, c, d);
            c.l = T.l;
            16384 === (c.mode & 61440) ? (c.e = T.e, c.g = {}) : 32768 === (c.mode & 61440) ? (c.e = T.e, 
            c.g = []) : 40960 === (c.mode & 61440) ? c.e = T.e : 8192 === (c.mode & 61440) && (c.e = Rb);
            c.timestamp = Date.now();
            a && (a.g[b] = c);
            return c;
        },
        l: {
            ge: function(a) {
                var b = {};
                b.ce = 8192 === (a.mode & 61440) ? a.id : 1;
                b.je = a.id;
                b.mode = a.mode;
                b.pe = 1;
                b.uid = 0;
                b.he = 0;
                b.X = a.X;
                b.size = 16384 === (a.mode & 61440) ? 4096 : 32768 === (a.mode & 61440) ? a.g.length : 40960 === (a.mode & 61440) ? a.link.length : 0;
                b.Yd = new Date(a.timestamp);
                b.oe = new Date(a.timestamp);
                b.ae = new Date(a.timestamp);
                b.ib = 4096;
                b.Zd = Math.ceil(b.size / b.ib);
                return b;
            },
            Y: function(a, b) {
                b.mode !== k && (a.mode = b.mode);
                b.timestamp !== k && (a.timestamp = b.timestamp);
                if (b.size !== k) {
                    var c = a.g;
                    if (b.size < c.length) {
                        c.length = b.size;
                    } else {
                        for (;b.size > c.length; ) {
                            c.push(0);
                        }
                    }
                }
            },
            tb: function() {
                g(new Q(N.ca));
            },
            Ta: function(a, b, c, d) {
                return T.ka(a, b, c, d);
            },
            rename: function(a, b, c) {
                if (16384 === (a.mode & 61440)) {
                    var d;
                    try {
                        d = Sb(b, c);
                    } catch (e) {}
                    if (d) {
                        for (var f in d.g) {
                            g(new Q(N.ya));
                        }
                    }
                }
                delete a.parent.g[a.name];
                a.name = c;
                b.g[c] = a;
            },
            ze: function(a, b) {
                delete a.g[b];
            },
            ve: function(a, b) {
                var c = Sb(a, b), d;
                for (d in c.g) {
                    g(new Q(N.ya));
                }
                delete a.g[b];
            },
            Wa: function(a, b, c) {
                a = T.ka(a, b, 41471, 0);
                a.link = c;
                return a;
            },
            Va: function(a) {
                40960 !== (a.mode & 61440) && g(new Q(N.A));
                return a.link;
            }
        },
        e: {
            open: function(a) {
                if (16384 === (a.d.mode & 61440)) {
                    var b = [ ".", ".." ], c;
                    for (c in a.d.g) {
                        a.d.g.hasOwnProperty(c) && b.push(c);
                    }
                    a.lb = b;
                }
            },
            Q: function(a, b, c, d, e) {
                a = a.d.g;
                d = Math.min(a.length - e, d);
                if (a.subarray) {
                    b.set(a.subarray(e, e + d), c);
                } else {
                    for (var f = 0; f < d; f++) {
                        b[c + f] = a[e + f];
                    }
                }
                return d;
            },
            write: function(a, b, c, d, e) {
                for (var f = a.d.g; f.length < e; ) {
                    f.push(0);
                }
                for (var h = 0; h < d; h++) {
                    f[e + h] = b[c + h];
                }
                a.d.timestamp = Date.now();
                return d;
            },
            na: function(a, b, c) {
                1 === c ? b += a.position : 2 === c && 32768 === (a.d.mode & 61440) && (b += a.d.g.length);
                0 > b && g(new Q(N.A));
                a.Gb = [];
                return a.position = b;
            },
            ue: function(a) {
                return a.lb;
            },
            Wd: function(a, b, c) {
                a = a.d.g;
                for (b += c; b > a.length; ) {
                    a.push(0);
                }
            },
            ne: function(a, b, c, d, e, f, h) {
                32768 !== (a.d.mode & 61440) && g(new Q(N.wa));
                a = a.d.g;
                if (h & 2) {
                    if (0 < e || e + d < a.length) {
                        a = a.subarray ? a.subarray(e, e + d) : Array.prototype.slice.call(a, e, e + d);
                    }
                    e = l;
                    (d = Oa(d)) || g(new Q(N.$a));
                    b.set(a, d);
                } else {
                    w(a.buffer === b || a.buffer === b.buffer), e = p, d = a.byteOffset;
                }
                return {
                    te: d,
                    Xd: e
                };
            }
        }
    }, Tb = F(1, "i32*", E), Ub = F(1, "i32*", E);
    nb = F(1, "i32*", E);
    var Vb = m, Nb = [ m ], R = [ m ], Wb = 1, Xb = [ , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , ,  ], Yb = l;
    function Q(a) {
        this.mb = a;
        for (var b in N) {
            if (N[b] === a) {
                this.code = b;
                break;
            }
        }
        this.message = ub[a];
    }
    function Zb(a) {
        a instanceof Q || g(a + " : " + Error().stack);
        M(a.mb);
    }
    function $b(a, b) {
        for (var c = 0, d = 0; d < b.length; d++) {
            c = (c << 5) - c + b.charCodeAt(d) | 0;
        }
        return (a + c) % Xb.length;
    }
    function Sb(a, b) {
        var c = Gb(a, "x");
        c && g(new Q(c));
        for (c = Xb[$b(a.id, b)]; c; c = c.wb) {
            if (c.parent.id === a.id && c.name === b) {
                return c;
            }
        }
        return a.l.tb(a, b);
    }
    function Qb(a, b, c, d) {
        var e = {
            id: Wb++,
            name: b,
            mode: c,
            l: {},
            e: {},
            X: d,
            parent: m,
            z: m
        };
        a || (a = e);
        e.parent = a;
        e.z = a.z;
        Object.defineProperty(e, "read", {
            get: function() {
                return 365 === (e.mode & 365);
            },
            set: function(a) {
                a ? e.mode |= 365 : e.mode &= -366;
            }
        });
        Object.defineProperty(e, "write", {
            get: function() {
                return 146 === (e.mode & 146);
            },
            set: function(a) {
                a ? e.mode |= 146 : e.mode &= -147;
            }
        });
        a = $b(e.parent.id, e.name);
        e.wb = Xb[a];
        return Xb[a] = e;
    }
    function O(a, b) {
        a = Kb("/", a);
        b = b || {
            pa: 0
        };
        8 < b.pa && g(new Q(N.ba));
        for (var c = Jb(a.split("/").filter(function(a) {
            return !!a;
        }), p), d = Vb, e = "/", f = 0; f < c.length; f++) {
            var h = f === c.length - 1;
            if (h && b.parent) {
                break;
            }
            d = Sb(d, c[f]);
            e = S(e, c[f]);
            d.ub && (d = d.z.root);
            if (!h || b.N) {
                for (h = 0; 40960 === (d.mode & 61440); ) {
                    d = O(e, {
                        N: p
                    }).d;
                    d.l.Va || g(new Q(N.A));
                    var d = d.l.Va(d), i = Kb;
                    var j = wb(e), e = j[0], j = j[1];
                    !e && !j ? e = "." : (j && (j = j.substr(0, j.length - 1)), e += j);
                    e = i(e, d);
                    d = O(e, {
                        pa: b.pa
                    }).d;
                    40 < h++ && g(new Q(N.ba));
                }
            }
        }
        return {
            path: e,
            d: d
        };
    }
    function ac(a) {
        for (var b; ;) {
            if (a === a.parent) {
                return b ? S(a.z.Ua, b) : a.z.Ua;
            }
            b = b ? S(a.name, b) : a.name;
            a = a.parent;
        }
    }
    var Fb = {
        r: 0,
        rs: 8192,
        "r+": 2,
        w: 1537,
        wx: 3585,
        xw: 3585,
        "w+": 1538,
        "wx+": 3586,
        "xw+": 3586,
        a: 521,
        ax: 2569,
        xa: 2569,
        "a+": 522,
        "ax+": 2570,
        "xa+": 2570
    };
    function Gb(a, b) {
        return Yb ? 0 : -1 !== b.indexOf("r") && !(a.mode & 292) || -1 !== b.indexOf("w") && !(a.mode & 146) || -1 !== b.indexOf("x") && !(a.mode & 73) ? N.Ya : 0;
    }
    function xb(a, b) {
        try {
            return Sb(a, b), N.va;
        } catch (c) {}
        return Gb(a, "wx");
    }
    var Rb = {
        open: function(a) {
            a.e = Nb[a.d.X].e;
            a.e.open && a.e.open(a);
        },
        na: function() {
            g(new Q(N.da));
        }
    }, bc;
    function cc(a, b) {
        var c = 0;
        a && (c |= 365);
        b && (c |= 146);
        return c;
    }
    function dc(a, b, c, d, e) {
        a = S("string" === typeof a ? a : ac(a), b);
        d = cc(d, e);
        e = yb(a, d);
        if (c) {
            if ("string" === typeof c) {
                for (var b = Array(c.length), f = 0, h = c.length; f < h; ++f) {
                    b[f] = c.charCodeAt(f);
                }
                c = b;
            }
            Cb(a, d | 146);
            b = Db(a, "w");
            Ib(b, c, 0, c.length, 0);
            Hb(b);
            Cb(a, d);
        }
        return e;
    }
    function ec(a, b, c, d) {
        a = S("string" === typeof a ? a : ac(a), b);
        ec.Sa || (ec.Sa = 64);
        b = ec.Sa++ << 8 | 0;
        Nb[b] = {
            e: {
                open: function(a) {
                    a.seekable = p;
                },
                close: function() {
                    d && d.buffer && d.buffer.length && d(10);
                },
                Q: function(a, b, d, i) {
                    for (var j = 0, n = 0; n < i; n++) {
                        var y;
                        try {
                            y = c();
                        } catch (v) {
                            g(new Q(N.I));
                        }
                        y === k && 0 === j && g(new Q(N.ua));
                        if (y === m || y === k) {
                            break;
                        }
                        j++;
                        b[d + n] = y;
                    }
                    j && (a.d.timestamp = Date.now());
                    return j;
                },
                write: function(a, b, c, i) {
                    for (var j = 0; j < i; j++) {
                        try {
                            d(b[c + j]);
                        } catch (n) {
                            g(new Q(N.I));
                        }
                    }
                    i && (a.d.timestamp = Date.now());
                    return j;
                }
            }
        };
        return Ab(a, c && d ? 511 : c ? 219 : 365, b);
    }
    function fc(a, b, c) {
        a = R[a];
        if (!a) {
            return -1;
        }
        a.sender(G.subarray(b, b + c));
        return c;
    }
    function gc(a, b, c) {
        var d = R[a];
        if (!d) {
            return M(N.$), -1;
        }
        if (d && "socket" in d) {
            return fc(a, b, c);
        }
        try {
            return Ib(d, A, b, c);
        } catch (e) {
            return Zb(e), -1;
        }
    }
    function hc(a, b, c, d) {
        c *= b;
        if (0 == c) {
            return 0;
        }
        a = gc(d, a, c);
        if (-1 == a) {
            if (b = R[d]) {
                b.error = l;
            }
            return 0;
        }
        return Math.floor(a / b);
    }
    s._strlen = ic;
    function jc(a) {
        return 0 > a || 0 === a && -Infinity === 1 / a;
    }
    function kc(a, b) {
        function c(a) {
            var c;
            "double" === a ? c = Ja[b + e >> 3] : "i64" == a ? (c = [ B[b + e >> 2], B[b + (e + 8) >> 2] ], 
            e += 8) : (a = "i32", c = B[b + e >> 2]);
            e += Math.max(Math.max(la(a), ma), 8);
            return c;
        }
        for (var d = a, e = 0, f = [], h, i; ;) {
            var j = d;
            h = A[d];
            if (0 === h) {
                break;
            }
            i = A[d + 1 | 0];
            if (37 == h) {
                var n = p, y = p, v = p, C = p;
                a: for (;;) {
                    switch (i) {
                      case 43:
                        n = l;
                        break;

                      case 45:
                        y = l;
                        break;

                      case 35:
                        v = l;
                        break;

                      case 48:
                        if (C) {
                            break a;
                        } else {
                            C = l;
                            break;
                        }
                        ;

                      default:
                        break a;
                    }
                    d++;
                    i = A[d + 1 | 0];
                }
                var D = 0;
                if (42 == i) {
                    D = c("i32"), d++, i = A[d + 1 | 0];
                } else {
                    for (;48 <= i && 57 >= i; ) {
                        D = 10 * D + (i - 48), d++, i = A[d + 1 | 0];
                    }
                }
                var K = p;
                if (46 == i) {
                    var H = 0, K = l;
                    d++;
                    i = A[d + 1 | 0];
                    if (42 == i) {
                        H = c("i32"), d++;
                    } else {
                        for (;;) {
                            i = A[d + 1 | 0];
                            if (48 > i || 57 < i) {
                                break;
                            }
                            H = 10 * H + (i - 48);
                            d++;
                        }
                    }
                    i = A[d + 1 | 0];
                } else {
                    H = 6;
                }
                var x;
                switch (String.fromCharCode(i)) {
                  case "h":
                    i = A[d + 2 | 0];
                    104 == i ? (d++, x = 1) : x = 2;
                    break;

                  case "l":
                    i = A[d + 2 | 0];
                    108 == i ? (d++, x = 8) : x = 4;
                    break;

                  case "L":
                    ;

                  case "q":
                    ;

                  case "j":
                    x = 8;
                    break;

                  case "z":
                    ;

                  case "t":
                    ;

                  case "I":
                    x = 4;
                    break;

                  default:
                    x = m;
                }
                x && d++;
                i = A[d + 1 | 0];
                switch (String.fromCharCode(i)) {
                  case "d":
                    ;

                  case "i":
                    ;

                  case "u":
                    ;

                  case "o":
                    ;

                  case "x":
                    ;

                  case "X":
                    ;

                  case "p":
                    j = 100 == i || 105 == i;
                    x = x || 4;
                    var P = h = c("i" + 8 * x), r;
                    8 == x && (h = 117 == i ? +(h[0] >>> 0) + 4294967296 * +(h[1] >>> 0) : +(h[0] >>> 0) + 4294967296 * +(h[1] | 0));
                    4 >= x && (h = (j ? eb : db)(h & Math.pow(256, x) - 1, 8 * x));
                    var ta = Math.abs(h), j = "";
                    if (100 == i || 105 == i) {
                        r = 8 == x && lc ? lc.stringify(P[0], P[1], m) : eb(h, 8 * x).toString(10);
                    } else {
                        if (117 == i) {
                            r = 8 == x && lc ? lc.stringify(P[0], P[1], l) : db(h, 8 * x).toString(10), h = Math.abs(h);
                        } else {
                            if (111 == i) {
                                r = (v ? "0" : "") + ta.toString(8);
                            } else {
                                if (120 == i || 88 == i) {
                                    j = v && 0 != h ? "0x" : "";
                                    if (8 == x && lc) {
                                        if (P[1]) {
                                            r = (P[1] >>> 0).toString(16);
                                            for (v = (P[0] >>> 0).toString(16); 8 > v.length; ) {
                                                v = "0" + v;
                                            }
                                            r += v;
                                        } else {
                                            r = (P[0] >>> 0).toString(16);
                                        }
                                    } else {
                                        if (0 > h) {
                                            h = -h;
                                            r = (ta - 1).toString(16);
                                            P = [];
                                            for (v = 0; v < r.length; v++) {
                                                P.push((15 - parseInt(r[v], 16)).toString(16));
                                            }
                                            for (r = P.join(""); r.length < 2 * x; ) {
                                                r = "f" + r;
                                            }
                                        } else {
                                            r = ta.toString(16);
                                        }
                                    }
                                    88 == i && (j = j.toUpperCase(), r = r.toUpperCase());
                                } else {
                                    112 == i && (0 === ta ? r = "(nil)" : (j = "0x", r = ta.toString(16)));
                                }
                            }
                        }
                    }
                    if (K) {
                        for (;r.length < H; ) {
                            r = "0" + r;
                        }
                    }
                    for (n && (j = 0 > h ? "-" + j : "+" + j); j.length + r.length < D; ) {
                        y ? r += " " : C ? r = "0" + r : j = " " + j;
                    }
                    r = j + r;
                    r.split("").forEach(function(a) {
                        f.push(a.charCodeAt(0));
                    });
                    break;

                  case "f":
                    ;

                  case "F":
                    ;

                  case "e":
                    ;

                  case "E":
                    ;

                  case "g":
                    ;

                  case "G":
                    h = c("double");
                    if (isNaN(h)) {
                        r = "nan", C = p;
                    } else {
                        if (isFinite(h)) {
                            K = p;
                            x = Math.min(H, 20);
                            if (103 == i || 71 == i) {
                                K = l, H = H || 1, x = parseInt(h.toExponential(x).split("e")[1], 10), H > x && -4 <= x ? (i = (103 == i ? "f" : "F").charCodeAt(0), 
                                H -= x + 1) : (i = (103 == i ? "e" : "E").charCodeAt(0), H--), x = Math.min(H, 20);
                            }
                            if (101 == i || 69 == i) {
                                r = h.toExponential(x), /[eE][-+]\d$/.test(r) && (r = r.slice(0, -1) + "0" + r.slice(-1));
                            } else {
                                if (102 == i || 70 == i) {
                                    r = h.toFixed(x), 0 === h && jc(h) && (r = "-" + r);
                                }
                            }
                            j = r.split("e");
                            if (K && !v) {
                                for (;1 < j[0].length && -1 != j[0].indexOf(".") && ("0" == j[0].slice(-1) || "." == j[0].slice(-1)); ) {
                                    j[0] = j[0].slice(0, -1);
                                }
                            } else {
                                for (v && -1 == r.indexOf(".") && (j[0] += "."); H > x++; ) {
                                    j[0] += "0";
                                }
                            }
                            r = j[0] + (1 < j.length ? "e" + j[1] : "");
                            69 == i && (r = r.toUpperCase());
                            n && 0 <= h && (r = "+" + r);
                        } else {
                            r = (0 > h ? "-" : "") + "inf", C = p;
                        }
                    }
                    for (;r.length < D; ) {
                        r = y ? r + " " : C && ("-" == r[0] || "+" == r[0]) ? r[0] + "0" + r.slice(1) : (C ? "0" : " ") + r;
                    }
                    97 > i && (r = r.toUpperCase());
                    r.split("").forEach(function(a) {
                        f.push(a.charCodeAt(0));
                    });
                    break;

                  case "s":
                    C = (n = c("i8*")) ? ic(n) : 6;
                    K && (C = Math.min(C, H));
                    if (!y) {
                        for (;C < D--; ) {
                            f.push(32);
                        }
                    }
                    if (n) {
                        for (v = 0; v < C; v++) {
                            f.push(G[n++ | 0]);
                        }
                    } else {
                        f = f.concat(J("(null)".substr(0, C), l));
                    }
                    if (y) {
                        for (;C < D--; ) {
                            f.push(32);
                        }
                    }
                    break;

                  case "c":
                    for (y && f.push(c("i8")); 0 < --D; ) {
                        f.push(32);
                    }
                    y || f.push(c("i8"));
                    break;

                  case "n":
                    y = c("i32*");
                    B[y >> 2] = f.length;
                    break;

                  case "%":
                    f.push(h);
                    break;

                  default:
                    for (v = j; v < d + 2; v++) {
                        f.push(A[v]);
                    }
                }
                d += 2;
            } else {
                f.push(h), d += 1;
            }
        }
        return f;
    }
    function mc(a, b, c) {
        c = kc(b, c);
        b = ja();
        a = hc(F(c, "i8", La), 1, c.length, a);
        ka(b);
        return a;
    }
    function nc(a) {
        nc.ia || (z = z + 4095 >> 12 << 12, nc.ia = l, w(ua), nc.hb = ua, ua = function() {
            wa("cannot dynamically allocate, sbrk now has control");
        });
        var b = z;
        0 != a && nc.hb(a);
        return b;
    }
    function U() {
        return B[U.m >> 2];
    }
    function oc() {
        return !!oc.ta;
    }
    function pc(a) {
        var b = p;
        try {
            a == __ZTIi && (b = l);
        } catch (c) {}
        try {
            a == __ZTIj && (b = l);
        } catch (d) {}
        try {
            a == __ZTIl && (b = l);
        } catch (e) {}
        try {
            a == __ZTIm && (b = l);
        } catch (f) {}
        try {
            a == __ZTIx && (b = l);
        } catch (h) {}
        try {
            a == __ZTIy && (b = l);
        } catch (i) {}
        try {
            a == __ZTIf && (b = l);
        } catch (j) {}
        try {
            a == __ZTId && (b = l);
        } catch (n) {}
        try {
            a == __ZTIe && (b = l);
        } catch (y) {}
        try {
            a == __ZTIc && (b = l);
        } catch (v) {}
        try {
            a == __ZTIa && (b = l);
        } catch (C) {}
        try {
            a == __ZTIh && (b = l);
        } catch (D) {}
        try {
            a == __ZTIs && (b = l);
        } catch (K) {}
        try {
            a == __ZTIt && (b = l);
        } catch (H) {}
        return b;
    }
    function qc(a, b, c) {
        if (0 == c) {
            return p;
        }
        if (0 == b || b == a) {
            return l;
        }
        switch (pc(b) ? b : B[B[b >> 2] - 8 >> 2]) {
          case 0:
            return 0 == B[B[a >> 2] - 8 >> 2] ? qc(B[a + 8 >> 2], B[b + 8 >> 2], c) : p;

          case 1:
            return p;

          case 2:
            return qc(a, B[b + 8 >> 2], c);

          default:
            return p;
        }
    }
    function rc(a, b, c) {
        if (!rc.sb) {
            try {
                B[__ZTVN10__cxxabiv119__pointer_type_infoE >> 2] = 0;
            } catch (d) {}
            try {
                B[pb >> 2] = 1;
            } catch (e) {}
            try {
                B[ob >> 2] = 2;
            } catch (f) {}
            rc.sb = l;
        }
        B[U.m >> 2] = a;
        B[U.m + 4 >> 2] = b;
        B[U.m + 8 >> 2] = c;
        "uncaught_exception" in oc ? oc.ta++ : oc.ta = 1;
        g(a + " - Exception catching is disabled, this exception cannot be caught. Compile with -s DISABLE_EXCEPTION_CATCHING=0 or DISABLE_EXCEPTION_CATCHING=2 to catch.");
    }
    function sc(a) {
        try {
            return tc(a);
        } catch (b) {}
    }
    function uc() {
        if (uc.Bb) {
            uc.Bb = p;
        } else {
            V.setThrew(0);
            B[U.m + 4 >> 2] = 0;
            var a = B[U.m >> 2], b = B[U.m + 8 >> 2];
            b && (na("vi", b, [ a ]), B[U.m + 8 >> 2] = 0);
            a && (sc(a), B[U.m >> 2] = 0);
        }
    }
    var vc = F(1, "i32*", E);
    function wc(a) {
        var b, c;
        wc.ia ? (c = B[vc >> 2], b = B[c >> 2]) : (wc.ia = l, W.USER = "root", W.PATH = "/", 
        W.PWD = "/", W.HOME = "/home/emscripten", W.LANG = "en_US.UTF-8", W._ = "./this.program", 
        b = F(1024, "i8", E), c = F(256, "i8*", E), B[c >> 2] = b, B[vc >> 2] = c);
        var d = [], e = 0, f;
        for (f in a) {
            if ("string" === typeof a[f]) {
                var h = f + "=" + a[f];
                d.push(h);
                e += h.length;
            }
        }
        1024 < e && g(Error("Environment size exceeded TOTAL_ENV_SIZE!"));
        for (a = 0; a < d.length; a++) {
            h = d[a];
            for (e = 0; e < h.length; e++) {
                A[b + e | 0] = h.charCodeAt(e);
            }
            A[b + e | 0] = 0;
            B[c + 4 * a >> 2] = b;
            b += h.length + 1;
        }
        B[c + 4 * d.length >> 2] = 0;
    }
    var W = {};
    function xc(a) {
        if (0 === a) {
            return 0;
        }
        a = Fa(a);
        if (!W.hasOwnProperty(a)) {
            return 0;
        }
        xc.J && tc(xc.J);
        xc.J = F(J(W[a]), "i8", Ka);
        return xc.J;
    }
    function yc(a, b, c) {
        if (a in ub) {
            if (ub[a].length > c - 1) {
                return M(N.ab);
            }
            a = ub[a];
            for (c = 0; c < a.length; c++) {
                A[b + c | 0] = a.charCodeAt(c);
            }
            return A[b + c | 0] = 0;
        }
        return M(N.A);
    }
    function zc(a) {
        zc.buffer || (zc.buffer = Oa(256));
        yc(a, zc.buffer, 256);
        return zc.buffer;
    }
    function Ac(a) {
        s.exit(a);
    }
    function Bc(a, b) {
        var c = db(a & 255);
        A[Bc.J | 0] = c;
        if (-1 == gc(b, Bc.J, 1)) {
            if (c = R[b]) {
                c.error = l;
            }
            return -1;
        }
        return c;
    }
    var Cc = p, Dc = p, Ec = p, Fc = p, Gc = k, Hc = k;
    function Ic(a) {
        return {
            jpg: "image/jpeg",
            jpeg: "image/jpeg",
            png: "image/png",
            bmp: "image/bmp",
            ogg: "audio/ogg",
            wav: "audio/wav",
            mp3: "audio/mpeg"
        }[a.substr(a.lastIndexOf(".") + 1)];
    }
    var Jc = [];
    function Kc() {
        var a = s.canvas;
        Jc.forEach(function(b) {
            b(a.width, a.height);
        });
    }
    function Lc() {
        var a = s.canvas;
        this.Ib = a.width;
        this.Hb = a.height;
        a.width = screen.width;
        a.height = screen.height;
        "undefined" != typeof SDL && (a = Qa[SDL.screen + 0 * ma >> 2], B[SDL.screen + 0 * ma >> 2] = a | 8388608);
        Kc();
    }
    function Mc() {
        var a = s.canvas;
        a.width = this.Ib;
        a.height = this.Hb;
        "undefined" != typeof SDL && (a = Qa[SDL.screen + 0 * ma >> 2], B[SDL.screen + 0 * ma >> 2] = a & -8388609);
        Kc();
    }
    var Nc, Oc, Pc, Qc, rb = ra(4);
    B[rb >> 2] = 0;
    var Vb = Qb(m, "/", 16895, 0), Rc = T, Sc = {
        type: Rc,
        se: {},
        Ua: "/",
        root: m
    }, Tc;
    Tc = O("/", {
        N: p
    });
    var Uc = Rc.z(Sc);
    Uc.z = Sc;
    Sc.root = Uc;
    Tc && (Tc.d.z = Sc, Tc.d.ub = l, Vb = Sc.root);
    zb("/tmp", 511);
    zb("/dev", 511);
    Nb[259] = {
        e: {
            Q: function() {
                return 0;
            },
            write: function() {
                return 0;
            }
        }
    };
    Ab("/dev/null", 438, 259);
    Mb(1280, {
        Na: function(a) {
            if (!a.input.length) {
                var b = m;
                if (ca) {
                    if (process.Eb.be) {
                        return;
                    }
                    b = process.Eb.Q();
                } else {
                    "undefined" != typeof window && "function" == typeof window.prompt ? (b = window.prompt("Input: "), 
                    b !== m && (b += "\n")) : "function" == typeof readline && (b = readline(), b !== m && (b += "\n"));
                }
                if (!b) {
                    return m;
                }
                a.input = J(b, l);
            }
            return a.input.shift();
        },
        W: function(a, b) {
            b === m || 10 === b ? (s.print(a.H.join("")), a.H = []) : a.H.push(Pb.oa(b));
        }
    });
    Mb(1536, {
        W: function(a, b) {
            b === m || 10 === b ? (s.printErr(a.H.join("")), a.H = []) : a.H.push(Pb.oa(b));
        }
    });
    Ab("/dev/tty", 438, 1280);
    Ab("/dev/tty1", 438, 1536);
    zb("/dev/shm", 511);
    zb("/dev/shm/tmp", 511);
    Xa.unshift({
        V: function() {
            if (!s.noFSInit && !bc) {
                w(!bc, "FS.init was previously called. If you want to initialize later with custom parameters, remove any earlier calls (note that one is automatically added to the generated code)");
                bc = l;
                s.stdin = s.stdin;
                s.stdout = s.stdout;
                s.stderr = s.stderr;
                s.stdin ? ec("/dev", "stdin", s.stdin) : Bb("/dev/tty", "/dev/stdin");
                s.stdout ? ec("/dev", "stdout", m, s.stdout) : Bb("/dev/tty", "/dev/stdout");
                s.stderr ? ec("/dev", "stderr", m, s.stderr) : Bb("/dev/tty1", "/dev/stderr");
                var a = Db("/dev/stdin", "r");
                B[Tb >> 2] = a.s;
                w(1 === a.s, "invalid handle for stdin (" + a.s + ")");
                a = Db("/dev/stdout", "w");
                B[Ub >> 2] = a.s;
                w(2 === a.s, "invalid handle for stdout (" + a.s + ")");
                a = Db("/dev/stderr", "w");
                B[nb >> 2] = a.s;
                w(3 === a.s, "invalid handle for stderr (" + a.s + ")");
            }
        }
    });
    Ya.push({
        V: function() {
            Yb = p;
        }
    });
    Za.push({
        V: function() {
            bc = p;
            for (var a = 0; a < R.length; a++) {
                var b = R[a];
                b && Hb(b);
            }
        }
    });
    s.FS_createFolder = function(a, b, c, d) {
        a = S("string" === typeof a ? a : ac(a), b);
        return zb(a, cc(c, d));
    };
    s.FS_createPath = function(a, b) {
        for (var a = "string" === typeof a ? a : ac(a), c = b.split("/").reverse(); c.length; ) {
            var d = c.pop();
            if (d) {
                var e = S(a, d);
                try {
                    zb(e, 511);
                } catch (f) {}
                a = e;
            }
        }
        return e;
    };
    s.FS_createDataFile = dc;
    s.FS_createPreloadedFile = function(a, b, c, d, e, f, h, i) {
        function j() {
            Ec = document.pointerLockElement === v || document.mozPointerLockElement === v || document.webkitPointerLockElement === v;
        }
        function n(c) {
            function j(c) {
                i || dc(a, b, c, d, e);
                f && f();
                jb("cp " + C);
            }
            var n = p;
            s.preloadPlugins.forEach(function(a) {
                !n && a.canHandle(C) && (a.handle(c, C, j, function() {
                    h && h();
                    jb("cp " + C);
                }), n = l);
            });
            n || j(c);
        }
        s.preloadPlugins || (s.preloadPlugins = []);
        if (!Nc && !ea) {
            Nc = l;
            try {
                new Blob(), Oc = l;
            } catch (y) {
                Oc = p, console.log("warning: no blob constructor, cannot create blobs with mimetypes");
            }
            Pc = "undefined" != typeof MozBlobBuilder ? MozBlobBuilder : "undefined" != typeof WebKitBlobBuilder ? WebKitBlobBuilder : !Oc ? console.log("warning: no BlobBuilder") : m;
            Qc = "undefined" != typeof window ? window.URL ? window.URL : window.webkitURL : console.log("warning: cannot create object URLs");
            s.preloadPlugins.push({
                canHandle: function(a) {
                    return !s.re && /\.(jpg|jpeg|png|bmp)$/i.test(a);
                },
                handle: function(a, b, c, d) {
                    var e = m;
                    if (Oc) {
                        try {
                            e = new Blob([ a ], {
                                type: Ic(b)
                            }), e.size !== a.length && (e = new Blob([ new Uint8Array(a).buffer ], {
                                type: Ic(b)
                            }));
                        } catch (f) {
                            var h = "Blob constructor present but fails: " + f + "; falling back to blob builder";
                            oa || (oa = {});
                            oa[h] || (oa[h] = 1, s.P(h));
                        }
                    }
                    e || (e = new Pc(), e.append(new Uint8Array(a).buffer), e = e.getBlob());
                    var i = Qc.createObjectURL(e), j = new Image();
                    j.onload = function() {
                        w(j.complete, "Image " + b + " could not be decoded");
                        var d = document.createElement("canvas");
                        d.width = j.width;
                        d.height = j.height;
                        d.getContext("2d").drawImage(j, 0, 0);
                        s.preloadedImages[b] = d;
                        Qc.revokeObjectURL(i);
                        c && c(a);
                    };
                    j.onerror = function() {
                        console.log("Image " + i + " could not be decoded");
                        d && d();
                    };
                    j.src = i;
                }
            });
            s.preloadPlugins.push({
                canHandle: function(a) {
                    return !s.qe && a.substr(-4) in {
                        ".ogg": 1,
                        ".wav": 1,
                        ".mp3": 1
                    };
                },
                handle: function(a, b, c, d) {
                    function e(d) {
                        h || (h = l, s.preloadedAudios[b] = d, c && c(a));
                    }
                    function f() {
                        h || (h = l, s.preloadedAudios[b] = new Audio(), d && d());
                    }
                    var h = p;
                    if (Oc) {
                        try {
                            var i = new Blob([ a ], {
                                type: Ic(b)
                            });
                        } catch (j) {
                            return f();
                        }
                        var i = Qc.createObjectURL(i), n = new Audio();
                        n.addEventListener("canplaythrough", function() {
                            e(n);
                        }, p);
                        n.onerror = function() {
                            if (!h) {
                                console.log("warning: browser could not fully decode audio " + b + ", trying slower base64 approach");
                                for (var c = "", d = 0, f = 0, i = 0; i < a.length; i++) {
                                    d = d << 8 | a[i];
                                    for (f += 8; 6 <= f; ) {
                                        var j = d >> f - 6 & 63, f = f - 6, c = c + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[j];
                                    }
                                }
                                2 == f ? (c += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(d & 3) << 4], 
                                c += "==") : 4 == f && (c += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(d & 15) << 2], 
                                c += "=");
                                n.src = "data:audio/x-" + b.substr(-3) + ";base64," + c;
                                e(n);
                            }
                        };
                        n.src = i;
                        setTimeout(function() {
                            za || e(n);
                        }, 1e4);
                    } else {
                        return f();
                    }
                }
            });
            var v = s.canvas;
            v.qa = v.requestPointerLock || v.mozRequestPointerLock || v.webkitRequestPointerLock;
            v.La = document.exitPointerLock || document.mozExitPointerLock || document.webkitExitPointerLock || aa();
            v.La = v.La.bind(document);
            document.addEventListener("pointerlockchange", j, p);
            document.addEventListener("mozpointerlockchange", j, p);
            document.addEventListener("webkitpointerlockchange", j, p);
            s.elementPointerLock && v.addEventListener("click", function(a) {
                !Ec && v.qa && (v.qa(), a.preventDefault());
            }, p);
        }
        var C, D = S.apply(m, [ a, b ]);
        "/" == D[0] && (D = D.substr(1));
        C = D;
        ib("cp " + C);
        if ("string" == typeof c) {
            var K = h, H = function() {
                K ? K() : g('Loading data file "' + c + '" failed.');
            }, x = new XMLHttpRequest();
            x.open("GET", c, l);
            x.responseType = "arraybuffer";
            x.onload = function() {
                if (200 == x.status || 0 == x.status && x.response) {
                    var a = x.response;
                    w(a, 'Loading data file "' + c + '" failed (no arrayBuffer).');
                    a = new Uint8Array(a);
                    n(a);
                    jb("al " + c);
                } else {
                    H();
                }
            };
            x.onerror = H;
            x.send(m);
            ib("al " + c);
        } else {
            n(c);
        }
    };
    s.FS_createLazyFile = function(a, b, c, d, e) {
        var f, h;
        "undefined" !== typeof XMLHttpRequest ? (ea || g("Cannot do synchronous binary XHRs outside webworkers in modern browsers. Use --embed-file or --preload-file in emcc"), 
        f = function() {
            this.ma = p;
            this.T = [];
        }, f.prototype.get = function(a) {
            if (!(a > this.length - 1 || 0 > a)) {
                var b = a % this.S;
                return this.pb(Math.floor(a / this.S))[b];
            }
        }, f.prototype.Cb = function(a) {
            this.pb = a;
        }, f.prototype.Fa = function() {
            var a = new XMLHttpRequest();
            a.open("HEAD", c, p);
            a.send(m);
            200 <= a.status && 300 > a.status || 304 === a.status || g(Error("Couldn't load " + c + ". Status: " + a.status));
            var b = Number(a.getResponseHeader("Content-length")), d, e = 1048576;
            if (!((d = a.getResponseHeader("Accept-Ranges")) && "bytes" === d)) {
                e = b;
            }
            var f = this;
            f.Cb(function(a) {
                var d = a * e, h = (a + 1) * e - 1, h = Math.min(h, b - 1);
                if ("undefined" === typeof f.T[a]) {
                    var i = f.T;
                    d > h && g(Error("invalid range (" + d + ", " + h + ") or no bytes requested!"));
                    h > b - 1 && g(Error("only " + b + " bytes available! programmer error!"));
                    var j = new XMLHttpRequest();
                    j.open("GET", c, p);
                    b !== e && j.setRequestHeader("Range", "bytes=" + d + "-" + h);
                    "undefined" != typeof Uint8Array && (j.responseType = "arraybuffer");
                    j.overrideMimeType && j.overrideMimeType("text/plain; charset=x-user-defined");
                    j.send(m);
                    200 <= j.status && 300 > j.status || 304 === j.status || g(Error("Couldn't load " + c + ". Status: " + j.status));
                    d = j.response !== k ? new Uint8Array(j.response || []) : J(j.responseText || "", l);
                    i[a] = d;
                }
                "undefined" === typeof f.T[a] && g(Error("doXHR failed!"));
                return f.T[a];
            });
            this.gb = b;
            this.fb = e;
            this.ma = l;
        }, f = new f(), Object.defineProperty(f, "length", {
            get: function() {
                this.ma || this.Fa();
                return this.gb;
            }
        }), Object.defineProperty(f, "chunkSize", {
            get: function() {
                this.ma || this.Fa();
                return this.fb;
            }
        }), h = k) : (h = c, f = k);
        var i, a = S("string" === typeof a ? a : ac(a), b);
        i = yb(a, cc(d, e));
        f ? i.g = f : h && (i.g = m, i.url = h);
        var j = {};
        Object.keys(i.e).forEach(function(a) {
            var b = i.e[a];
            j[a] = function() {
                var a;
                if (i.ke || i.le || i.link || i.g) {
                    a = l;
                } else {
                    a = l;
                    "undefined" !== typeof XMLHttpRequest && g(Error("Lazy loading should have been performed (contents set) in createLazyFile, but it was not. Lazy loading only works in web workers. Use --embed-file or --preload-file in emcc on the main thread."));
                    if (s.read) {
                        try {
                            i.g = J(s.read(i.url), l);
                        } catch (c) {
                            a = p;
                        }
                    } else {
                        g(Error("Cannot load without read() or XMLHttpRequest."));
                    }
                    a || M(N.I);
                }
                a || g(new Q(N.I));
                return b.apply(m, arguments);
            };
        });
        j.Q = function(a, b, c, d, e) {
            a = a.d.g;
            d = Math.min(a.length - e, d);
            if (a.slice) {
                for (var f = 0; f < d; f++) {
                    b[c + f] = a[e + f];
                }
            } else {
                for (f = 0; f < d; f++) {
                    b[c + f] = a.get(e + f);
                }
            }
            return d;
        };
        i.e = j;
        return i;
    };
    s.FS_createLink = function(a, b, c) {
        a = S("string" === typeof a ? a : ac(a), b);
        return Bb(c, a);
    };
    s.FS_createDevice = ec;
    U.m = F(12, "void*", E);
    wc(W);
    Bc.J = F([ 0 ], "i8", E);
    s.requestFullScreen = function(a, b) {
        function c() {
            Dc = p;
            (document.webkitFullScreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.mozFullscreenElement || document.fullScreenElement || document.fullscreenElement) === d ? (d.Ga = document.cancelFullScreen || document.mozCancelFullScreen || document.webkitCancelFullScreen, 
            d.Ga = d.Ga.bind(document), Gc && d.qa(), Dc = l, Hc && Lc()) : Hc && Mc();
            if (s.onFullScreen) {
                s.onFullScreen(Dc);
            }
        }
        Gc = a;
        Hc = b;
        "undefined" === typeof Gc && (Gc = l);
        "undefined" === typeof Hc && (Hc = p);
        var d = s.canvas;
        Fc || (Fc = l, document.addEventListener("fullscreenchange", c, p), document.addEventListener("mozfullscreenchange", c, p), 
        document.addEventListener("webkitfullscreenchange", c, p));
        d.Ab = d.requestFullScreen || d.mozRequestFullScreen || (d.webkitRequestFullScreen ? function() {
            d.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT);
        } : m);
        d.Ab();
    };
    s.requestAnimationFrame = function(a) {
        window.requestAnimationFrame || (window.requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame || window.oRequestAnimationFrame || window.setTimeout);
        window.requestAnimationFrame(a);
    };
    s.pauseMainLoop = aa();
    s.resumeMainLoop = function() {
        Cc && (Cc = p, m());
    };
    s.getUserMedia = function() {
        window.Ma || (window.Ma = navigator.getUserMedia || navigator.mozGetUserMedia);
        window.Ma(k);
    };
    Sa = u = xa(sa);
    Ta = Sa + 5242880;
    Ua = z = xa(Ta);
    w(Ua < va);
    var Vc = F([ 8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], "i8", 3), Wc = F([ 8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0 ], "i8", 3), Xc = Math.min;
    var V = function(global, env, buffer) {
        "use asm";
        var a = new global.Int8Array(buffer);
        var b = new global.Int16Array(buffer);
        var c = new global.Int32Array(buffer);
        var d = new global.Uint8Array(buffer);
        var e = new global.Uint16Array(buffer);
        var f = new global.Uint32Array(buffer);
        var g = new global.Float32Array(buffer);
        var h = new global.Float64Array(buffer);
        var i = env.STACKTOP | 0;
        var j = env.STACK_MAX | 0;
        var k = env.tempDoublePtr | 0;
        var l = env.ABORT | 0;
        var m = env.cttz_i8 | 0;
        var n = env.ctlz_i8 | 0;
        var o = env._stderr | 0;
        var p = env.__ZTVN10__cxxabiv120__si_class_type_infoE | 0;
        var q = env.__ZTVN10__cxxabiv117__class_type_infoE | 0;
        var r = env.___progname | 0;
        var s = +env.NaN;
        var t = +env.Infinity;
        var u = 0;
        var v = 0;
        var w = 0;
        var x = 0;
        var y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0;
        var H = 0;
        var I = 0;
        var J = 0;
        var K = 0;
        var L = 0;
        var M = 0;
        var N = 0;
        var O = 0;
        var P = 0;
        var Q = 0;
        var R = global.Math.floor;
        var S = global.Math.abs;
        var T = global.Math.sqrt;
        var U = global.Math.pow;
        var V = global.Math.cos;
        var W = global.Math.sin;
        var X = global.Math.tan;
        var Y = global.Math.acos;
        var Z = global.Math.asin;
        var _ = global.Math.atan;
        var $ = global.Math.atan2;
        var aa = global.Math.exp;
        var ab = global.Math.log;
        var ac = global.Math.ceil;
        var ad = global.Math.imul;
        var ae = env.abort;
        var af = env.assert;
        var ag = env.asmPrintInt;
        var ah = env.asmPrintFloat;
        var ai = env.min;
        var aj = env.invoke_vi;
        var ak = env.invoke_vii;
        var al = env.invoke_ii;
        var am = env.invoke_viii;
        var an = env.invoke_v;
        var ao = env.invoke_iii;
        var ap = env._strncmp;
        var aq = env._llvm_va_end;
        var ar = env._sysconf;
        var as = env.___cxa_throw;
        var at = env._strerror;
        var au = env._abort;
        var av = env._fprintf;
        var aw = env._llvm_eh_exception;
        var ax = env.___cxa_free_exception;
        var ay = env._fflush;
        var az = env.___buildEnvironment;
        var aA = env.__reallyNegative;
        var aB = env._strchr;
        var aC = env._fputc;
        var aD = env.___setErrNo;
        var aE = env._fwrite;
        var aF = env._send;
        var aG = env._write;
        var aH = env._exit;
        var aI = env.___cxa_find_matching_catch;
        var aJ = env.___cxa_allocate_exception;
        var aK = env._isspace;
        var aL = env.__formatString;
        var aM = env.___resumeException;
        var aN = env._llvm_uadd_with_overflow_i32;
        var aO = env.___cxa_does_inherit;
        var aP = env._getenv;
        var aQ = env._vfprintf;
        var aR = env.___cxa_begin_catch;
        var aS = env.__ZSt18uncaught_exceptionv;
        var aT = env._pwrite;
        var aU = env.___cxa_call_unexpected;
        var aV = env._sbrk;
        var aW = env._strerror_r;
        var aX = env.___errno_location;
        var aY = env.___gxx_personality_v0;
        var aZ = env.___cxa_is_number_type;
        var a_ = env._time;
        var a$ = env.__exit;
        var a0 = env.___cxa_end_catch;
        function a7(a) {
            a = a | 0;
            var b = 0;
            b = i;
            i = i + a | 0;
            i = i + 7 >> 3 << 3;
            return b | 0;
        }
        function a8() {
            return i | 0;
        }
        function a9(a) {
            a = a | 0;
            i = a;
        }
        function ba(a, b) {
            a = a | 0;
            b = b | 0;
            if ((u | 0) == 0) {
                u = a;
                v = b;
            }
        }
        function bb(b) {
            b = b | 0;
            a[k] = a[b];
            a[k + 1 | 0] = a[b + 1 | 0];
            a[k + 2 | 0] = a[b + 2 | 0];
            a[k + 3 | 0] = a[b + 3 | 0];
        }
        function bc(b) {
            b = b | 0;
            a[k] = a[b];
            a[k + 1 | 0] = a[b + 1 | 0];
            a[k + 2 | 0] = a[b + 2 | 0];
            a[k + 3 | 0] = a[b + 3 | 0];
            a[k + 4 | 0] = a[b + 4 | 0];
            a[k + 5 | 0] = a[b + 5 | 0];
            a[k + 6 | 0] = a[b + 6 | 0];
            a[k + 7 | 0] = a[b + 7 | 0];
        }
        function bd(a) {
            a = a | 0;
            H = a;
        }
        function be(a) {
            a = a | 0;
            I = a;
        }
        function bf(a) {
            a = a | 0;
            J = a;
        }
        function bg(a) {
            a = a | 0;
            K = a;
        }
        function bh(a) {
            a = a | 0;
            L = a;
        }
        function bi(a) {
            a = a | 0;
            M = a;
        }
        function bj(a) {
            a = a | 0;
            N = a;
        }
        function bk(a) {
            a = a | 0;
            O = a;
        }
        function bl(a) {
            a = a | 0;
            P = a;
        }
        function bm(a) {
            a = a | 0;
            Q = a;
        }
        function bn() {
            c[170] = q + 8;
            c[172] = p + 8;
            c[176] = p + 8;
        }
        function bo(b, c, d) {
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0;
            if ((d | 0) == 0) {
                return;
            } else {
                e = 0;
            }
            do {
                a[b + e | 0] = a[c + e | 0] | 0;
                e = e + 1 | 0;
            } while (e >>> 0 < d >>> 0);
            return;
        }
        function bp(b, c, d) {
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0, f = 0;
            if ((d | 0) == 0) {
                return;
            } else {
                e = 0;
            }
            do {
                f = b + e | 0;
                a[f] = a[f] ^ a[c + e | 0];
                e = e + 1 | 0;
            } while (e >>> 0 < d >>> 0);
            return;
        }
        function bq(a) {
            a = a | 0;
            var b = 0, c = 0, e = 0, f = 0;
            b = d[a + 1 | 0] | 0;
            c = d[a + 2 | 0] | 0;
            e = d[a + 3 | 0] | 0;
            f = cN(b << 8 | 0 >>> 24 | (d[a] | 0) | (c << 16 | 0 >>> 16) | (e << 24 | 0 >>> 8) | (0 << 8 | 0 >>> 24), 0 << 8 | b >>> 24 | (0 << 16 | c >>> 16) | (0 << 24 | e >>> 8) | (d[a + 4 | 0] | 0) | ((d[a + 5 | 0] | 0) << 8 | 0 >>> 24), 0 << 16 | 0 >>> 16, (d[a + 6 | 0] | 0) << 16 | 0 >>> 16) | 0;
            e = cN(f, H, 0 << 24 | 0 >>> 8, (d[a + 7 | 0] | 0) << 24 | 0 >>> 8) | 0;
            return (H = H, e) | 0;
        }
        function br(a) {
            a = a | 0;
            return (d[a + 1 | 0] | 0) << 8 | (d[a] | 0) | (d[a + 2 | 0] | 0) << 16 | (d[a + 3 | 0] | 0) << 24 | 0;
        }
        function bs(b, c) {
            b = b | 0;
            c = c | 0;
            a[b] = c & 255;
            a[b + 1 | 0] = c >>> 8 & 255;
            a[b + 2 | 0] = c >>> 16 & 255;
            a[b + 3 | 0] = c >>> 24 & 255;
            return;
        }
        function bt(a) {
            a = a | 0;
            c[a + 36 >> 2] = 0;
            c[a + 32 >> 2] = 0;
            c[a >> 2] = 1779033703;
            c[a + 4 >> 2] = -1150833019;
            c[a + 8 >> 2] = 1013904242;
            c[a + 12 >> 2] = -1521486534;
            c[a + 16 >> 2] = 1359893119;
            c[a + 20 >> 2] = -1694144372;
            c[a + 24 >> 2] = 528734635;
            c[a + 28 >> 2] = 1541459225;
            return;
        }
        function bu(a, b, d, e, f, g, h, i, j, k) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            g = g | 0;
            h = h | 0;
            i = i | 0;
            j = j | 0;
            k = k | 0;
            var l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0;
            l = cX(i, 0, h, 0) | 0;
            m = H;
            n = 0;
            if (m >>> 0 > n >>> 0 | m >>> 0 == n >>> 0 & l >>> 0 > 1073741823 >>> 0) {
                c[(aX() | 0) >> 2] = 27;
                o = -1;
                return o | 0;
            }
            l = cN(f, g, -1, -1) | 0;
            if ((l & f | 0) != 0 | (H & g | 0) != 0 | (f | 0) == 0 & (g | 0) == 0) {
                c[(aX() | 0) >> 2] = 22;
                o = -1;
                return o | 0;
            }
            do {
                if (!((33554431 / (i >>> 0) | 0) >>> 0 < h >>> 0 | h >>> 0 > 16777215)) {
                    l = 0;
                    if (l >>> 0 < g >>> 0 | l >>> 0 == g >>> 0 & (33554431 / (h >>> 0) | 0) >>> 0 < f >>> 0) {
                        break;
                    }
                    l = h << 7;
                    n = bL(ad(l, i) | 0) | 0;
                    if ((n | 0) == 0) {
                        o = -1;
                        return o | 0;
                    }
                    m = bL(h << 8) | 0;
                    do {
                        if ((m | 0) != 0) {
                            p = cX(l, 0, f, g) | 0;
                            q = bL(p) | 0;
                            if ((q | 0) == 0) {
                                bM(m);
                                break;
                            }
                            p = ad(i << 7, h) | 0;
                            bJ(a, b, d, e, 1, 0, n, p);
                            if ((i | 0) != 0) {
                                r = h << 7;
                                s = 0;
                                do {
                                    bv(n + (ad(r, s) | 0) | 0, h, f, g, q, m);
                                    s = s + 1 | 0;
                                } while (s >>> 0 < i >>> 0);
                            }
                            bJ(a, b, n, p, 1, 0, j, k);
                            bM(q);
                            bM(m);
                            bM(n);
                            o = 0;
                            return o | 0;
                        }
                    } while (0);
                    bM(n);
                    o = -1;
                    return o | 0;
                }
            } while (0);
            c[(aX() | 0) >> 2] = 12;
            o = -1;
            return o | 0;
        }
        function bv(a, b, c, d, e, f) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            var g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0;
            g = b << 7;
            h = f + g | 0;
            bo(f, a, g);
            if ((c | 0) == 0 & (d | 0) == 0) {
                bo(a, f, g);
                return;
            }
            i = g;
            j = 0;
            k = 0;
            l = 0;
            do {
                m = cX(l, k, i, j) | 0;
                bo(e + m | 0, f, g);
                bw(f, h, b);
                l = cN(l, k, 1, 0) | 0;
                k = H;
            } while (k >>> 0 < d >>> 0 | k >>> 0 == d >>> 0 & l >>> 0 < c >>> 0);
            if ((c | 0) == 0 & (d | 0) == 0) {
                bo(a, f, g);
                return;
            }
            l = cN(c, d, -1, -1) | 0;
            k = H;
            j = g;
            i = 0;
            m = 0;
            n = 0;
            do {
                o = bx(f, b) | 0;
                p = cX(o & l, H & k, j, i) | 0;
                bp(f, e + p | 0, g);
                bw(f, h, b);
                n = cN(n, m, 1, 0) | 0;
                m = H;
            } while (m >>> 0 < d >>> 0 | m >>> 0 == d >>> 0 & n >>> 0 < c >>> 0);
            bo(a, f, g);
            return;
        }
        function bw(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, j = 0, k = 0;
            d = i;
            i = i + 64 | 0;
            e = d | 0;
            f = c << 1;
            bo(e, a + ((c << 7) - 64) | 0, 64);
            if ((f | 0) != 0) {
                g = 0;
                do {
                    h = g << 6;
                    bp(e, a + h | 0, 64);
                    by(e);
                    bo(b + h | 0, e, 64);
                    g = g + 1 | 0;
                } while (g >>> 0 < f >>> 0);
            }
            if ((c | 0) == 0) {
                i = d;
                return;
            } else {
                j = 0;
            }
            do {
                bo(a + (j << 6) | 0, b + (j << 7) | 0, 64);
                j = j + 1 | 0;
            } while (j >>> 0 < c >>> 0);
            if ((c | 0) == 0) {
                i = d;
                return;
            } else {
                k = 0;
            }
            do {
                bo(a + (k + c << 6) | 0, b + (k << 7 | 64) | 0, 64);
                k = k + 1 | 0;
            } while (k >>> 0 < c >>> 0);
            i = d;
            return;
        }
        function bx(a, b) {
            a = a | 0;
            b = b | 0;
            var c = 0;
            c = bq(a + ((b << 7) - 64) | 0) | 0;
            return (H = H, c) | 0;
        }
        function by(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0, M = 0, N = 0, O = 0, P = 0, Q = 0, R = 0, S = 0, T = 0, U = 0, V = 0, W = 0, X = 0, Y = 0, Z = 0, _ = 0, $ = 0, aa = 0, ab = 0;
            b = i;
            i = i + 128 | 0;
            d = b | 0;
            e = b + 64 | 0;
            f = 0;
            do {
                c[d + (f << 2) >> 2] = br(a + (f << 2) | 0) | 0;
                f = f + 1 | 0;
            } while (f >>> 0 < 16);
            f = d;
            g = e;
            cK(g | 0, f | 0, 64) | 0;
            f = e | 0;
            g = e + 48 | 0;
            h = e + 16 | 0;
            j = e + 32 | 0;
            k = e + 20 | 0;
            l = e + 4 | 0;
            m = e + 36 | 0;
            n = e + 52 | 0;
            o = e + 40 | 0;
            p = e + 24 | 0;
            q = e + 56 | 0;
            r = e + 8 | 0;
            s = e + 60 | 0;
            t = e + 44 | 0;
            u = e + 12 | 0;
            v = e + 28 | 0;
            w = 0;
            x = c[f >> 2] | 0;
            y = c[g >> 2] | 0;
            z = c[h >> 2] | 0;
            A = c[j >> 2] | 0;
            B = c[k >> 2] | 0;
            C = c[l >> 2] | 0;
            D = c[m >> 2] | 0;
            E = c[n >> 2] | 0;
            F = c[o >> 2] | 0;
            G = c[p >> 2] | 0;
            H = c[q >> 2] | 0;
            I = c[r >> 2] | 0;
            J = c[s >> 2] | 0;
            K = c[t >> 2] | 0;
            L = c[u >> 2] | 0;
            M = c[v >> 2] | 0;
            do {
                N = y + x | 0;
                O = (N << 7 | N >>> 25) ^ z;
                N = O + x | 0;
                P = (N << 9 | N >>> 23) ^ A;
                N = P + O | 0;
                Q = (N << 13 | N >>> 19) ^ y;
                N = Q + P | 0;
                R = (N << 18 | N >>> 14) ^ x;
                N = C + B | 0;
                S = (N << 7 | N >>> 25) ^ D;
                N = S + B | 0;
                T = (N << 9 | N >>> 23) ^ E;
                N = T + S | 0;
                U = (N << 13 | N >>> 19) ^ C;
                N = U + T | 0;
                V = (N << 18 | N >>> 14) ^ B;
                N = G + F | 0;
                W = (N << 7 | N >>> 25) ^ H;
                N = W + F | 0;
                X = (N << 9 | N >>> 23) ^ I;
                N = X + W | 0;
                Y = (N << 13 | N >>> 19) ^ G;
                N = Y + X | 0;
                Z = (N << 18 | N >>> 14) ^ F;
                N = K + J | 0;
                _ = (N << 7 | N >>> 25) ^ L;
                N = _ + J | 0;
                $ = (N << 9 | N >>> 23) ^ M;
                N = $ + _ | 0;
                aa = (N << 13 | N >>> 19) ^ K;
                N = aa + $ | 0;
                ab = (N << 18 | N >>> 14) ^ J;
                N = _ + R | 0;
                C = (N << 7 | N >>> 25) ^ U;
                U = C + R | 0;
                I = (U << 9 | U >>> 23) ^ X;
                X = I + C | 0;
                L = (X << 13 | X >>> 19) ^ _;
                _ = L + I | 0;
                x = (_ << 18 | _ >>> 14) ^ R;
                R = O + V | 0;
                G = (R << 7 | R >>> 25) ^ Y;
                Y = G + V | 0;
                M = (Y << 9 | Y >>> 23) ^ $;
                $ = M + G | 0;
                z = ($ << 13 | $ >>> 19) ^ O;
                O = z + M | 0;
                B = (O << 18 | O >>> 14) ^ V;
                V = S + Z | 0;
                K = (V << 7 | V >>> 25) ^ aa;
                aa = K + Z | 0;
                A = (aa << 9 | aa >>> 23) ^ P;
                P = A + K | 0;
                D = (P << 13 | P >>> 19) ^ S;
                S = D + A | 0;
                F = (S << 18 | S >>> 14) ^ Z;
                Z = W + ab | 0;
                y = (Z << 7 | Z >>> 25) ^ Q;
                Q = y + ab | 0;
                E = (Q << 9 | Q >>> 23) ^ T;
                T = E + y | 0;
                H = (T << 13 | T >>> 19) ^ W;
                W = H + E | 0;
                J = (W << 18 | W >>> 14) ^ ab;
                w = w + 2 | 0;
            } while (w >>> 0 < 8);
            c[f >> 2] = x;
            c[g >> 2] = y;
            c[h >> 2] = z;
            c[j >> 2] = A;
            c[k >> 2] = B;
            c[l >> 2] = C;
            c[m >> 2] = D;
            c[n >> 2] = E;
            c[o >> 2] = F;
            c[p >> 2] = G;
            c[q >> 2] = H;
            c[r >> 2] = I;
            c[s >> 2] = J;
            c[t >> 2] = K;
            c[u >> 2] = L;
            c[v >> 2] = M;
            M = d | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e >> 2] | 0);
            M = d + 4 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 4 >> 2] | 0);
            M = d + 8 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 8 >> 2] | 0);
            M = d + 12 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 12 >> 2] | 0);
            M = d + 16 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 16 >> 2] | 0);
            M = d + 20 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 20 >> 2] | 0);
            M = d + 24 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 24 >> 2] | 0);
            M = d + 28 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 28 >> 2] | 0);
            M = d + 32 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 32 >> 2] | 0);
            M = d + 36 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 36 >> 2] | 0);
            M = d + 40 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 40 >> 2] | 0);
            M = d + 44 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 44 >> 2] | 0);
            M = d + 48 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 48 >> 2] | 0);
            M = d + 52 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 52 >> 2] | 0);
            M = d + 56 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 56 >> 2] | 0);
            M = d + 60 | 0;
            c[M >> 2] = (c[M >> 2] | 0) + (c[e + 60 >> 2] | 0);
            e = 0;
            do {
                bs(a + (e << 2) | 0, c[d + (e << 2) >> 2] | 0);
                e = e + 1 | 0;
            } while (e >>> 0 < 16);
            i = b;
            return;
        }
        function bz(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0;
            e = a + 32 | 0;
            f = a + 36 | 0;
            g = c[f >> 2] | 0;
            h = g >>> 3 & 63;
            i = aN(g | 0, d << 3 | 0) | 0;
            c[f >> 2] = i;
            if (H) {
                i = e | 0;
                c[i >> 2] = (c[i >> 2] | 0) + 1;
            }
            i = e | 0;
            c[i >> 2] = (c[i >> 2] | 0) + (d >>> 29);
            i = 64 - h | 0;
            e = a + 40 + h | 0;
            if (i >>> 0 > d >>> 0) {
                cK(e | 0, b | 0, d) | 0;
                return;
            }
            cK(e | 0, b | 0, i) | 0;
            e = a | 0;
            h = a + 40 | 0;
            bA(e, h);
            a = b + i | 0;
            b = d - i | 0;
            if (b >>> 0 > 63) {
                i = b;
                d = a;
                while (1) {
                    bA(e, d);
                    f = d + 64 | 0;
                    g = i - 64 | 0;
                    if (g >>> 0 > 63) {
                        i = g;
                        d = f;
                    } else {
                        j = g;
                        k = f;
                        break;
                    }
                }
            } else {
                j = b;
                k = a;
            }
            cK(h | 0, k | 0, j) | 0;
            return;
        }
        function bA(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0;
            d = i;
            i = i + 288 | 0;
            e = d | 0;
            f = d + 256 | 0;
            g = e | 0;
            bK(g, b);
            b = 16;
            do {
                h = c[e + (b - 2 << 2) >> 2] | 0;
                j = c[e + (b - 15 << 2) >> 2] | 0;
                c[e + (b << 2) >> 2] = (c[e + (b - 16 << 2) >> 2] | 0) + (c[e + (b - 7 << 2) >> 2] | 0) + ((h >>> 19 | h << 13) ^ h >>> 10 ^ (h >>> 17 | h << 15)) + ((j >>> 18 | j << 14) ^ j >>> 3 ^ (j >>> 7 | j << 25));
                b = b + 1 | 0;
            } while ((b | 0) < 64);
            b = f;
            j = a;
            cK(b | 0, j | 0, 32) | 0;
            j = f + 28 | 0;
            b = f + 16 | 0;
            h = c[b >> 2] | 0;
            k = f + 20 | 0;
            l = f + 24 | 0;
            m = c[l >> 2] | 0;
            n = (c[j >> 2] | 0) + 1116352408 + (c[g >> 2] | 0) + ((h >>> 6 | h << 26) ^ (h >>> 11 | h << 21) ^ (h >>> 25 | h << 7)) + ((m ^ c[k >> 2]) & h ^ m) | 0;
            m = f | 0;
            h = c[m >> 2] | 0;
            g = f + 4 | 0;
            o = c[g >> 2] | 0;
            p = f + 8 | 0;
            q = c[p >> 2] | 0;
            r = f + 12 | 0;
            c[r >> 2] = (c[r >> 2] | 0) + n;
            s = ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + n + ((q | o) & h | q & o) | 0;
            c[j >> 2] = s;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            h = (c[l >> 2] | 0) + 1899447441 + (c[e + 4 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[l >> 2] = n;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            s = (c[k >> 2] | 0) - 1245643825 + (c[e + 8 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[k >> 2] = h;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            n = (c[b >> 2] | 0) - 373957723 + (c[e + 12 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[b >> 2] = s;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            h = (c[r >> 2] | 0) + 961987163 + (c[e + 16 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[r >> 2] = n;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            s = (c[p >> 2] | 0) + 1508970993 + (c[e + 20 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[p >> 2] = h;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            n = (c[g >> 2] | 0) - 1841331548 + (c[e + 24 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[g >> 2] = s;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            h = (c[m >> 2] | 0) - 1424204075 + (c[e + 28 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[m >> 2] = n;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            s = (c[j >> 2] | 0) - 670586216 + (c[e + 32 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[j >> 2] = h;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            n = (c[l >> 2] | 0) + 310598401 + (c[e + 36 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[l >> 2] = s;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            h = (c[k >> 2] | 0) + 607225278 + (c[e + 40 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[k >> 2] = n;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            s = (c[b >> 2] | 0) + 1426881987 + (c[e + 44 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[b >> 2] = h;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            n = (c[r >> 2] | 0) + 1925078388 + (c[e + 48 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[r >> 2] = s;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            h = (c[p >> 2] | 0) - 2132889090 + (c[e + 52 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[p >> 2] = n;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            s = (c[g >> 2] | 0) - 1680079193 + (c[e + 56 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[g >> 2] = h;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            n = (c[m >> 2] | 0) - 1046744716 + (c[e + 60 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[m >> 2] = s;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            h = (c[j >> 2] | 0) - 459576895 + (c[e + 64 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[j >> 2] = n;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            s = (c[l >> 2] | 0) - 272742522 + (c[e + 68 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[l >> 2] = h;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            n = (c[k >> 2] | 0) + 264347078 + (c[e + 72 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[k >> 2] = s;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            h = (c[b >> 2] | 0) + 604807628 + (c[e + 76 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[b >> 2] = n;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            s = (c[r >> 2] | 0) + 770255983 + (c[e + 80 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[r >> 2] = h;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            n = (c[p >> 2] | 0) + 1249150122 + (c[e + 84 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[p >> 2] = s;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            h = (c[g >> 2] | 0) + 1555081692 + (c[e + 88 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[g >> 2] = n;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            s = (c[m >> 2] | 0) + 1996064986 + (c[e + 92 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[m >> 2] = h;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            n = (c[j >> 2] | 0) - 1740746414 + (c[e + 96 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[j >> 2] = s;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            h = (c[l >> 2] | 0) - 1473132947 + (c[e + 100 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[l >> 2] = n;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            s = (c[k >> 2] | 0) - 1341970488 + (c[e + 104 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[k >> 2] = h;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            n = (c[b >> 2] | 0) - 1084653625 + (c[e + 108 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[b >> 2] = s;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            h = (c[r >> 2] | 0) - 958395405 + (c[e + 112 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[r >> 2] = n;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            s = (c[p >> 2] | 0) - 710438585 + (c[e + 116 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[p >> 2] = h;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            n = (c[g >> 2] | 0) + 113926993 + (c[e + 120 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[g >> 2] = s;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            h = (c[m >> 2] | 0) + 338241895 + (c[e + 124 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[m >> 2] = n;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            s = (c[j >> 2] | 0) + 666307205 + (c[e + 128 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[j >> 2] = h;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            n = (c[l >> 2] | 0) + 773529912 + (c[e + 132 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[l >> 2] = s;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            h = (c[k >> 2] | 0) + 1294757372 + (c[e + 136 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[k >> 2] = n;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            s = (c[b >> 2] | 0) + 1396182291 + (c[e + 140 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[b >> 2] = h;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            n = (c[r >> 2] | 0) + 1695183700 + (c[e + 144 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[r >> 2] = s;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            h = (c[p >> 2] | 0) + 1986661051 + (c[e + 148 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[p >> 2] = n;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            s = (c[g >> 2] | 0) - 2117940946 + (c[e + 152 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[g >> 2] = h;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            n = (c[m >> 2] | 0) - 1838011259 + (c[e + 156 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[m >> 2] = s;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            h = (c[j >> 2] | 0) - 1564481375 + (c[e + 160 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[j >> 2] = n;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            s = (c[l >> 2] | 0) - 1474664885 + (c[e + 164 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[l >> 2] = h;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            n = (c[k >> 2] | 0) - 1035236496 + (c[e + 168 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[k >> 2] = s;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            h = (c[b >> 2] | 0) - 949202525 + (c[e + 172 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[b >> 2] = n;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            s = (c[r >> 2] | 0) - 778901479 + (c[e + 176 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[r >> 2] = h;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            n = (c[p >> 2] | 0) - 694614492 + (c[e + 180 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[p >> 2] = s;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            h = (c[g >> 2] | 0) - 200395387 + (c[e + 184 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[g >> 2] = n;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            s = (c[m >> 2] | 0) + 275423344 + (c[e + 188 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[m >> 2] = h;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            n = (c[j >> 2] | 0) + 430227734 + (c[e + 192 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[j >> 2] = s;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            h = (c[l >> 2] | 0) + 506948616 + (c[e + 196 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[l >> 2] = n;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            s = (c[k >> 2] | 0) + 659060556 + (c[e + 200 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[k >> 2] = h;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            n = (c[b >> 2] | 0) + 883997877 + (c[e + 204 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[b >> 2] = s;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            h = (c[r >> 2] | 0) + 958139571 + (c[e + 208 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[r >> 2] = n;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            s = (c[p >> 2] | 0) + 1322822218 + (c[e + 212 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[p >> 2] = h;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            n = (c[g >> 2] | 0) + 1537002063 + (c[e + 216 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[g >> 2] = s;
            o = c[k >> 2] | 0;
            q = c[j >> 2] | 0;
            h = (c[m >> 2] | 0) + 1747873779 + (c[e + 220 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[l >> 2]) & o ^ q) | 0;
            q = c[p >> 2] | 0;
            o = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[m >> 2] = n;
            q = c[b >> 2] | 0;
            o = c[l >> 2] | 0;
            s = (c[j >> 2] | 0) + 1955562222 + (c[e + 224 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[k >> 2]) & q ^ o) | 0;
            o = c[g >> 2] | 0;
            q = c[p >> 2] | 0;
            c[r >> 2] = (c[r >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[j >> 2] = h;
            o = c[r >> 2] | 0;
            q = c[k >> 2] | 0;
            n = (c[l >> 2] | 0) + 2024104815 + (c[e + 228 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[b >> 2]) & o ^ q) | 0;
            q = c[m >> 2] | 0;
            o = c[g >> 2] | 0;
            c[p >> 2] = (c[p >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((o | q) & h | o & q) | 0;
            c[l >> 2] = s;
            q = c[p >> 2] | 0;
            o = c[b >> 2] | 0;
            h = (c[k >> 2] | 0) - 2067236844 + (c[e + 232 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[r >> 2]) & q ^ o) | 0;
            o = c[j >> 2] | 0;
            q = c[m >> 2] | 0;
            c[g >> 2] = (c[g >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((q | o) & s | q & o) | 0;
            c[k >> 2] = n;
            o = c[g >> 2] | 0;
            q = c[r >> 2] | 0;
            s = (c[b >> 2] | 0) - 1933114872 + (c[e + 236 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[p >> 2]) & o ^ q) | 0;
            q = c[l >> 2] | 0;
            o = c[j >> 2] | 0;
            c[m >> 2] = (c[m >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((o | q) & n | o & q) | 0;
            c[b >> 2] = h;
            q = c[m >> 2] | 0;
            o = c[p >> 2] | 0;
            n = (c[r >> 2] | 0) - 1866530822 + (c[e + 240 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[g >> 2]) & q ^ o) | 0;
            o = c[k >> 2] | 0;
            q = c[l >> 2] | 0;
            c[j >> 2] = (c[j >> 2] | 0) + n;
            s = n + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((q | o) & h | q & o) | 0;
            c[r >> 2] = s;
            o = c[j >> 2] | 0;
            q = c[g >> 2] | 0;
            h = (c[p >> 2] | 0) - 1538233109 + (c[e + 244 >> 2] | 0) + ((o >>> 6 | o << 26) ^ (o >>> 11 | o << 21) ^ (o >>> 25 | o << 7)) + ((q ^ c[m >> 2]) & o ^ q) | 0;
            q = c[b >> 2] | 0;
            o = c[k >> 2] | 0;
            c[l >> 2] = (c[l >> 2] | 0) + h;
            n = h + ((s >>> 2 | s << 30) ^ (s >>> 13 | s << 19) ^ (s >>> 22 | s << 10)) + ((o | q) & s | o & q) | 0;
            c[p >> 2] = n;
            q = c[l >> 2] | 0;
            o = c[m >> 2] | 0;
            s = (c[g >> 2] | 0) - 1090935817 + (c[e + 248 >> 2] | 0) + ((q >>> 6 | q << 26) ^ (q >>> 11 | q << 21) ^ (q >>> 25 | q << 7)) + ((o ^ c[j >> 2]) & q ^ o) | 0;
            o = c[r >> 2] | 0;
            q = c[b >> 2] | 0;
            c[k >> 2] = (c[k >> 2] | 0) + s;
            h = s + ((n >>> 2 | n << 30) ^ (n >>> 13 | n << 19) ^ (n >>> 22 | n << 10)) + ((q | o) & n | q & o) | 0;
            c[g >> 2] = h;
            g = c[k >> 2] | 0;
            k = c[j >> 2] | 0;
            j = (c[m >> 2] | 0) - 965641998 + (c[e + 252 >> 2] | 0) + ((g >>> 6 | g << 26) ^ (g >>> 11 | g << 21) ^ (g >>> 25 | g << 7)) + ((k ^ c[l >> 2]) & g ^ k) | 0;
            k = c[p >> 2] | 0;
            p = c[r >> 2] | 0;
            c[b >> 2] = (c[b >> 2] | 0) + j;
            b = j + ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) + ((p | k) & h | p & k) | 0;
            c[m >> 2] = b;
            c[a >> 2] = (c[a >> 2] | 0) + b;
            b = a + 4 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 4 >> 2] | 0);
            b = a + 8 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 8 >> 2] | 0);
            b = a + 12 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 12 >> 2] | 0);
            b = a + 16 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 16 >> 2] | 0);
            b = a + 20 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 20 >> 2] | 0);
            b = a + 24 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 24 >> 2] | 0);
            b = a + 28 | 0;
            c[b >> 2] = (c[b >> 2] | 0) + (c[f + 28 >> 2] | 0);
            i = d;
            return;
        }
        function bB(b, c) {
            b = b | 0;
            c = c | 0;
            a[b + 3 | 0] = c & 255;
            a[b + 2 | 0] = c >>> 8 & 255;
            a[b + 1 | 0] = c >>> 16 & 255;
            a[b] = c >>> 24 & 255;
            return;
        }
        function bC(a) {
            a = a | 0;
            return (d[a + 2 | 0] | 0) << 8 | (d[a + 3 | 0] | 0) | (d[a + 1 | 0] | 0) << 16 | (d[a] | 0) << 24 | 0;
        }
        function bD(a, b) {
            a = a | 0;
            b = b | 0;
            bE(b);
            bF(a, b | 0, 32);
            cL(b | 0, 0, 104);
            return;
        }
        function bE(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0;
            b = i;
            i = i + 8 | 0;
            d = b | 0;
            bF(d, a + 32 | 0, 8);
            e = (c[a + 36 >> 2] | 0) >>> 3 & 63;
            bz(a, 720, (e >>> 0 < 56 ? 56 : 120) - e | 0);
            bz(a, d, 8);
            i = b;
            return;
        }
        function bF(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = d >>> 2;
            if ((e | 0) == 0) {
                return;
            } else {
                f = 0;
            }
            do {
                bB(a + (f << 2) | 0, c[b + (f << 2) >> 2] | 0);
                f = f + 1 | 0;
            } while (f >>> 0 < e >>> 0);
            return;
        }
        function bG(b, c, d) {
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0, f = 0, g = 0, h = 0, j = 0, k = 0, l = 0;
            e = i;
            i = i + 96 | 0;
            f = e | 0;
            if (d >>> 0 > 64) {
                g = b | 0;
                bt(g);
                bz(g, c, d);
                h = e + 64 | 0;
                bD(h, g);
                j = h;
                k = 32;
            } else {
                j = c;
                k = d;
            }
            d = b | 0;
            bt(d);
            c = f | 0;
            cL(c | 0, 54, 64);
            if ((k | 0) != 0) {
                h = 0;
                do {
                    g = f + h | 0;
                    a[g] = a[g] ^ a[j + h | 0];
                    h = h + 1 | 0;
                } while (h >>> 0 < k >>> 0);
            }
            bz(d, c, 64);
            d = b + 104 | 0;
            bt(d);
            cL(c | 0, 92, 64);
            if ((k | 0) == 0) {
                bz(d, c, 64);
                i = e;
                return;
            } else {
                l = 0;
            }
            do {
                b = f + l | 0;
                a[b] = a[b] ^ a[j + l | 0];
                l = l + 1 | 0;
            } while (l >>> 0 < k >>> 0);
            bz(d, c, 64);
            i = e;
            return;
        }
        function bH(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            bz(a | 0, b, c);
            return;
        }
        function bI(a, b) {
            a = a | 0;
            b = b | 0;
            var c = 0, d = 0, e = 0;
            c = i;
            i = i + 32 | 0;
            d = c | 0;
            bD(d, b | 0);
            e = b + 104 | 0;
            bz(e, d, 32);
            bD(a, e);
            i = c;
            return;
        }
        function bJ(b, c, d, e, f, g, h, j) {
            b = b | 0;
            c = c | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            g = g | 0;
            h = h | 0;
            j = j | 0;
            var k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0;
            k = i;
            i = i + 488 | 0;
            l = k | 0;
            m = k + 208 | 0;
            n = k + 424 | 0;
            o = k + 456 | 0;
            bG(l, b, c);
            bH(l, d, e);
            if ((j | 0) == 0) {
                i = k;
                return;
            }
            e = k + 416 | 0;
            d = m;
            p = l;
            l = n | 0;
            q = o | 0;
            r = 0;
            s = g >>> 0 < r >>> 0 | g >>> 0 == r >>> 0 & f >>> 0 < 2 >>> 0;
            r = 0;
            t = 0;
            do {
                r = r + 1 | 0;
                bB(e, r);
                cK(d | 0, p | 0, 208) | 0;
                bH(m, e, 4);
                bI(l, m);
                cK(q | 0, l | 0, 32) | 0;
                if (!s) {
                    u = 0;
                    v = 2;
                    do {
                        bG(m, b, c);
                        bH(m, l, 32);
                        bI(l, m);
                        w = 0;
                        do {
                            x = o + w | 0;
                            a[x] = a[x] ^ a[n + w | 0];
                            w = w + 1 | 0;
                        } while ((w | 0) < 32);
                        v = cN(v, u, 1, 0) | 0;
                        u = H;
                    } while (!(u >>> 0 > g >>> 0 | u >>> 0 == g >>> 0 & v >>> 0 > f >>> 0));
                }
                v = j - t | 0;
                u = v >>> 0 > 32 ? 32 : v;
                v = h + t | 0;
                cK(v | 0, q | 0, u) | 0;
                t = r << 5;
            } while (t >>> 0 < j >>> 0);
            i = k;
            return;
        }
        function bK(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0;
            d = 0;
            do {
                c[a + (d << 2) >> 2] = bC(b + (d << 2) | 0) | 0;
                d = d + 1 | 0;
            } while (d >>> 0 < 16);
            return;
        }
        function bL(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0, M = 0, N = 0, O = 0, P = 0, Q = 0, R = 0, S = 0, T = 0, U = 0, V = 0, W = 0, X = 0, Y = 0, Z = 0, _ = 0, $ = 0, aa = 0, ab = 0, ac = 0, ad = 0, ae = 0, af = 0, ag = 0, ah = 0, ai = 0, aj = 0, ak = 0, al = 0, am = 0, an = 0, ao = 0, ap = 0, aq = 0, as = 0, at = 0, av = 0, aw = 0, ax = 0, ay = 0, az = 0, aA = 0, aB = 0, aC = 0, aD = 0, aE = 0, aF = 0, aG = 0, aH = 0, aI = 0;
            do {
                if (a >>> 0 < 245) {
                    if (a >>> 0 < 11) {
                        b = 16;
                    } else {
                        b = a + 11 & -8;
                    }
                    d = b >>> 3;
                    e = c[208] | 0;
                    f = e >>> (d >>> 0);
                    if ((f & 3 | 0) != 0) {
                        g = (f & 1 ^ 1) + d | 0;
                        h = g << 1;
                        i = 872 + (h << 2) | 0;
                        j = 872 + (h + 2 << 2) | 0;
                        h = c[j >> 2] | 0;
                        k = h + 8 | 0;
                        l = c[k >> 2] | 0;
                        do {
                            if ((i | 0) == (l | 0)) {
                                c[208] = e & ~(1 << g);
                            } else {
                                if (l >>> 0 < (c[212] | 0) >>> 0) {
                                    au();
                                    return 0;
                                }
                                m = l + 12 | 0;
                                if ((c[m >> 2] | 0) == (h | 0)) {
                                    c[m >> 2] = i;
                                    c[j >> 2] = l;
                                    break;
                                } else {
                                    au();
                                    return 0;
                                }
                            }
                        } while (0);
                        l = g << 3;
                        c[h + 4 >> 2] = l | 3;
                        j = h + (l | 4) | 0;
                        c[j >> 2] = c[j >> 2] | 1;
                        n = k;
                        return n | 0;
                    }
                    if (b >>> 0 <= (c[210] | 0) >>> 0) {
                        o = b;
                        break;
                    }
                    if ((f | 0) != 0) {
                        j = 2 << d;
                        l = f << d & (j | -j);
                        j = (l & -l) - 1 | 0;
                        l = j >>> 12 & 16;
                        i = j >>> (l >>> 0);
                        j = i >>> 5 & 8;
                        m = i >>> (j >>> 0);
                        i = m >>> 2 & 4;
                        p = m >>> (i >>> 0);
                        m = p >>> 1 & 2;
                        q = p >>> (m >>> 0);
                        p = q >>> 1 & 1;
                        r = (j | l | i | m | p) + (q >>> (p >>> 0)) | 0;
                        p = r << 1;
                        q = 872 + (p << 2) | 0;
                        m = 872 + (p + 2 << 2) | 0;
                        p = c[m >> 2] | 0;
                        i = p + 8 | 0;
                        l = c[i >> 2] | 0;
                        do {
                            if ((q | 0) == (l | 0)) {
                                c[208] = e & ~(1 << r);
                            } else {
                                if (l >>> 0 < (c[212] | 0) >>> 0) {
                                    au();
                                    return 0;
                                }
                                j = l + 12 | 0;
                                if ((c[j >> 2] | 0) == (p | 0)) {
                                    c[j >> 2] = q;
                                    c[m >> 2] = l;
                                    break;
                                } else {
                                    au();
                                    return 0;
                                }
                            }
                        } while (0);
                        l = r << 3;
                        m = l - b | 0;
                        c[p + 4 >> 2] = b | 3;
                        q = p;
                        e = q + b | 0;
                        c[q + (b | 4) >> 2] = m | 1;
                        c[q + l >> 2] = m;
                        l = c[210] | 0;
                        if ((l | 0) != 0) {
                            q = c[213] | 0;
                            d = l >>> 3;
                            l = d << 1;
                            f = 872 + (l << 2) | 0;
                            k = c[208] | 0;
                            h = 1 << d;
                            do {
                                if ((k & h | 0) == 0) {
                                    c[208] = k | h;
                                    s = f;
                                    t = 872 + (l + 2 << 2) | 0;
                                } else {
                                    d = 872 + (l + 2 << 2) | 0;
                                    g = c[d >> 2] | 0;
                                    if (g >>> 0 >= (c[212] | 0) >>> 0) {
                                        s = g;
                                        t = d;
                                        break;
                                    }
                                    au();
                                    return 0;
                                }
                            } while (0);
                            c[t >> 2] = q;
                            c[s + 12 >> 2] = q;
                            c[q + 8 >> 2] = s;
                            c[q + 12 >> 2] = f;
                        }
                        c[210] = m;
                        c[213] = e;
                        n = i;
                        return n | 0;
                    }
                    l = c[209] | 0;
                    if ((l | 0) == 0) {
                        o = b;
                        break;
                    }
                    h = (l & -l) - 1 | 0;
                    l = h >>> 12 & 16;
                    k = h >>> (l >>> 0);
                    h = k >>> 5 & 8;
                    p = k >>> (h >>> 0);
                    k = p >>> 2 & 4;
                    r = p >>> (k >>> 0);
                    p = r >>> 1 & 2;
                    d = r >>> (p >>> 0);
                    r = d >>> 1 & 1;
                    g = c[1136 + ((h | l | k | p | r) + (d >>> (r >>> 0)) << 2) >> 2] | 0;
                    r = g;
                    d = g;
                    p = (c[g + 4 >> 2] & -8) - b | 0;
                    while (1) {
                        g = c[r + 16 >> 2] | 0;
                        if ((g | 0) == 0) {
                            k = c[r + 20 >> 2] | 0;
                            if ((k | 0) == 0) {
                                break;
                            } else {
                                u = k;
                            }
                        } else {
                            u = g;
                        }
                        g = (c[u + 4 >> 2] & -8) - b | 0;
                        k = g >>> 0 < p >>> 0;
                        r = u;
                        d = k ? u : d;
                        p = k ? g : p;
                    }
                    r = d;
                    i = c[212] | 0;
                    if (r >>> 0 < i >>> 0) {
                        au();
                        return 0;
                    }
                    e = r + b | 0;
                    m = e;
                    if (r >>> 0 >= e >>> 0) {
                        au();
                        return 0;
                    }
                    e = c[d + 24 >> 2] | 0;
                    f = c[d + 12 >> 2] | 0;
                    do {
                        if ((f | 0) == (d | 0)) {
                            q = d + 20 | 0;
                            g = c[q >> 2] | 0;
                            if ((g | 0) == 0) {
                                k = d + 16 | 0;
                                l = c[k >> 2] | 0;
                                if ((l | 0) == 0) {
                                    v = 0;
                                    break;
                                } else {
                                    w = l;
                                    x = k;
                                }
                            } else {
                                w = g;
                                x = q;
                            }
                            while (1) {
                                q = w + 20 | 0;
                                g = c[q >> 2] | 0;
                                if ((g | 0) != 0) {
                                    w = g;
                                    x = q;
                                    continue;
                                }
                                q = w + 16 | 0;
                                g = c[q >> 2] | 0;
                                if ((g | 0) == 0) {
                                    break;
                                } else {
                                    w = g;
                                    x = q;
                                }
                            }
                            if (x >>> 0 < i >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[x >> 2] = 0;
                                v = w;
                                break;
                            }
                        } else {
                            q = c[d + 8 >> 2] | 0;
                            if (q >>> 0 < i >>> 0) {
                                au();
                                return 0;
                            }
                            g = q + 12 | 0;
                            if ((c[g >> 2] | 0) != (d | 0)) {
                                au();
                                return 0;
                            }
                            k = f + 8 | 0;
                            if ((c[k >> 2] | 0) == (d | 0)) {
                                c[g >> 2] = f;
                                c[k >> 2] = q;
                                v = f;
                                break;
                            } else {
                                au();
                                return 0;
                            }
                        }
                    } while (0);
                    L223: do {
                        if ((e | 0) != 0) {
                            f = d + 28 | 0;
                            i = 1136 + (c[f >> 2] << 2) | 0;
                            do {
                                if ((d | 0) == (c[i >> 2] | 0)) {
                                    c[i >> 2] = v;
                                    if ((v | 0) != 0) {
                                        break;
                                    }
                                    c[209] = c[209] & ~(1 << c[f >> 2]);
                                    break L223;
                                } else {
                                    if (e >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                        return 0;
                                    }
                                    q = e + 16 | 0;
                                    if ((c[q >> 2] | 0) == (d | 0)) {
                                        c[q >> 2] = v;
                                    } else {
                                        c[e + 20 >> 2] = v;
                                    }
                                    if ((v | 0) == 0) {
                                        break L223;
                                    }
                                }
                            } while (0);
                            if (v >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            }
                            c[v + 24 >> 2] = e;
                            f = c[d + 16 >> 2] | 0;
                            do {
                                if ((f | 0) != 0) {
                                    if (f >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                        return 0;
                                    } else {
                                        c[v + 16 >> 2] = f;
                                        c[f + 24 >> 2] = v;
                                        break;
                                    }
                                }
                            } while (0);
                            f = c[d + 20 >> 2] | 0;
                            if ((f | 0) == 0) {
                                break;
                            }
                            if (f >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[v + 20 >> 2] = f;
                                c[f + 24 >> 2] = v;
                                break;
                            }
                        }
                    } while (0);
                    if (p >>> 0 < 16) {
                        e = p + b | 0;
                        c[d + 4 >> 2] = e | 3;
                        f = r + (e + 4) | 0;
                        c[f >> 2] = c[f >> 2] | 1;
                    } else {
                        c[d + 4 >> 2] = b | 3;
                        c[r + (b | 4) >> 2] = p | 1;
                        c[r + (p + b) >> 2] = p;
                        f = c[210] | 0;
                        if ((f | 0) != 0) {
                            e = c[213] | 0;
                            i = f >>> 3;
                            f = i << 1;
                            q = 872 + (f << 2) | 0;
                            k = c[208] | 0;
                            g = 1 << i;
                            do {
                                if ((k & g | 0) == 0) {
                                    c[208] = k | g;
                                    y = q;
                                    z = 872 + (f + 2 << 2) | 0;
                                } else {
                                    i = 872 + (f + 2 << 2) | 0;
                                    l = c[i >> 2] | 0;
                                    if (l >>> 0 >= (c[212] | 0) >>> 0) {
                                        y = l;
                                        z = i;
                                        break;
                                    }
                                    au();
                                    return 0;
                                }
                            } while (0);
                            c[z >> 2] = e;
                            c[y + 12 >> 2] = e;
                            c[e + 8 >> 2] = y;
                            c[e + 12 >> 2] = q;
                        }
                        c[210] = p;
                        c[213] = m;
                    }
                    f = d + 8 | 0;
                    if ((f | 0) == 0) {
                        o = b;
                        break;
                    } else {
                        n = f;
                    }
                    return n | 0;
                } else {
                    if (a >>> 0 > 4294967231) {
                        o = -1;
                        break;
                    }
                    f = a + 11 | 0;
                    g = f & -8;
                    k = c[209] | 0;
                    if ((k | 0) == 0) {
                        o = g;
                        break;
                    }
                    r = -g | 0;
                    i = f >>> 8;
                    do {
                        if ((i | 0) == 0) {
                            A = 0;
                        } else {
                            if (g >>> 0 > 16777215) {
                                A = 31;
                                break;
                            }
                            f = (i + 1048320 | 0) >>> 16 & 8;
                            l = i << f;
                            h = (l + 520192 | 0) >>> 16 & 4;
                            j = l << h;
                            l = (j + 245760 | 0) >>> 16 & 2;
                            B = 14 - (h | f | l) + (j << l >>> 15) | 0;
                            A = g >>> ((B + 7 | 0) >>> 0) & 1 | B << 1;
                        }
                    } while (0);
                    i = c[1136 + (A << 2) >> 2] | 0;
                    L271: do {
                        if ((i | 0) == 0) {
                            C = 0;
                            D = r;
                            E = 0;
                        } else {
                            if ((A | 0) == 31) {
                                F = 0;
                            } else {
                                F = 25 - (A >>> 1) | 0;
                            }
                            d = 0;
                            m = r;
                            p = i;
                            q = g << F;
                            e = 0;
                            while (1) {
                                B = c[p + 4 >> 2] & -8;
                                l = B - g | 0;
                                if (l >>> 0 < m >>> 0) {
                                    if ((B | 0) == (g | 0)) {
                                        C = p;
                                        D = l;
                                        E = p;
                                        break L271;
                                    } else {
                                        G = p;
                                        H = l;
                                    }
                                } else {
                                    G = d;
                                    H = m;
                                }
                                l = c[p + 20 >> 2] | 0;
                                B = c[p + 16 + (q >>> 31 << 2) >> 2] | 0;
                                j = (l | 0) == 0 | (l | 0) == (B | 0) ? e : l;
                                if ((B | 0) == 0) {
                                    C = G;
                                    D = H;
                                    E = j;
                                    break;
                                } else {
                                    d = G;
                                    m = H;
                                    p = B;
                                    q = q << 1;
                                    e = j;
                                }
                            }
                        }
                    } while (0);
                    if ((E | 0) == 0 & (C | 0) == 0) {
                        i = 2 << A;
                        r = k & (i | -i);
                        if ((r | 0) == 0) {
                            o = g;
                            break;
                        }
                        i = (r & -r) - 1 | 0;
                        r = i >>> 12 & 16;
                        e = i >>> (r >>> 0);
                        i = e >>> 5 & 8;
                        q = e >>> (i >>> 0);
                        e = q >>> 2 & 4;
                        p = q >>> (e >>> 0);
                        q = p >>> 1 & 2;
                        m = p >>> (q >>> 0);
                        p = m >>> 1 & 1;
                        I = c[1136 + ((i | r | e | q | p) + (m >>> (p >>> 0)) << 2) >> 2] | 0;
                    } else {
                        I = E;
                    }
                    if ((I | 0) == 0) {
                        J = D;
                        K = C;
                    } else {
                        p = I;
                        m = D;
                        q = C;
                        while (1) {
                            e = (c[p + 4 >> 2] & -8) - g | 0;
                            r = e >>> 0 < m >>> 0;
                            i = r ? e : m;
                            e = r ? p : q;
                            r = c[p + 16 >> 2] | 0;
                            if ((r | 0) != 0) {
                                p = r;
                                m = i;
                                q = e;
                                continue;
                            }
                            r = c[p + 20 >> 2] | 0;
                            if ((r | 0) == 0) {
                                J = i;
                                K = e;
                                break;
                            } else {
                                p = r;
                                m = i;
                                q = e;
                            }
                        }
                    }
                    if ((K | 0) == 0) {
                        o = g;
                        break;
                    }
                    if (J >>> 0 >= ((c[210] | 0) - g | 0) >>> 0) {
                        o = g;
                        break;
                    }
                    q = K;
                    m = c[212] | 0;
                    if (q >>> 0 < m >>> 0) {
                        au();
                        return 0;
                    }
                    p = q + g | 0;
                    k = p;
                    if (q >>> 0 >= p >>> 0) {
                        au();
                        return 0;
                    }
                    e = c[K + 24 >> 2] | 0;
                    i = c[K + 12 >> 2] | 0;
                    do {
                        if ((i | 0) == (K | 0)) {
                            r = K + 20 | 0;
                            d = c[r >> 2] | 0;
                            if ((d | 0) == 0) {
                                j = K + 16 | 0;
                                B = c[j >> 2] | 0;
                                if ((B | 0) == 0) {
                                    L = 0;
                                    break;
                                } else {
                                    M = B;
                                    N = j;
                                }
                            } else {
                                M = d;
                                N = r;
                            }
                            while (1) {
                                r = M + 20 | 0;
                                d = c[r >> 2] | 0;
                                if ((d | 0) != 0) {
                                    M = d;
                                    N = r;
                                    continue;
                                }
                                r = M + 16 | 0;
                                d = c[r >> 2] | 0;
                                if ((d | 0) == 0) {
                                    break;
                                } else {
                                    M = d;
                                    N = r;
                                }
                            }
                            if (N >>> 0 < m >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[N >> 2] = 0;
                                L = M;
                                break;
                            }
                        } else {
                            r = c[K + 8 >> 2] | 0;
                            if (r >>> 0 < m >>> 0) {
                                au();
                                return 0;
                            }
                            d = r + 12 | 0;
                            if ((c[d >> 2] | 0) != (K | 0)) {
                                au();
                                return 0;
                            }
                            j = i + 8 | 0;
                            if ((c[j >> 2] | 0) == (K | 0)) {
                                c[d >> 2] = i;
                                c[j >> 2] = r;
                                L = i;
                                break;
                            } else {
                                au();
                                return 0;
                            }
                        }
                    } while (0);
                    L321: do {
                        if ((e | 0) != 0) {
                            i = K + 28 | 0;
                            m = 1136 + (c[i >> 2] << 2) | 0;
                            do {
                                if ((K | 0) == (c[m >> 2] | 0)) {
                                    c[m >> 2] = L;
                                    if ((L | 0) != 0) {
                                        break;
                                    }
                                    c[209] = c[209] & ~(1 << c[i >> 2]);
                                    break L321;
                                } else {
                                    if (e >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                        return 0;
                                    }
                                    r = e + 16 | 0;
                                    if ((c[r >> 2] | 0) == (K | 0)) {
                                        c[r >> 2] = L;
                                    } else {
                                        c[e + 20 >> 2] = L;
                                    }
                                    if ((L | 0) == 0) {
                                        break L321;
                                    }
                                }
                            } while (0);
                            if (L >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            }
                            c[L + 24 >> 2] = e;
                            i = c[K + 16 >> 2] | 0;
                            do {
                                if ((i | 0) != 0) {
                                    if (i >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                        return 0;
                                    } else {
                                        c[L + 16 >> 2] = i;
                                        c[i + 24 >> 2] = L;
                                        break;
                                    }
                                }
                            } while (0);
                            i = c[K + 20 >> 2] | 0;
                            if ((i | 0) == 0) {
                                break;
                            }
                            if (i >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[L + 20 >> 2] = i;
                                c[i + 24 >> 2] = L;
                                break;
                            }
                        }
                    } while (0);
                    do {
                        if (J >>> 0 < 16) {
                            e = J + g | 0;
                            c[K + 4 >> 2] = e | 3;
                            i = q + (e + 4) | 0;
                            c[i >> 2] = c[i >> 2] | 1;
                        } else {
                            c[K + 4 >> 2] = g | 3;
                            c[q + (g | 4) >> 2] = J | 1;
                            c[q + (J + g) >> 2] = J;
                            i = J >>> 3;
                            if (J >>> 0 < 256) {
                                e = i << 1;
                                m = 872 + (e << 2) | 0;
                                r = c[208] | 0;
                                j = 1 << i;
                                do {
                                    if ((r & j | 0) == 0) {
                                        c[208] = r | j;
                                        O = m;
                                        P = 872 + (e + 2 << 2) | 0;
                                    } else {
                                        i = 872 + (e + 2 << 2) | 0;
                                        d = c[i >> 2] | 0;
                                        if (d >>> 0 >= (c[212] | 0) >>> 0) {
                                            O = d;
                                            P = i;
                                            break;
                                        }
                                        au();
                                        return 0;
                                    }
                                } while (0);
                                c[P >> 2] = k;
                                c[O + 12 >> 2] = k;
                                c[q + (g + 8) >> 2] = O;
                                c[q + (g + 12) >> 2] = m;
                                break;
                            }
                            e = p;
                            j = J >>> 8;
                            do {
                                if ((j | 0) == 0) {
                                    Q = 0;
                                } else {
                                    if (J >>> 0 > 16777215) {
                                        Q = 31;
                                        break;
                                    }
                                    r = (j + 1048320 | 0) >>> 16 & 8;
                                    i = j << r;
                                    d = (i + 520192 | 0) >>> 16 & 4;
                                    B = i << d;
                                    i = (B + 245760 | 0) >>> 16 & 2;
                                    l = 14 - (d | r | i) + (B << i >>> 15) | 0;
                                    Q = J >>> ((l + 7 | 0) >>> 0) & 1 | l << 1;
                                }
                            } while (0);
                            j = 1136 + (Q << 2) | 0;
                            c[q + (g + 28) >> 2] = Q;
                            c[q + (g + 20) >> 2] = 0;
                            c[q + (g + 16) >> 2] = 0;
                            m = c[209] | 0;
                            l = 1 << Q;
                            if ((m & l | 0) == 0) {
                                c[209] = m | l;
                                c[j >> 2] = e;
                                c[q + (g + 24) >> 2] = j;
                                c[q + (g + 12) >> 2] = e;
                                c[q + (g + 8) >> 2] = e;
                                break;
                            }
                            if ((Q | 0) == 31) {
                                R = 0;
                            } else {
                                R = 25 - (Q >>> 1) | 0;
                            }
                            l = J << R;
                            m = c[j >> 2] | 0;
                            while (1) {
                                if ((c[m + 4 >> 2] & -8 | 0) == (J | 0)) {
                                    break;
                                }
                                S = m + 16 + (l >>> 31 << 2) | 0;
                                j = c[S >> 2] | 0;
                                if ((j | 0) == 0) {
                                    T = 262;
                                    break;
                                } else {
                                    l = l << 1;
                                    m = j;
                                }
                            }
                            if ((T | 0) == 262) {
                                if (S >>> 0 < (c[212] | 0) >>> 0) {
                                    au();
                                    return 0;
                                } else {
                                    c[S >> 2] = e;
                                    c[q + (g + 24) >> 2] = m;
                                    c[q + (g + 12) >> 2] = e;
                                    c[q + (g + 8) >> 2] = e;
                                    break;
                                }
                            }
                            l = m + 8 | 0;
                            j = c[l >> 2] | 0;
                            i = c[212] | 0;
                            if (m >>> 0 < i >>> 0) {
                                au();
                                return 0;
                            }
                            if (j >>> 0 < i >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[j + 12 >> 2] = e;
                                c[l >> 2] = e;
                                c[q + (g + 8) >> 2] = j;
                                c[q + (g + 12) >> 2] = m;
                                c[q + (g + 24) >> 2] = 0;
                                break;
                            }
                        }
                    } while (0);
                    q = K + 8 | 0;
                    if ((q | 0) == 0) {
                        o = g;
                        break;
                    } else {
                        n = q;
                    }
                    return n | 0;
                }
            } while (0);
            K = c[210] | 0;
            if (o >>> 0 <= K >>> 0) {
                S = K - o | 0;
                J = c[213] | 0;
                if (S >>> 0 > 15) {
                    R = J;
                    c[213] = R + o;
                    c[210] = S;
                    c[R + (o + 4) >> 2] = S | 1;
                    c[R + K >> 2] = S;
                    c[J + 4 >> 2] = o | 3;
                } else {
                    c[210] = 0;
                    c[213] = 0;
                    c[J + 4 >> 2] = K | 3;
                    S = J + (K + 4) | 0;
                    c[S >> 2] = c[S >> 2] | 1;
                }
                n = J + 8 | 0;
                return n | 0;
            }
            J = c[211] | 0;
            if (o >>> 0 < J >>> 0) {
                S = J - o | 0;
                c[211] = S;
                J = c[214] | 0;
                K = J;
                c[214] = K + o;
                c[K + (o + 4) >> 2] = S | 1;
                c[J + 4 >> 2] = o | 3;
                n = J + 8 | 0;
                return n | 0;
            }
            do {
                if ((c[200] | 0) == 0) {
                    J = ar(8) | 0;
                    if ((J - 1 & J | 0) == 0) {
                        c[202] = J;
                        c[201] = J;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                        return 0;
                    }
                }
            } while (0);
            J = o + 48 | 0;
            S = c[202] | 0;
            K = o + 47 | 0;
            R = S + K | 0;
            Q = -S | 0;
            S = R & Q;
            if (S >>> 0 <= o >>> 0) {
                n = 0;
                return n | 0;
            }
            O = c[318] | 0;
            do {
                if ((O | 0) != 0) {
                    P = c[316] | 0;
                    L = P + S | 0;
                    if (L >>> 0 <= P >>> 0 | L >>> 0 > O >>> 0) {
                        n = 0;
                    } else {
                        break;
                    }
                    return n | 0;
                }
            } while (0);
            L413: do {
                if ((c[319] & 4 | 0) == 0) {
                    O = c[214] | 0;
                    L415: do {
                        if ((O | 0) == 0) {
                            T = 292;
                        } else {
                            L = O;
                            P = 1280;
                            while (1) {
                                U = P | 0;
                                M = c[U >> 2] | 0;
                                if (M >>> 0 <= L >>> 0) {
                                    V = P + 4 | 0;
                                    if ((M + (c[V >> 2] | 0) | 0) >>> 0 > L >>> 0) {
                                        break;
                                    }
                                }
                                M = c[P + 8 >> 2] | 0;
                                if ((M | 0) == 0) {
                                    T = 292;
                                    break L415;
                                } else {
                                    P = M;
                                }
                            }
                            if ((P | 0) == 0) {
                                T = 292;
                                break;
                            }
                            L = R - (c[211] | 0) & Q;
                            if (L >>> 0 >= 2147483647) {
                                W = 0;
                                break;
                            }
                            m = aV(L | 0) | 0;
                            e = (m | 0) == ((c[U >> 2] | 0) + (c[V >> 2] | 0) | 0);
                            X = e ? m : -1;
                            Y = e ? L : 0;
                            Z = m;
                            _ = L;
                            T = 301;
                        }
                    } while (0);
                    do {
                        if ((T | 0) == 292) {
                            O = aV(0) | 0;
                            if ((O | 0) == -1) {
                                W = 0;
                                break;
                            }
                            g = O;
                            L = c[201] | 0;
                            m = L - 1 | 0;
                            if ((m & g | 0) == 0) {
                                $ = S;
                            } else {
                                $ = S - g + (m + g & -L) | 0;
                            }
                            L = c[316] | 0;
                            g = L + $ | 0;
                            if (!($ >>> 0 > o >>> 0 & $ >>> 0 < 2147483647)) {
                                W = 0;
                                break;
                            }
                            m = c[318] | 0;
                            if ((m | 0) != 0) {
                                if (g >>> 0 <= L >>> 0 | g >>> 0 > m >>> 0) {
                                    W = 0;
                                    break;
                                }
                            }
                            m = aV($ | 0) | 0;
                            g = (m | 0) == (O | 0);
                            X = g ? O : -1;
                            Y = g ? $ : 0;
                            Z = m;
                            _ = $;
                            T = 301;
                        }
                    } while (0);
                    L435: do {
                        if ((T | 0) == 301) {
                            m = -_ | 0;
                            if ((X | 0) != -1) {
                                aa = Y;
                                ab = X;
                                T = 312;
                                break L413;
                            }
                            do {
                                if ((Z | 0) != -1 & _ >>> 0 < 2147483647 & _ >>> 0 < J >>> 0) {
                                    g = c[202] | 0;
                                    O = K - _ + g & -g;
                                    if (O >>> 0 >= 2147483647) {
                                        ac = _;
                                        break;
                                    }
                                    if ((aV(O | 0) | 0) == -1) {
                                        aV(m | 0) | 0;
                                        W = Y;
                                        break L435;
                                    } else {
                                        ac = O + _ | 0;
                                        break;
                                    }
                                } else {
                                    ac = _;
                                }
                            } while (0);
                            if ((Z | 0) == -1) {
                                W = Y;
                            } else {
                                aa = ac;
                                ab = Z;
                                T = 312;
                                break L413;
                            }
                        }
                    } while (0);
                    c[319] = c[319] | 4;
                    ad = W;
                    T = 309;
                } else {
                    ad = 0;
                    T = 309;
                }
            } while (0);
            do {
                if ((T | 0) == 309) {
                    if (S >>> 0 >= 2147483647) {
                        break;
                    }
                    W = aV(S | 0) | 0;
                    Z = aV(0) | 0;
                    if (!((Z | 0) != -1 & (W | 0) != -1 & W >>> 0 < Z >>> 0)) {
                        break;
                    }
                    ac = Z - W | 0;
                    Z = ac >>> 0 > (o + 40 | 0) >>> 0;
                    Y = Z ? W : -1;
                    if ((Y | 0) != -1) {
                        aa = Z ? ac : ad;
                        ab = Y;
                        T = 312;
                    }
                }
            } while (0);
            do {
                if ((T | 0) == 312) {
                    ad = (c[316] | 0) + aa | 0;
                    c[316] = ad;
                    if (ad >>> 0 > (c[317] | 0) >>> 0) {
                        c[317] = ad;
                    }
                    ad = c[214] | 0;
                    L455: do {
                        if ((ad | 0) == 0) {
                            S = c[212] | 0;
                            if ((S | 0) == 0 | ab >>> 0 < S >>> 0) {
                                c[212] = ab;
                            }
                            c[320] = ab;
                            c[321] = aa;
                            c[323] = 0;
                            c[217] = c[200];
                            c[216] = -1;
                            S = 0;
                            do {
                                Y = S << 1;
                                ac = 872 + (Y << 2) | 0;
                                c[872 + (Y + 3 << 2) >> 2] = ac;
                                c[872 + (Y + 2 << 2) >> 2] = ac;
                                S = S + 1 | 0;
                            } while (S >>> 0 < 32);
                            S = ab + 8 | 0;
                            if ((S & 7 | 0) == 0) {
                                ae = 0;
                            } else {
                                ae = -S & 7;
                            }
                            S = aa - 40 - ae | 0;
                            c[214] = ab + ae;
                            c[211] = S;
                            c[ab + (ae + 4) >> 2] = S | 1;
                            c[ab + (aa - 36) >> 2] = 40;
                            c[215] = c[204];
                        } else {
                            S = 1280;
                            while (1) {
                                af = c[S >> 2] | 0;
                                ag = S + 4 | 0;
                                ah = c[ag >> 2] | 0;
                                if ((ab | 0) == (af + ah | 0)) {
                                    T = 324;
                                    break;
                                }
                                ac = c[S + 8 >> 2] | 0;
                                if ((ac | 0) == 0) {
                                    break;
                                } else {
                                    S = ac;
                                }
                            }
                            do {
                                if ((T | 0) == 324) {
                                    if ((c[S + 12 >> 2] & 8 | 0) != 0) {
                                        break;
                                    }
                                    ac = ad;
                                    if (!(ac >>> 0 >= af >>> 0 & ac >>> 0 < ab >>> 0)) {
                                        break;
                                    }
                                    c[ag >> 2] = ah + aa;
                                    ac = c[214] | 0;
                                    Y = (c[211] | 0) + aa | 0;
                                    Z = ac;
                                    W = ac + 8 | 0;
                                    if ((W & 7 | 0) == 0) {
                                        ai = 0;
                                    } else {
                                        ai = -W & 7;
                                    }
                                    W = Y - ai | 0;
                                    c[214] = Z + ai;
                                    c[211] = W;
                                    c[Z + (ai + 4) >> 2] = W | 1;
                                    c[Z + (Y + 4) >> 2] = 40;
                                    c[215] = c[204];
                                    break L455;
                                }
                            } while (0);
                            if (ab >>> 0 < (c[212] | 0) >>> 0) {
                                c[212] = ab;
                            }
                            S = ab + aa | 0;
                            Y = 1280;
                            while (1) {
                                aj = Y | 0;
                                if ((c[aj >> 2] | 0) == (S | 0)) {
                                    T = 334;
                                    break;
                                }
                                Z = c[Y + 8 >> 2] | 0;
                                if ((Z | 0) == 0) {
                                    break;
                                } else {
                                    Y = Z;
                                }
                            }
                            do {
                                if ((T | 0) == 334) {
                                    if ((c[Y + 12 >> 2] & 8 | 0) != 0) {
                                        break;
                                    }
                                    c[aj >> 2] = ab;
                                    S = Y + 4 | 0;
                                    c[S >> 2] = (c[S >> 2] | 0) + aa;
                                    S = ab + 8 | 0;
                                    if ((S & 7 | 0) == 0) {
                                        ak = 0;
                                    } else {
                                        ak = -S & 7;
                                    }
                                    S = ab + (aa + 8) | 0;
                                    if ((S & 7 | 0) == 0) {
                                        al = 0;
                                    } else {
                                        al = -S & 7;
                                    }
                                    S = ab + (al + aa) | 0;
                                    Z = S;
                                    W = ak + o | 0;
                                    ac = ab + W | 0;
                                    _ = ac;
                                    K = S - (ab + ak) - o | 0;
                                    c[ab + (ak + 4) >> 2] = o | 3;
                                    do {
                                        if ((Z | 0) == (c[214] | 0)) {
                                            J = (c[211] | 0) + K | 0;
                                            c[211] = J;
                                            c[214] = _;
                                            c[ab + (W + 4) >> 2] = J | 1;
                                        } else {
                                            if ((Z | 0) == (c[213] | 0)) {
                                                J = (c[210] | 0) + K | 0;
                                                c[210] = J;
                                                c[213] = _;
                                                c[ab + (W + 4) >> 2] = J | 1;
                                                c[ab + (J + W) >> 2] = J;
                                                break;
                                            }
                                            J = aa + 4 | 0;
                                            X = c[ab + (J + al) >> 2] | 0;
                                            if ((X & 3 | 0) == 1) {
                                                $ = X & -8;
                                                V = X >>> 3;
                                                L500: do {
                                                    if (X >>> 0 < 256) {
                                                        U = c[ab + ((al | 8) + aa) >> 2] | 0;
                                                        Q = c[ab + (aa + 12 + al) >> 2] | 0;
                                                        R = 872 + (V << 1 << 2) | 0;
                                                        do {
                                                            if ((U | 0) != (R | 0)) {
                                                                if (U >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                }
                                                                if ((c[U + 12 >> 2] | 0) == (Z | 0)) {
                                                                    break;
                                                                }
                                                                au();
                                                                return 0;
                                                            }
                                                        } while (0);
                                                        if ((Q | 0) == (U | 0)) {
                                                            c[208] = c[208] & ~(1 << V);
                                                            break;
                                                        }
                                                        do {
                                                            if ((Q | 0) == (R | 0)) {
                                                                am = Q + 8 | 0;
                                                            } else {
                                                                if (Q >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                }
                                                                m = Q + 8 | 0;
                                                                if ((c[m >> 2] | 0) == (Z | 0)) {
                                                                    am = m;
                                                                    break;
                                                                }
                                                                au();
                                                                return 0;
                                                            }
                                                        } while (0);
                                                        c[U + 12 >> 2] = Q;
                                                        c[am >> 2] = U;
                                                    } else {
                                                        R = S;
                                                        m = c[ab + ((al | 24) + aa) >> 2] | 0;
                                                        P = c[ab + (aa + 12 + al) >> 2] | 0;
                                                        do {
                                                            if ((P | 0) == (R | 0)) {
                                                                O = al | 16;
                                                                g = ab + (J + O) | 0;
                                                                L = c[g >> 2] | 0;
                                                                if ((L | 0) == 0) {
                                                                    e = ab + (O + aa) | 0;
                                                                    O = c[e >> 2] | 0;
                                                                    if ((O | 0) == 0) {
                                                                        an = 0;
                                                                        break;
                                                                    } else {
                                                                        ao = O;
                                                                        ap = e;
                                                                    }
                                                                } else {
                                                                    ao = L;
                                                                    ap = g;
                                                                }
                                                                while (1) {
                                                                    g = ao + 20 | 0;
                                                                    L = c[g >> 2] | 0;
                                                                    if ((L | 0) != 0) {
                                                                        ao = L;
                                                                        ap = g;
                                                                        continue;
                                                                    }
                                                                    g = ao + 16 | 0;
                                                                    L = c[g >> 2] | 0;
                                                                    if ((L | 0) == 0) {
                                                                        break;
                                                                    } else {
                                                                        ao = L;
                                                                        ap = g;
                                                                    }
                                                                }
                                                                if (ap >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                } else {
                                                                    c[ap >> 2] = 0;
                                                                    an = ao;
                                                                    break;
                                                                }
                                                            } else {
                                                                g = c[ab + ((al | 8) + aa) >> 2] | 0;
                                                                if (g >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                }
                                                                L = g + 12 | 0;
                                                                if ((c[L >> 2] | 0) != (R | 0)) {
                                                                    au();
                                                                    return 0;
                                                                }
                                                                e = P + 8 | 0;
                                                                if ((c[e >> 2] | 0) == (R | 0)) {
                                                                    c[L >> 2] = P;
                                                                    c[e >> 2] = g;
                                                                    an = P;
                                                                    break;
                                                                } else {
                                                                    au();
                                                                    return 0;
                                                                }
                                                            }
                                                        } while (0);
                                                        if ((m | 0) == 0) {
                                                            break;
                                                        }
                                                        P = ab + (aa + 28 + al) | 0;
                                                        U = 1136 + (c[P >> 2] << 2) | 0;
                                                        do {
                                                            if ((R | 0) == (c[U >> 2] | 0)) {
                                                                c[U >> 2] = an;
                                                                if ((an | 0) != 0) {
                                                                    break;
                                                                }
                                                                c[209] = c[209] & ~(1 << c[P >> 2]);
                                                                break L500;
                                                            } else {
                                                                if (m >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                }
                                                                Q = m + 16 | 0;
                                                                if ((c[Q >> 2] | 0) == (R | 0)) {
                                                                    c[Q >> 2] = an;
                                                                } else {
                                                                    c[m + 20 >> 2] = an;
                                                                }
                                                                if ((an | 0) == 0) {
                                                                    break L500;
                                                                }
                                                            }
                                                        } while (0);
                                                        if (an >>> 0 < (c[212] | 0) >>> 0) {
                                                            au();
                                                            return 0;
                                                        }
                                                        c[an + 24 >> 2] = m;
                                                        R = al | 16;
                                                        P = c[ab + (R + aa) >> 2] | 0;
                                                        do {
                                                            if ((P | 0) != 0) {
                                                                if (P >>> 0 < (c[212] | 0) >>> 0) {
                                                                    au();
                                                                    return 0;
                                                                } else {
                                                                    c[an + 16 >> 2] = P;
                                                                    c[P + 24 >> 2] = an;
                                                                    break;
                                                                }
                                                            }
                                                        } while (0);
                                                        P = c[ab + (J + R) >> 2] | 0;
                                                        if ((P | 0) == 0) {
                                                            break;
                                                        }
                                                        if (P >>> 0 < (c[212] | 0) >>> 0) {
                                                            au();
                                                            return 0;
                                                        } else {
                                                            c[an + 20 >> 2] = P;
                                                            c[P + 24 >> 2] = an;
                                                            break;
                                                        }
                                                    }
                                                } while (0);
                                                aq = ab + (($ | al) + aa) | 0;
                                                as = $ + K | 0;
                                            } else {
                                                aq = Z;
                                                as = K;
                                            }
                                            J = aq + 4 | 0;
                                            c[J >> 2] = c[J >> 2] & -2;
                                            c[ab + (W + 4) >> 2] = as | 1;
                                            c[ab + (as + W) >> 2] = as;
                                            J = as >>> 3;
                                            if (as >>> 0 < 256) {
                                                V = J << 1;
                                                X = 872 + (V << 2) | 0;
                                                P = c[208] | 0;
                                                m = 1 << J;
                                                do {
                                                    if ((P & m | 0) == 0) {
                                                        c[208] = P | m;
                                                        at = X;
                                                        av = 872 + (V + 2 << 2) | 0;
                                                    } else {
                                                        J = 872 + (V + 2 << 2) | 0;
                                                        U = c[J >> 2] | 0;
                                                        if (U >>> 0 >= (c[212] | 0) >>> 0) {
                                                            at = U;
                                                            av = J;
                                                            break;
                                                        }
                                                        au();
                                                        return 0;
                                                    }
                                                } while (0);
                                                c[av >> 2] = _;
                                                c[at + 12 >> 2] = _;
                                                c[ab + (W + 8) >> 2] = at;
                                                c[ab + (W + 12) >> 2] = X;
                                                break;
                                            }
                                            V = ac;
                                            m = as >>> 8;
                                            do {
                                                if ((m | 0) == 0) {
                                                    aw = 0;
                                                } else {
                                                    if (as >>> 0 > 16777215) {
                                                        aw = 31;
                                                        break;
                                                    }
                                                    P = (m + 1048320 | 0) >>> 16 & 8;
                                                    $ = m << P;
                                                    J = ($ + 520192 | 0) >>> 16 & 4;
                                                    U = $ << J;
                                                    $ = (U + 245760 | 0) >>> 16 & 2;
                                                    Q = 14 - (J | P | $) + (U << $ >>> 15) | 0;
                                                    aw = as >>> ((Q + 7 | 0) >>> 0) & 1 | Q << 1;
                                                }
                                            } while (0);
                                            m = 1136 + (aw << 2) | 0;
                                            c[ab + (W + 28) >> 2] = aw;
                                            c[ab + (W + 20) >> 2] = 0;
                                            c[ab + (W + 16) >> 2] = 0;
                                            X = c[209] | 0;
                                            Q = 1 << aw;
                                            if ((X & Q | 0) == 0) {
                                                c[209] = X | Q;
                                                c[m >> 2] = V;
                                                c[ab + (W + 24) >> 2] = m;
                                                c[ab + (W + 12) >> 2] = V;
                                                c[ab + (W + 8) >> 2] = V;
                                                break;
                                            }
                                            if ((aw | 0) == 31) {
                                                ax = 0;
                                            } else {
                                                ax = 25 - (aw >>> 1) | 0;
                                            }
                                            Q = as << ax;
                                            X = c[m >> 2] | 0;
                                            while (1) {
                                                if ((c[X + 4 >> 2] & -8 | 0) == (as | 0)) {
                                                    break;
                                                }
                                                ay = X + 16 + (Q >>> 31 << 2) | 0;
                                                m = c[ay >> 2] | 0;
                                                if ((m | 0) == 0) {
                                                    T = 407;
                                                    break;
                                                } else {
                                                    Q = Q << 1;
                                                    X = m;
                                                }
                                            }
                                            if ((T | 0) == 407) {
                                                if (ay >>> 0 < (c[212] | 0) >>> 0) {
                                                    au();
                                                    return 0;
                                                } else {
                                                    c[ay >> 2] = V;
                                                    c[ab + (W + 24) >> 2] = X;
                                                    c[ab + (W + 12) >> 2] = V;
                                                    c[ab + (W + 8) >> 2] = V;
                                                    break;
                                                }
                                            }
                                            Q = X + 8 | 0;
                                            m = c[Q >> 2] | 0;
                                            $ = c[212] | 0;
                                            if (X >>> 0 < $ >>> 0) {
                                                au();
                                                return 0;
                                            }
                                            if (m >>> 0 < $ >>> 0) {
                                                au();
                                                return 0;
                                            } else {
                                                c[m + 12 >> 2] = V;
                                                c[Q >> 2] = V;
                                                c[ab + (W + 8) >> 2] = m;
                                                c[ab + (W + 12) >> 2] = X;
                                                c[ab + (W + 24) >> 2] = 0;
                                                break;
                                            }
                                        }
                                    } while (0);
                                    n = ab + (ak | 8) | 0;
                                    return n | 0;
                                }
                            } while (0);
                            Y = ad;
                            W = 1280;
                            while (1) {
                                az = c[W >> 2] | 0;
                                if (az >>> 0 <= Y >>> 0) {
                                    aA = c[W + 4 >> 2] | 0;
                                    aB = az + aA | 0;
                                    if (aB >>> 0 > Y >>> 0) {
                                        break;
                                    }
                                }
                                W = c[W + 8 >> 2] | 0;
                            }
                            W = az + (aA - 39) | 0;
                            if ((W & 7 | 0) == 0) {
                                aC = 0;
                            } else {
                                aC = -W & 7;
                            }
                            W = az + (aA - 47 + aC) | 0;
                            ac = W >>> 0 < (ad + 16 | 0) >>> 0 ? Y : W;
                            W = ac + 8 | 0;
                            _ = ab + 8 | 0;
                            if ((_ & 7 | 0) == 0) {
                                aD = 0;
                            } else {
                                aD = -_ & 7;
                            }
                            _ = aa - 40 - aD | 0;
                            c[214] = ab + aD;
                            c[211] = _;
                            c[ab + (aD + 4) >> 2] = _ | 1;
                            c[ab + (aa - 36) >> 2] = 40;
                            c[215] = c[204];
                            c[ac + 4 >> 2] = 27;
                            c[W >> 2] = c[320];
                            c[W + 4 >> 2] = c[1284 >> 2];
                            c[W + 8 >> 2] = c[1288 >> 2];
                            c[W + 12 >> 2] = c[1292 >> 2];
                            c[320] = ab;
                            c[321] = aa;
                            c[323] = 0;
                            c[322] = W;
                            W = ac + 28 | 0;
                            c[W >> 2] = 7;
                            if ((ac + 32 | 0) >>> 0 < aB >>> 0) {
                                _ = W;
                                while (1) {
                                    W = _ + 4 | 0;
                                    c[W >> 2] = 7;
                                    if ((_ + 8 | 0) >>> 0 < aB >>> 0) {
                                        _ = W;
                                    } else {
                                        break;
                                    }
                                }
                            }
                            if ((ac | 0) == (Y | 0)) {
                                break;
                            }
                            _ = ac - ad | 0;
                            W = Y + (_ + 4) | 0;
                            c[W >> 2] = c[W >> 2] & -2;
                            c[ad + 4 >> 2] = _ | 1;
                            c[Y + _ >> 2] = _;
                            W = _ >>> 3;
                            if (_ >>> 0 < 256) {
                                K = W << 1;
                                Z = 872 + (K << 2) | 0;
                                S = c[208] | 0;
                                m = 1 << W;
                                do {
                                    if ((S & m | 0) == 0) {
                                        c[208] = S | m;
                                        aE = Z;
                                        aF = 872 + (K + 2 << 2) | 0;
                                    } else {
                                        W = 872 + (K + 2 << 2) | 0;
                                        Q = c[W >> 2] | 0;
                                        if (Q >>> 0 >= (c[212] | 0) >>> 0) {
                                            aE = Q;
                                            aF = W;
                                            break;
                                        }
                                        au();
                                        return 0;
                                    }
                                } while (0);
                                c[aF >> 2] = ad;
                                c[aE + 12 >> 2] = ad;
                                c[ad + 8 >> 2] = aE;
                                c[ad + 12 >> 2] = Z;
                                break;
                            }
                            K = ad;
                            m = _ >>> 8;
                            do {
                                if ((m | 0) == 0) {
                                    aG = 0;
                                } else {
                                    if (_ >>> 0 > 16777215) {
                                        aG = 31;
                                        break;
                                    }
                                    S = (m + 1048320 | 0) >>> 16 & 8;
                                    Y = m << S;
                                    ac = (Y + 520192 | 0) >>> 16 & 4;
                                    W = Y << ac;
                                    Y = (W + 245760 | 0) >>> 16 & 2;
                                    Q = 14 - (ac | S | Y) + (W << Y >>> 15) | 0;
                                    aG = _ >>> ((Q + 7 | 0) >>> 0) & 1 | Q << 1;
                                }
                            } while (0);
                            m = 1136 + (aG << 2) | 0;
                            c[ad + 28 >> 2] = aG;
                            c[ad + 20 >> 2] = 0;
                            c[ad + 16 >> 2] = 0;
                            Z = c[209] | 0;
                            Q = 1 << aG;
                            if ((Z & Q | 0) == 0) {
                                c[209] = Z | Q;
                                c[m >> 2] = K;
                                c[ad + 24 >> 2] = m;
                                c[ad + 12 >> 2] = ad;
                                c[ad + 8 >> 2] = ad;
                                break;
                            }
                            if ((aG | 0) == 31) {
                                aH = 0;
                            } else {
                                aH = 25 - (aG >>> 1) | 0;
                            }
                            Q = _ << aH;
                            Z = c[m >> 2] | 0;
                            while (1) {
                                if ((c[Z + 4 >> 2] & -8 | 0) == (_ | 0)) {
                                    break;
                                }
                                aI = Z + 16 + (Q >>> 31 << 2) | 0;
                                m = c[aI >> 2] | 0;
                                if ((m | 0) == 0) {
                                    T = 442;
                                    break;
                                } else {
                                    Q = Q << 1;
                                    Z = m;
                                }
                            }
                            if ((T | 0) == 442) {
                                if (aI >>> 0 < (c[212] | 0) >>> 0) {
                                    au();
                                    return 0;
                                } else {
                                    c[aI >> 2] = K;
                                    c[ad + 24 >> 2] = Z;
                                    c[ad + 12 >> 2] = ad;
                                    c[ad + 8 >> 2] = ad;
                                    break;
                                }
                            }
                            Q = Z + 8 | 0;
                            _ = c[Q >> 2] | 0;
                            m = c[212] | 0;
                            if (Z >>> 0 < m >>> 0) {
                                au();
                                return 0;
                            }
                            if (_ >>> 0 < m >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[_ + 12 >> 2] = K;
                                c[Q >> 2] = K;
                                c[ad + 8 >> 2] = _;
                                c[ad + 12 >> 2] = Z;
                                c[ad + 24 >> 2] = 0;
                                break;
                            }
                        }
                    } while (0);
                    ad = c[211] | 0;
                    if (ad >>> 0 <= o >>> 0) {
                        break;
                    }
                    _ = ad - o | 0;
                    c[211] = _;
                    ad = c[214] | 0;
                    Q = ad;
                    c[214] = Q + o;
                    c[Q + (o + 4) >> 2] = _ | 1;
                    c[ad + 4 >> 2] = o | 3;
                    n = ad + 8 | 0;
                    return n | 0;
                }
            } while (0);
            c[(aX() | 0) >> 2] = 12;
            n = 0;
            return n | 0;
        }
        function bM(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0, M = 0, N = 0, O = 0;
            if ((a | 0) == 0) {
                return;
            }
            b = a - 8 | 0;
            d = b;
            e = c[212] | 0;
            if (b >>> 0 < e >>> 0) {
                au();
            }
            f = c[a - 4 >> 2] | 0;
            g = f & 3;
            if ((g | 0) == 1) {
                au();
            }
            h = f & -8;
            i = a + (h - 8) | 0;
            j = i;
            L672: do {
                if ((f & 1 | 0) == 0) {
                    k = c[b >> 2] | 0;
                    if ((g | 0) == 0) {
                        return;
                    }
                    l = -8 - k | 0;
                    m = a + l | 0;
                    n = m;
                    o = k + h | 0;
                    if (m >>> 0 < e >>> 0) {
                        au();
                    }
                    if ((n | 0) == (c[213] | 0)) {
                        p = a + (h - 4) | 0;
                        if ((c[p >> 2] & 3 | 0) != 3) {
                            q = n;
                            r = o;
                            break;
                        }
                        c[210] = o;
                        c[p >> 2] = c[p >> 2] & -2;
                        c[a + (l + 4) >> 2] = o | 1;
                        c[i >> 2] = o;
                        return;
                    }
                    p = k >>> 3;
                    if (k >>> 0 < 256) {
                        k = c[a + (l + 8) >> 2] | 0;
                        s = c[a + (l + 12) >> 2] | 0;
                        t = 872 + (p << 1 << 2) | 0;
                        do {
                            if ((k | 0) != (t | 0)) {
                                if (k >>> 0 < e >>> 0) {
                                    au();
                                }
                                if ((c[k + 12 >> 2] | 0) == (n | 0)) {
                                    break;
                                }
                                au();
                            }
                        } while (0);
                        if ((s | 0) == (k | 0)) {
                            c[208] = c[208] & ~(1 << p);
                            q = n;
                            r = o;
                            break;
                        }
                        do {
                            if ((s | 0) == (t | 0)) {
                                u = s + 8 | 0;
                            } else {
                                if (s >>> 0 < e >>> 0) {
                                    au();
                                }
                                v = s + 8 | 0;
                                if ((c[v >> 2] | 0) == (n | 0)) {
                                    u = v;
                                    break;
                                }
                                au();
                            }
                        } while (0);
                        c[k + 12 >> 2] = s;
                        c[u >> 2] = k;
                        q = n;
                        r = o;
                        break;
                    }
                    t = m;
                    p = c[a + (l + 24) >> 2] | 0;
                    v = c[a + (l + 12) >> 2] | 0;
                    do {
                        if ((v | 0) == (t | 0)) {
                            w = a + (l + 20) | 0;
                            x = c[w >> 2] | 0;
                            if ((x | 0) == 0) {
                                y = a + (l + 16) | 0;
                                z = c[y >> 2] | 0;
                                if ((z | 0) == 0) {
                                    A = 0;
                                    break;
                                } else {
                                    B = z;
                                    C = y;
                                }
                            } else {
                                B = x;
                                C = w;
                            }
                            while (1) {
                                w = B + 20 | 0;
                                x = c[w >> 2] | 0;
                                if ((x | 0) != 0) {
                                    B = x;
                                    C = w;
                                    continue;
                                }
                                w = B + 16 | 0;
                                x = c[w >> 2] | 0;
                                if ((x | 0) == 0) {
                                    break;
                                } else {
                                    B = x;
                                    C = w;
                                }
                            }
                            if (C >>> 0 < e >>> 0) {
                                au();
                            } else {
                                c[C >> 2] = 0;
                                A = B;
                                break;
                            }
                        } else {
                            w = c[a + (l + 8) >> 2] | 0;
                            if (w >>> 0 < e >>> 0) {
                                au();
                            }
                            x = w + 12 | 0;
                            if ((c[x >> 2] | 0) != (t | 0)) {
                                au();
                            }
                            y = v + 8 | 0;
                            if ((c[y >> 2] | 0) == (t | 0)) {
                                c[x >> 2] = v;
                                c[y >> 2] = w;
                                A = v;
                                break;
                            } else {
                                au();
                            }
                        }
                    } while (0);
                    if ((p | 0) == 0) {
                        q = n;
                        r = o;
                        break;
                    }
                    v = a + (l + 28) | 0;
                    m = 1136 + (c[v >> 2] << 2) | 0;
                    do {
                        if ((t | 0) == (c[m >> 2] | 0)) {
                            c[m >> 2] = A;
                            if ((A | 0) != 0) {
                                break;
                            }
                            c[209] = c[209] & ~(1 << c[v >> 2]);
                            q = n;
                            r = o;
                            break L672;
                        } else {
                            if (p >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            }
                            k = p + 16 | 0;
                            if ((c[k >> 2] | 0) == (t | 0)) {
                                c[k >> 2] = A;
                            } else {
                                c[p + 20 >> 2] = A;
                            }
                            if ((A | 0) == 0) {
                                q = n;
                                r = o;
                                break L672;
                            }
                        }
                    } while (0);
                    if (A >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                    }
                    c[A + 24 >> 2] = p;
                    t = c[a + (l + 16) >> 2] | 0;
                    do {
                        if ((t | 0) != 0) {
                            if (t >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            } else {
                                c[A + 16 >> 2] = t;
                                c[t + 24 >> 2] = A;
                                break;
                            }
                        }
                    } while (0);
                    t = c[a + (l + 20) >> 2] | 0;
                    if ((t | 0) == 0) {
                        q = n;
                        r = o;
                        break;
                    }
                    if (t >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                    } else {
                        c[A + 20 >> 2] = t;
                        c[t + 24 >> 2] = A;
                        q = n;
                        r = o;
                        break;
                    }
                } else {
                    q = d;
                    r = h;
                }
            } while (0);
            d = q;
            if (d >>> 0 >= i >>> 0) {
                au();
            }
            A = a + (h - 4) | 0;
            e = c[A >> 2] | 0;
            if ((e & 1 | 0) == 0) {
                au();
            }
            do {
                if ((e & 2 | 0) == 0) {
                    if ((j | 0) == (c[214] | 0)) {
                        B = (c[211] | 0) + r | 0;
                        c[211] = B;
                        c[214] = q;
                        c[q + 4 >> 2] = B | 1;
                        if ((q | 0) == (c[213] | 0)) {
                            c[213] = 0;
                            c[210] = 0;
                        }
                        if (B >>> 0 <= (c[215] | 0) >>> 0) {
                            return;
                        }
                        bS(0) | 0;
                        return;
                    }
                    if ((j | 0) == (c[213] | 0)) {
                        B = (c[210] | 0) + r | 0;
                        c[210] = B;
                        c[213] = q;
                        c[q + 4 >> 2] = B | 1;
                        c[d + B >> 2] = B;
                        return;
                    }
                    B = (e & -8) + r | 0;
                    C = e >>> 3;
                    L777: do {
                        if (e >>> 0 < 256) {
                            u = c[a + h >> 2] | 0;
                            g = c[a + (h | 4) >> 2] | 0;
                            b = 872 + (C << 1 << 2) | 0;
                            do {
                                if ((u | 0) != (b | 0)) {
                                    if (u >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    }
                                    if ((c[u + 12 >> 2] | 0) == (j | 0)) {
                                        break;
                                    }
                                    au();
                                }
                            } while (0);
                            if ((g | 0) == (u | 0)) {
                                c[208] = c[208] & ~(1 << C);
                                break;
                            }
                            do {
                                if ((g | 0) == (b | 0)) {
                                    D = g + 8 | 0;
                                } else {
                                    if (g >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    }
                                    f = g + 8 | 0;
                                    if ((c[f >> 2] | 0) == (j | 0)) {
                                        D = f;
                                        break;
                                    }
                                    au();
                                }
                            } while (0);
                            c[u + 12 >> 2] = g;
                            c[D >> 2] = u;
                        } else {
                            b = i;
                            f = c[a + (h + 16) >> 2] | 0;
                            t = c[a + (h | 4) >> 2] | 0;
                            do {
                                if ((t | 0) == (b | 0)) {
                                    p = a + (h + 12) | 0;
                                    v = c[p >> 2] | 0;
                                    if ((v | 0) == 0) {
                                        m = a + (h + 8) | 0;
                                        k = c[m >> 2] | 0;
                                        if ((k | 0) == 0) {
                                            E = 0;
                                            break;
                                        } else {
                                            F = k;
                                            G = m;
                                        }
                                    } else {
                                        F = v;
                                        G = p;
                                    }
                                    while (1) {
                                        p = F + 20 | 0;
                                        v = c[p >> 2] | 0;
                                        if ((v | 0) != 0) {
                                            F = v;
                                            G = p;
                                            continue;
                                        }
                                        p = F + 16 | 0;
                                        v = c[p >> 2] | 0;
                                        if ((v | 0) == 0) {
                                            break;
                                        } else {
                                            F = v;
                                            G = p;
                                        }
                                    }
                                    if (G >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    } else {
                                        c[G >> 2] = 0;
                                        E = F;
                                        break;
                                    }
                                } else {
                                    p = c[a + h >> 2] | 0;
                                    if (p >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    }
                                    v = p + 12 | 0;
                                    if ((c[v >> 2] | 0) != (b | 0)) {
                                        au();
                                    }
                                    m = t + 8 | 0;
                                    if ((c[m >> 2] | 0) == (b | 0)) {
                                        c[v >> 2] = t;
                                        c[m >> 2] = p;
                                        E = t;
                                        break;
                                    } else {
                                        au();
                                    }
                                }
                            } while (0);
                            if ((f | 0) == 0) {
                                break;
                            }
                            t = a + (h + 20) | 0;
                            u = 1136 + (c[t >> 2] << 2) | 0;
                            do {
                                if ((b | 0) == (c[u >> 2] | 0)) {
                                    c[u >> 2] = E;
                                    if ((E | 0) != 0) {
                                        break;
                                    }
                                    c[209] = c[209] & ~(1 << c[t >> 2]);
                                    break L777;
                                } else {
                                    if (f >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    }
                                    g = f + 16 | 0;
                                    if ((c[g >> 2] | 0) == (b | 0)) {
                                        c[g >> 2] = E;
                                    } else {
                                        c[f + 20 >> 2] = E;
                                    }
                                    if ((E | 0) == 0) {
                                        break L777;
                                    }
                                }
                            } while (0);
                            if (E >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            }
                            c[E + 24 >> 2] = f;
                            b = c[a + (h + 8) >> 2] | 0;
                            do {
                                if ((b | 0) != 0) {
                                    if (b >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    } else {
                                        c[E + 16 >> 2] = b;
                                        c[b + 24 >> 2] = E;
                                        break;
                                    }
                                }
                            } while (0);
                            b = c[a + (h + 12) >> 2] | 0;
                            if ((b | 0) == 0) {
                                break;
                            }
                            if (b >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            } else {
                                c[E + 20 >> 2] = b;
                                c[b + 24 >> 2] = E;
                                break;
                            }
                        }
                    } while (0);
                    c[q + 4 >> 2] = B | 1;
                    c[d + B >> 2] = B;
                    if ((q | 0) != (c[213] | 0)) {
                        H = B;
                        break;
                    }
                    c[210] = B;
                    return;
                } else {
                    c[A >> 2] = e & -2;
                    c[q + 4 >> 2] = r | 1;
                    c[d + r >> 2] = r;
                    H = r;
                }
            } while (0);
            r = H >>> 3;
            if (H >>> 0 < 256) {
                d = r << 1;
                e = 872 + (d << 2) | 0;
                A = c[208] | 0;
                E = 1 << r;
                do {
                    if ((A & E | 0) == 0) {
                        c[208] = A | E;
                        I = e;
                        J = 872 + (d + 2 << 2) | 0;
                    } else {
                        r = 872 + (d + 2 << 2) | 0;
                        h = c[r >> 2] | 0;
                        if (h >>> 0 >= (c[212] | 0) >>> 0) {
                            I = h;
                            J = r;
                            break;
                        }
                        au();
                    }
                } while (0);
                c[J >> 2] = q;
                c[I + 12 >> 2] = q;
                c[q + 8 >> 2] = I;
                c[q + 12 >> 2] = e;
                return;
            }
            e = q;
            I = H >>> 8;
            do {
                if ((I | 0) == 0) {
                    K = 0;
                } else {
                    if (H >>> 0 > 16777215) {
                        K = 31;
                        break;
                    }
                    J = (I + 1048320 | 0) >>> 16 & 8;
                    d = I << J;
                    E = (d + 520192 | 0) >>> 16 & 4;
                    A = d << E;
                    d = (A + 245760 | 0) >>> 16 & 2;
                    r = 14 - (E | J | d) + (A << d >>> 15) | 0;
                    K = H >>> ((r + 7 | 0) >>> 0) & 1 | r << 1;
                }
            } while (0);
            I = 1136 + (K << 2) | 0;
            c[q + 28 >> 2] = K;
            c[q + 20 >> 2] = 0;
            c[q + 16 >> 2] = 0;
            r = c[209] | 0;
            d = 1 << K;
            do {
                if ((r & d | 0) == 0) {
                    c[209] = r | d;
                    c[I >> 2] = e;
                    c[q + 24 >> 2] = I;
                    c[q + 12 >> 2] = q;
                    c[q + 8 >> 2] = q;
                } else {
                    if ((K | 0) == 31) {
                        L = 0;
                    } else {
                        L = 25 - (K >>> 1) | 0;
                    }
                    A = H << L;
                    J = c[I >> 2] | 0;
                    while (1) {
                        if ((c[J + 4 >> 2] & -8 | 0) == (H | 0)) {
                            break;
                        }
                        M = J + 16 + (A >>> 31 << 2) | 0;
                        E = c[M >> 2] | 0;
                        if ((E | 0) == 0) {
                            N = 621;
                            break;
                        } else {
                            A = A << 1;
                            J = E;
                        }
                    }
                    if ((N | 0) == 621) {
                        if (M >>> 0 < (c[212] | 0) >>> 0) {
                            au();
                        } else {
                            c[M >> 2] = e;
                            c[q + 24 >> 2] = J;
                            c[q + 12 >> 2] = q;
                            c[q + 8 >> 2] = q;
                            break;
                        }
                    }
                    A = J + 8 | 0;
                    B = c[A >> 2] | 0;
                    E = c[212] | 0;
                    if (J >>> 0 < E >>> 0) {
                        au();
                    }
                    if (B >>> 0 < E >>> 0) {
                        au();
                    } else {
                        c[B + 12 >> 2] = e;
                        c[A >> 2] = e;
                        c[q + 8 >> 2] = B;
                        c[q + 12 >> 2] = J;
                        c[q + 24 >> 2] = 0;
                        break;
                    }
                }
            } while (0);
            q = (c[216] | 0) - 1 | 0;
            c[216] = q;
            if ((q | 0) == 0) {
                O = 1288;
            } else {
                return;
            }
            while (1) {
                q = c[O >> 2] | 0;
                if ((q | 0) == 0) {
                    break;
                } else {
                    O = q + 8 | 0;
                }
            }
            c[216] = -1;
            return;
        }
        function bN(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0;
            do {
                if ((a | 0) == 0) {
                    d = 0;
                } else {
                    e = ad(b, a) | 0;
                    if ((b | a) >>> 0 <= 65535) {
                        d = e;
                        break;
                    }
                    d = ((e >>> 0) / (a >>> 0) | 0 | 0) == (b | 0) ? e : -1;
                }
            } while (0);
            b = bL(d) | 0;
            if ((b | 0) == 0) {
                return b | 0;
            }
            if ((c[b - 4 >> 2] & 3 | 0) == 0) {
                return b | 0;
            }
            cL(b | 0, 0, d | 0);
            return b | 0;
        }
        function bO(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0;
            if ((a | 0) == 0) {
                d = bL(b) | 0;
                return d | 0;
            }
            if (b >>> 0 > 4294967231) {
                c[(aX() | 0) >> 2] = 12;
                d = 0;
                return d | 0;
            }
            if (b >>> 0 < 11) {
                e = 16;
            } else {
                e = b + 11 & -8;
            }
            f = bT(a - 8 | 0, e) | 0;
            if ((f | 0) != 0) {
                d = f + 8 | 0;
                return d | 0;
            }
            f = bL(b) | 0;
            if ((f | 0) == 0) {
                d = 0;
                return d | 0;
            }
            e = c[a - 4 >> 2] | 0;
            g = (e & -8) - ((e & 3 | 0) == 0 ? 8 : 4) | 0;
            e = g >>> 0 < b >>> 0 ? g : b;
            cK(f | 0, a | 0, e) | 0;
            bM(a);
            d = f;
            return d | 0;
        }
        function bP(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0;
            if ((a | 0) == 0) {
                return 0;
            }
            if (b >>> 0 > 4294967231) {
                c[(aX() | 0) >> 2] = 12;
                return 0;
            }
            if (b >>> 0 < 11) {
                d = 16;
            } else {
                d = b + 11 & -8;
            }
            b = a - 8 | 0;
            return ((bT(b, d) | 0) == (b | 0) ? a : 0) | 0;
        }
        function bQ(a, b) {
            a = a | 0;
            b = b | 0;
            var c = 0;
            if (a >>> 0 < 9) {
                c = bL(b) | 0;
                return c | 0;
            } else {
                c = bR(a, b) | 0;
                return c | 0;
            }
            return 0;
        }
        function bR(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0;
            d = a >>> 0 < 16 ? 16 : a;
            if ((d - 1 & d | 0) == 0) {
                e = d;
            } else {
                a = 16;
                while (1) {
                    if (a >>> 0 < d >>> 0) {
                        a = a << 1;
                    } else {
                        e = a;
                        break;
                    }
                }
            }
            if ((-64 - e | 0) >>> 0 <= b >>> 0) {
                c[(aX() | 0) >> 2] = 12;
                f = 0;
                return f | 0;
            }
            if (b >>> 0 < 11) {
                g = 16;
            } else {
                g = b + 11 & -8;
            }
            b = bL(e + 12 + g | 0) | 0;
            if ((b | 0) == 0) {
                f = 0;
                return f | 0;
            }
            a = b - 8 | 0;
            d = a;
            h = e - 1 | 0;
            do {
                if ((b & h | 0) == 0) {
                    i = d;
                } else {
                    j = b + h & -e;
                    k = j - 8 | 0;
                    l = a;
                    if ((k - l | 0) >>> 0 > 15) {
                        m = k;
                    } else {
                        m = j + (e - 8) | 0;
                    }
                    j = m;
                    k = m - l | 0;
                    l = b - 4 | 0;
                    n = c[l >> 2] | 0;
                    o = (n & -8) - k | 0;
                    if ((n & 3 | 0) == 0) {
                        c[m >> 2] = (c[a >> 2] | 0) + k;
                        c[m + 4 >> 2] = o;
                        i = j;
                        break;
                    } else {
                        n = m + 4 | 0;
                        c[n >> 2] = o | c[n >> 2] & 1 | 2;
                        n = m + (o + 4) | 0;
                        c[n >> 2] = c[n >> 2] | 1;
                        c[l >> 2] = k | c[l >> 2] & 1 | 2;
                        l = b + (k - 4) | 0;
                        c[l >> 2] = c[l >> 2] | 1;
                        b9(d, k);
                        i = j;
                        break;
                    }
                }
            } while (0);
            d = i + 4 | 0;
            b = c[d >> 2] | 0;
            do {
                if ((b & 3 | 0) != 0) {
                    m = b & -8;
                    if (m >>> 0 <= (g + 16 | 0) >>> 0) {
                        break;
                    }
                    a = m - g | 0;
                    e = i;
                    c[d >> 2] = g | b & 1 | 2;
                    c[e + (g | 4) >> 2] = a | 3;
                    h = e + (m | 4) | 0;
                    c[h >> 2] = c[h >> 2] | 1;
                    b9(e + g | 0, a);
                }
            } while (0);
            f = i + 8 | 0;
            return f | 0;
        }
        function bS(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0;
            do {
                if ((c[200] | 0) == 0) {
                    b = ar(8) | 0;
                    if ((b - 1 & b | 0) == 0) {
                        c[202] = b;
                        c[201] = b;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                        return 0;
                    }
                }
            } while (0);
            if (a >>> 0 >= 4294967232) {
                d = 0;
                return d | 0;
            }
            b = c[214] | 0;
            if ((b | 0) == 0) {
                d = 0;
                return d | 0;
            }
            e = c[211] | 0;
            do {
                if (e >>> 0 > (a + 40 | 0) >>> 0) {
                    f = c[202] | 0;
                    g = ad((((-40 - a - 1 + e + f | 0) >>> 0) / (f >>> 0) | 0) - 1 | 0, f) | 0;
                    h = b;
                    i = 1280;
                    while (1) {
                        j = c[i >> 2] | 0;
                        if (j >>> 0 <= h >>> 0) {
                            if ((j + (c[i + 4 >> 2] | 0) | 0) >>> 0 > h >>> 0) {
                                k = i;
                                break;
                            }
                        }
                        j = c[i + 8 >> 2] | 0;
                        if ((j | 0) == 0) {
                            k = 0;
                            break;
                        } else {
                            i = j;
                        }
                    }
                    if ((c[k + 12 >> 2] & 8 | 0) != 0) {
                        break;
                    }
                    i = aV(0) | 0;
                    h = k + 4 | 0;
                    if ((i | 0) != ((c[k >> 2] | 0) + (c[h >> 2] | 0) | 0)) {
                        break;
                    }
                    j = aV(-(g >>> 0 > 2147483646 ? -2147483648 - f | 0 : g) | 0) | 0;
                    l = aV(0) | 0;
                    if (!((j | 0) != -1 & l >>> 0 < i >>> 0)) {
                        break;
                    }
                    j = i - l | 0;
                    if ((i | 0) == (l | 0)) {
                        break;
                    }
                    c[h >> 2] = (c[h >> 2] | 0) - j;
                    c[316] = (c[316] | 0) - j;
                    h = c[214] | 0;
                    m = (c[211] | 0) - j | 0;
                    j = h;
                    n = h + 8 | 0;
                    if ((n & 7 | 0) == 0) {
                        o = 0;
                    } else {
                        o = -n & 7;
                    }
                    n = m - o | 0;
                    c[214] = j + o;
                    c[211] = n;
                    c[j + (o + 4) >> 2] = n | 1;
                    c[j + (m + 4) >> 2] = 40;
                    c[215] = c[204];
                    d = (i | 0) != (l | 0) | 0;
                    return d | 0;
                }
            } while (0);
            if ((c[211] | 0) >>> 0 <= (c[215] | 0) >>> 0) {
                d = 0;
                return d | 0;
            }
            c[215] = -1;
            d = 0;
            return d | 0;
        }
        function bT(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0;
            d = a + 4 | 0;
            e = c[d >> 2] | 0;
            f = e & -8;
            g = a;
            h = g + f | 0;
            i = h;
            j = c[212] | 0;
            if (g >>> 0 < j >>> 0) {
                au();
                return 0;
            }
            k = e & 3;
            if (!((k | 0) != 1 & g >>> 0 < h >>> 0)) {
                au();
                return 0;
            }
            l = g + (f | 4) | 0;
            m = c[l >> 2] | 0;
            if ((m & 1 | 0) == 0) {
                au();
                return 0;
            }
            if ((k | 0) == 0) {
                if (b >>> 0 < 256) {
                    n = 0;
                    return n | 0;
                }
                do {
                    if (f >>> 0 >= (b + 4 | 0) >>> 0) {
                        if ((f - b | 0) >>> 0 > c[202] << 1 >>> 0) {
                            break;
                        } else {
                            n = a;
                        }
                        return n | 0;
                    }
                } while (0);
                n = 0;
                return n | 0;
            }
            if (f >>> 0 >= b >>> 0) {
                k = f - b | 0;
                if (k >>> 0 <= 15) {
                    n = a;
                    return n | 0;
                }
                c[d >> 2] = e & 1 | b | 2;
                c[g + (b + 4) >> 2] = k | 3;
                c[l >> 2] = c[l >> 2] | 1;
                b9(g + b | 0, k);
                n = a;
                return n | 0;
            }
            if ((i | 0) == (c[214] | 0)) {
                k = (c[211] | 0) + f | 0;
                if (k >>> 0 <= b >>> 0) {
                    n = 0;
                    return n | 0;
                }
                l = k - b | 0;
                c[d >> 2] = e & 1 | b | 2;
                c[g + (b + 4) >> 2] = l | 1;
                c[214] = g + b;
                c[211] = l;
                n = a;
                return n | 0;
            }
            if ((i | 0) == (c[213] | 0)) {
                l = (c[210] | 0) + f | 0;
                if (l >>> 0 < b >>> 0) {
                    n = 0;
                    return n | 0;
                }
                k = l - b | 0;
                if (k >>> 0 > 15) {
                    c[d >> 2] = e & 1 | b | 2;
                    c[g + (b + 4) >> 2] = k | 1;
                    c[g + l >> 2] = k;
                    o = g + (l + 4) | 0;
                    c[o >> 2] = c[o >> 2] & -2;
                    p = g + b | 0;
                    q = k;
                } else {
                    c[d >> 2] = e & 1 | l | 2;
                    e = g + (l + 4) | 0;
                    c[e >> 2] = c[e >> 2] | 1;
                    p = 0;
                    q = 0;
                }
                c[210] = q;
                c[213] = p;
                n = a;
                return n | 0;
            }
            if ((m & 2 | 0) != 0) {
                n = 0;
                return n | 0;
            }
            p = (m & -8) + f | 0;
            if (p >>> 0 < b >>> 0) {
                n = 0;
                return n | 0;
            }
            q = p - b | 0;
            e = m >>> 3;
            L1056: do {
                if (m >>> 0 < 256) {
                    l = c[g + (f + 8) >> 2] | 0;
                    k = c[g + (f + 12) >> 2] | 0;
                    o = 872 + (e << 1 << 2) | 0;
                    do {
                        if ((l | 0) != (o | 0)) {
                            if (l >>> 0 < j >>> 0) {
                                au();
                                return 0;
                            }
                            if ((c[l + 12 >> 2] | 0) == (i | 0)) {
                                break;
                            }
                            au();
                            return 0;
                        }
                    } while (0);
                    if ((k | 0) == (l | 0)) {
                        c[208] = c[208] & ~(1 << e);
                        break;
                    }
                    do {
                        if ((k | 0) == (o | 0)) {
                            r = k + 8 | 0;
                        } else {
                            if (k >>> 0 < j >>> 0) {
                                au();
                                return 0;
                            }
                            s = k + 8 | 0;
                            if ((c[s >> 2] | 0) == (i | 0)) {
                                r = s;
                                break;
                            }
                            au();
                            return 0;
                        }
                    } while (0);
                    c[l + 12 >> 2] = k;
                    c[r >> 2] = l;
                } else {
                    o = h;
                    s = c[g + (f + 24) >> 2] | 0;
                    t = c[g + (f + 12) >> 2] | 0;
                    do {
                        if ((t | 0) == (o | 0)) {
                            u = g + (f + 20) | 0;
                            v = c[u >> 2] | 0;
                            if ((v | 0) == 0) {
                                w = g + (f + 16) | 0;
                                x = c[w >> 2] | 0;
                                if ((x | 0) == 0) {
                                    y = 0;
                                    break;
                                } else {
                                    z = x;
                                    A = w;
                                }
                            } else {
                                z = v;
                                A = u;
                            }
                            while (1) {
                                u = z + 20 | 0;
                                v = c[u >> 2] | 0;
                                if ((v | 0) != 0) {
                                    z = v;
                                    A = u;
                                    continue;
                                }
                                u = z + 16 | 0;
                                v = c[u >> 2] | 0;
                                if ((v | 0) == 0) {
                                    break;
                                } else {
                                    z = v;
                                    A = u;
                                }
                            }
                            if (A >>> 0 < j >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[A >> 2] = 0;
                                y = z;
                                break;
                            }
                        } else {
                            u = c[g + (f + 8) >> 2] | 0;
                            if (u >>> 0 < j >>> 0) {
                                au();
                                return 0;
                            }
                            v = u + 12 | 0;
                            if ((c[v >> 2] | 0) != (o | 0)) {
                                au();
                                return 0;
                            }
                            w = t + 8 | 0;
                            if ((c[w >> 2] | 0) == (o | 0)) {
                                c[v >> 2] = t;
                                c[w >> 2] = u;
                                y = t;
                                break;
                            } else {
                                au();
                                return 0;
                            }
                        }
                    } while (0);
                    if ((s | 0) == 0) {
                        break;
                    }
                    t = g + (f + 28) | 0;
                    l = 1136 + (c[t >> 2] << 2) | 0;
                    do {
                        if ((o | 0) == (c[l >> 2] | 0)) {
                            c[l >> 2] = y;
                            if ((y | 0) != 0) {
                                break;
                            }
                            c[209] = c[209] & ~(1 << c[t >> 2]);
                            break L1056;
                        } else {
                            if (s >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            }
                            k = s + 16 | 0;
                            if ((c[k >> 2] | 0) == (o | 0)) {
                                c[k >> 2] = y;
                            } else {
                                c[s + 20 >> 2] = y;
                            }
                            if ((y | 0) == 0) {
                                break L1056;
                            }
                        }
                    } while (0);
                    if (y >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                        return 0;
                    }
                    c[y + 24 >> 2] = s;
                    o = c[g + (f + 16) >> 2] | 0;
                    do {
                        if ((o | 0) != 0) {
                            if (o >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                                return 0;
                            } else {
                                c[y + 16 >> 2] = o;
                                c[o + 24 >> 2] = y;
                                break;
                            }
                        }
                    } while (0);
                    o = c[g + (f + 20) >> 2] | 0;
                    if ((o | 0) == 0) {
                        break;
                    }
                    if (o >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                        return 0;
                    } else {
                        c[y + 20 >> 2] = o;
                        c[o + 24 >> 2] = y;
                        break;
                    }
                }
            } while (0);
            if (q >>> 0 < 16) {
                c[d >> 2] = p | c[d >> 2] & 1 | 2;
                y = g + (p | 4) | 0;
                c[y >> 2] = c[y >> 2] | 1;
                n = a;
                return n | 0;
            } else {
                c[d >> 2] = c[d >> 2] & 1 | b | 2;
                c[g + (b + 4) >> 2] = q | 3;
                d = g + (p | 4) | 0;
                c[d >> 2] = c[d >> 2] | 1;
                b9(g + b | 0, q);
                n = a;
                return n | 0;
            }
            return 0;
        }
        function bU() {
            return c[316] | 0;
        }
        function bV() {
            return c[317] | 0;
        }
        function bW() {
            var a = 0;
            a = c[318] | 0;
            return ((a | 0) == 0 ? -1 : a) | 0;
        }
        function bX(a) {
            a = a | 0;
            var b = 0, d = 0;
            if ((a | 0) == -1) {
                b = 0;
            } else {
                d = c[202] | 0;
                b = a - 1 + d & -d;
            }
            c[318] = b;
            return b | 0;
        }
        function bY(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0;
            do {
                if ((a | 0) == 0) {
                    b = 0;
                } else {
                    d = c[a - 4 >> 2] | 0;
                    e = d & 3;
                    if ((e | 0) == 1) {
                        b = 0;
                        break;
                    }
                    b = (d & -8) - ((e | 0) == 0 ? 8 : 4) | 0;
                }
            } while (0);
            return b | 0;
        }
        function bZ(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0, g = 0;
            do {
                if ((b | 0) == 8) {
                    e = bL(d) | 0;
                } else {
                    f = b >>> 2;
                    if ((b & 3 | 0) != 0 | (f | 0) == 0) {
                        g = 22;
                        return g | 0;
                    }
                    if ((f + 1073741823 & f | 0) != 0) {
                        g = 22;
                        return g | 0;
                    }
                    if ((-64 - b | 0) >>> 0 < d >>> 0) {
                        g = 12;
                        return g | 0;
                    } else {
                        e = bR(b >>> 0 < 16 ? 16 : b, d) | 0;
                        break;
                    }
                }
            } while (0);
            if ((e | 0) == 0) {
                g = 12;
                return g | 0;
            }
            c[a >> 2] = e;
            g = 0;
            return g | 0;
        }
        function b_(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = i;
            i = i + 8 | 0;
            f = e | 0;
            c[f >> 2] = b;
            b = b2(a, f, 3, d) | 0;
            i = e;
            return b | 0;
        }
        function b$(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            return b2(a, b, 0, c) | 0;
        }
        function b0(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0;
            if ((c[200] | 0) != 0) {
                b = c[201] | 0;
                d = bQ(b, a) | 0;
                return d | 0;
            }
            e = ar(8) | 0;
            if ((e - 1 & e | 0) != 0) {
                au();
                return 0;
            }
            c[202] = e;
            c[201] = e;
            c[203] = -1;
            c[204] = 2097152;
            c[205] = 0;
            c[319] = 0;
            c[200] = (a_(0) | 0) & -16 ^ 1431655768;
            b = c[201] | 0;
            d = bQ(b, a) | 0;
            return d | 0;
        }
        function b1(a) {
            a = a | 0;
            var b = 0;
            do {
                if ((c[200] | 0) == 0) {
                    b = ar(8) | 0;
                    if ((b - 1 & b | 0) == 0) {
                        c[202] = b;
                        c[201] = b;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                        return 0;
                    }
                }
            } while (0);
            b = c[201] | 0;
            return bQ(b, a - 1 + b & -b) | 0;
        }
        function b2(a, b, d, e) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            e = e | 0;
            var f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0;
            do {
                if ((c[200] | 0) == 0) {
                    f = ar(8) | 0;
                    if ((f - 1 & f | 0) == 0) {
                        c[202] = f;
                        c[201] = f;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                        return 0;
                    }
                }
            } while (0);
            f = (a | 0) == 0;
            do {
                if ((e | 0) == 0) {
                    if (f) {
                        g = bL(0) | 0;
                        return g | 0;
                    } else {
                        h = a << 2;
                        if (h >>> 0 < 11) {
                            i = 0;
                            j = 16;
                            break;
                        }
                        i = 0;
                        j = h + 11 & -8;
                        break;
                    }
                } else {
                    if (f) {
                        g = e;
                    } else {
                        i = e;
                        j = 0;
                        break;
                    }
                    return g | 0;
                }
            } while (0);
            do {
                if ((d & 1 | 0) == 0) {
                    if (f) {
                        k = 0;
                        l = 0;
                        break;
                    } else {
                        m = 0;
                        n = 0;
                    }
                    while (1) {
                        e = c[b + (n << 2) >> 2] | 0;
                        if (e >>> 0 < 11) {
                            o = 16;
                        } else {
                            o = e + 11 & -8;
                        }
                        e = o + m | 0;
                        h = n + 1 | 0;
                        if ((h | 0) == (a | 0)) {
                            k = 0;
                            l = e;
                            break;
                        } else {
                            m = e;
                            n = h;
                        }
                    }
                } else {
                    h = c[b >> 2] | 0;
                    if (h >>> 0 < 11) {
                        p = 16;
                    } else {
                        p = h + 11 & -8;
                    }
                    k = p;
                    l = ad(p, a) | 0;
                }
            } while (0);
            p = bL(j - 4 + l | 0) | 0;
            if ((p | 0) == 0) {
                g = 0;
                return g | 0;
            }
            n = p - 8 | 0;
            m = c[p - 4 >> 2] & -8;
            if ((d & 2 | 0) != 0) {
                cL(p | 0, 0, -4 - j + m | 0);
            }
            if ((i | 0) == 0) {
                c[p + (l - 4) >> 2] = m - l | 3;
                q = p + l | 0;
                r = l;
            } else {
                q = i;
                r = m;
            }
            c[q >> 2] = p;
            p = a - 1 | 0;
            L1216: do {
                if ((p | 0) == 0) {
                    s = n;
                    t = r;
                } else {
                    if ((k | 0) == 0) {
                        u = n;
                        v = r;
                        w = 0;
                    } else {
                        a = n;
                        m = r;
                        i = 0;
                        while (1) {
                            l = m - k | 0;
                            c[a + 4 >> 2] = k | 3;
                            j = a + k | 0;
                            d = i + 1 | 0;
                            c[q + (d << 2) >> 2] = a + (k + 8);
                            if ((d | 0) == (p | 0)) {
                                s = j;
                                t = l;
                                break L1216;
                            } else {
                                a = j;
                                m = l;
                                i = d;
                            }
                        }
                    }
                    while (1) {
                        i = c[b + (w << 2) >> 2] | 0;
                        if (i >>> 0 < 11) {
                            x = 16;
                        } else {
                            x = i + 11 & -8;
                        }
                        i = v - x | 0;
                        c[u + 4 >> 2] = x | 3;
                        m = u + x | 0;
                        a = w + 1 | 0;
                        c[q + (a << 2) >> 2] = u + (x + 8);
                        if ((a | 0) == (p | 0)) {
                            s = m;
                            t = i;
                            break;
                        } else {
                            u = m;
                            v = i;
                            w = a;
                        }
                    }
                }
            } while (0);
            c[s + 4 >> 2] = t | 3;
            g = q;
            return g | 0;
        }
        function b3(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0;
            d = a + (b << 2) | 0;
            L1229: do {
                if ((b | 0) != 0) {
                    e = a;
                    L1230: while (1) {
                        f = c[e >> 2] | 0;
                        L1232: do {
                            if ((f | 0) == 0) {
                                g = e + 4 | 0;
                            } else {
                                h = f - 8 | 0;
                                i = h;
                                j = f - 4 | 0;
                                k = c[j >> 2] & -8;
                                c[e >> 2] = 0;
                                if (h >>> 0 < (c[212] | 0) >>> 0) {
                                    l = 935;
                                    break L1230;
                                }
                                h = c[j >> 2] | 0;
                                if ((h & 3 | 0) == 1) {
                                    l = 936;
                                    break L1230;
                                }
                                m = e + 4 | 0;
                                n = h - 8 & -8;
                                do {
                                    if ((m | 0) != (d | 0)) {
                                        if ((c[m >> 2] | 0) != (f + (n + 8) | 0)) {
                                            break;
                                        }
                                        o = (c[f + (n | 4) >> 2] & -8) + k | 0;
                                        c[j >> 2] = h & 1 | o | 2;
                                        p = f + (o - 4) | 0;
                                        c[p >> 2] = c[p >> 2] | 1;
                                        c[m >> 2] = f;
                                        g = m;
                                        break L1232;
                                    }
                                } while (0);
                                b9(i, k);
                                g = m;
                            }
                        } while (0);
                        if ((g | 0) == (d | 0)) {
                            break L1229;
                        } else {
                            e = g;
                        }
                    }
                    if ((l | 0) == 935) {
                        au();
                        return 0;
                    } else if ((l | 0) == 936) {
                        au();
                        return 0;
                    }
                }
            } while (0);
            if ((c[211] | 0) >>> 0 <= (c[215] | 0) >>> 0) {
                return 0;
            }
            bS(0) | 0;
            return 0;
        }
        function b4(a) {
            a = a | 0;
            var b = 0, d = 0;
            if ((c[200] | 0) != 0) {
                b = bS(a) | 0;
                return b | 0;
            }
            d = ar(8) | 0;
            if ((d - 1 & d | 0) != 0) {
                au();
                return 0;
            }
            c[202] = d;
            c[201] = d;
            c[203] = -1;
            c[204] = 2097152;
            c[205] = 0;
            c[319] = 0;
            c[200] = (a_(0) | 0) & -16 ^ 1431655768;
            b = bS(a) | 0;
            return b | 0;
        }
        function b5(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0;
            do {
                if ((c[200] | 0) == 0) {
                    b = ar(8) | 0;
                    if ((b - 1 & b | 0) == 0) {
                        c[202] = b;
                        c[201] = b;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                    }
                }
            } while (0);
            b = c[214] | 0;
            if ((b | 0) == 0) {
                d = 0;
                e = 0;
                f = 0;
                g = 0;
                h = 0;
                i = 0;
                j = 0;
            } else {
                k = c[211] | 0;
                l = k + 40 | 0;
                m = 1;
                n = l;
                o = l;
                l = 1280;
                while (1) {
                    p = c[l >> 2] | 0;
                    q = p + 8 | 0;
                    if ((q & 7 | 0) == 0) {
                        r = 0;
                    } else {
                        r = -q & 7;
                    }
                    q = p + (c[l + 4 >> 2] | 0) | 0;
                    s = m;
                    t = n;
                    u = o;
                    v = p + r | 0;
                    while (1) {
                        if (v >>> 0 >= q >>> 0 | (v | 0) == (b | 0)) {
                            w = s;
                            x = t;
                            y = u;
                            break;
                        }
                        z = c[v + 4 >> 2] | 0;
                        if ((z | 0) == 7) {
                            w = s;
                            x = t;
                            y = u;
                            break;
                        }
                        A = z & -8;
                        B = A + u | 0;
                        if ((z & 3 | 0) == 1) {
                            C = A + t | 0;
                            D = s + 1 | 0;
                        } else {
                            C = t;
                            D = s;
                        }
                        z = v + A | 0;
                        if (z >>> 0 < p >>> 0) {
                            w = D;
                            x = C;
                            y = B;
                            break;
                        } else {
                            s = D;
                            t = C;
                            u = B;
                            v = z;
                        }
                    }
                    v = c[l + 8 >> 2] | 0;
                    if ((v | 0) == 0) {
                        break;
                    } else {
                        m = w;
                        n = x;
                        o = y;
                        l = v;
                    }
                }
                l = c[316] | 0;
                d = k;
                e = y;
                f = w;
                g = l - y | 0;
                h = c[317] | 0;
                i = l - x | 0;
                j = x;
            }
            c[a >> 2] = e;
            c[a + 4 >> 2] = f;
            f = a + 8 | 0;
            c[f >> 2] = 0;
            c[f + 4 >> 2] = 0;
            c[a + 16 >> 2] = g;
            c[a + 20 >> 2] = h;
            c[a + 24 >> 2] = 0;
            c[a + 28 >> 2] = i;
            c[a + 32 >> 2] = j;
            c[a + 36 >> 2] = d;
            return;
        }
        function b6() {
            var a = 0, b = 0, d = 0, e = 0, f = 0, g = 0, h = 0, j = 0, k = 0, l = 0, m = 0, n = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0;
            a = i;
            do {
                if ((c[200] | 0) == 0) {
                    b = ar(8) | 0;
                    if ((b - 1 & b | 0) == 0) {
                        c[202] = b;
                        c[201] = b;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                    }
                }
            } while (0);
            b = c[214] | 0;
            if ((b | 0) == 0) {
                d = 0;
                e = 0;
                f = 0;
            } else {
                g = c[317] | 0;
                h = c[316] | 0;
                j = h - 40 - (c[211] | 0) | 0;
                k = 1280;
                while (1) {
                    l = c[k >> 2] | 0;
                    m = l + 8 | 0;
                    if ((m & 7 | 0) == 0) {
                        n = 0;
                    } else {
                        n = -m & 7;
                    }
                    m = l + (c[k + 4 >> 2] | 0) | 0;
                    p = j;
                    q = l + n | 0;
                    while (1) {
                        if (q >>> 0 >= m >>> 0 | (q | 0) == (b | 0)) {
                            r = p;
                            break;
                        }
                        s = c[q + 4 >> 2] | 0;
                        if ((s | 0) == 7) {
                            r = p;
                            break;
                        }
                        t = s & -8;
                        u = p - ((s & 3 | 0) == 1 ? t : 0) | 0;
                        s = q + t | 0;
                        if (s >>> 0 < l >>> 0) {
                            r = u;
                            break;
                        } else {
                            p = u;
                            q = s;
                        }
                    }
                    q = c[k + 8 >> 2] | 0;
                    if ((q | 0) == 0) {
                        d = r;
                        e = h;
                        f = g;
                        break;
                    } else {
                        j = r;
                        k = q;
                    }
                }
            }
            av(c[o >> 2] | 0, 520, (y = i, i = i + 8 | 0, c[y >> 2] = f, y) | 0) | 0;
            av(c[o >> 2] | 0, 488, (y = i, i = i + 8 | 0, c[y >> 2] = e, y) | 0) | 0;
            av(c[o >> 2] | 0, 400, (y = i, i = i + 8 | 0, c[y >> 2] = d, y) | 0) | 0;
            i = a;
            return;
        }
        function b7(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0;
            do {
                if ((c[200] | 0) == 0) {
                    d = ar(8) | 0;
                    if ((d - 1 & d | 0) == 0) {
                        c[202] = d;
                        c[201] = d;
                        c[203] = -1;
                        c[204] = 2097152;
                        c[205] = 0;
                        c[319] = 0;
                        c[200] = (a_(0) | 0) & -16 ^ 1431655768;
                        break;
                    } else {
                        au();
                        return 0;
                    }
                }
            } while (0);
            if ((a | 0) == (-1 | 0)) {
                c[204] = b;
                e = 1;
                return e | 0;
            } else if ((a | 0) == (-2 | 0)) {
                if ((c[201] | 0) >>> 0 > b >>> 0) {
                    e = 0;
                    return e | 0;
                }
                if ((b - 1 & b | 0) != 0) {
                    e = 0;
                    return e | 0;
                }
                c[202] = b;
                e = 1;
                return e | 0;
            } else if ((a | 0) == (-3 | 0)) {
                c[203] = b;
                e = 1;
                return e | 0;
            } else {
                e = 0;
                return e | 0;
            }
            return 0;
        }
        function b8() {
            return (F = c[328] | 0, c[328] = F + 0, F) | 0;
        }
        function b9(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0;
            d = a;
            e = d + b | 0;
            f = e;
            g = c[a + 4 >> 2] | 0;
            L1325: do {
                if ((g & 1 | 0) == 0) {
                    h = c[a >> 2] | 0;
                    if ((g & 3 | 0) == 0) {
                        return;
                    }
                    i = d + (-h | 0) | 0;
                    j = i;
                    k = h + b | 0;
                    l = c[212] | 0;
                    if (i >>> 0 < l >>> 0) {
                        au();
                    }
                    if ((j | 0) == (c[213] | 0)) {
                        m = d + (b + 4) | 0;
                        if ((c[m >> 2] & 3 | 0) != 3) {
                            n = j;
                            o = k;
                            break;
                        }
                        c[210] = k;
                        c[m >> 2] = c[m >> 2] & -2;
                        c[d + (4 - h) >> 2] = k | 1;
                        c[e >> 2] = k;
                        return;
                    }
                    m = h >>> 3;
                    if (h >>> 0 < 256) {
                        p = c[d + (8 - h) >> 2] | 0;
                        q = c[d + (12 - h) >> 2] | 0;
                        r = 872 + (m << 1 << 2) | 0;
                        do {
                            if ((p | 0) != (r | 0)) {
                                if (p >>> 0 < l >>> 0) {
                                    au();
                                }
                                if ((c[p + 12 >> 2] | 0) == (j | 0)) {
                                    break;
                                }
                                au();
                            }
                        } while (0);
                        if ((q | 0) == (p | 0)) {
                            c[208] = c[208] & ~(1 << m);
                            n = j;
                            o = k;
                            break;
                        }
                        do {
                            if ((q | 0) == (r | 0)) {
                                s = q + 8 | 0;
                            } else {
                                if (q >>> 0 < l >>> 0) {
                                    au();
                                }
                                t = q + 8 | 0;
                                if ((c[t >> 2] | 0) == (j | 0)) {
                                    s = t;
                                    break;
                                }
                                au();
                            }
                        } while (0);
                        c[p + 12 >> 2] = q;
                        c[s >> 2] = p;
                        n = j;
                        o = k;
                        break;
                    }
                    r = i;
                    m = c[d + (24 - h) >> 2] | 0;
                    t = c[d + (12 - h) >> 2] | 0;
                    do {
                        if ((t | 0) == (r | 0)) {
                            u = 16 - h | 0;
                            v = d + (u + 4) | 0;
                            w = c[v >> 2] | 0;
                            if ((w | 0) == 0) {
                                x = d + u | 0;
                                u = c[x >> 2] | 0;
                                if ((u | 0) == 0) {
                                    y = 0;
                                    break;
                                } else {
                                    z = u;
                                    A = x;
                                }
                            } else {
                                z = w;
                                A = v;
                            }
                            while (1) {
                                v = z + 20 | 0;
                                w = c[v >> 2] | 0;
                                if ((w | 0) != 0) {
                                    z = w;
                                    A = v;
                                    continue;
                                }
                                v = z + 16 | 0;
                                w = c[v >> 2] | 0;
                                if ((w | 0) == 0) {
                                    break;
                                } else {
                                    z = w;
                                    A = v;
                                }
                            }
                            if (A >>> 0 < l >>> 0) {
                                au();
                            } else {
                                c[A >> 2] = 0;
                                y = z;
                                break;
                            }
                        } else {
                            v = c[d + (8 - h) >> 2] | 0;
                            if (v >>> 0 < l >>> 0) {
                                au();
                            }
                            w = v + 12 | 0;
                            if ((c[w >> 2] | 0) != (r | 0)) {
                                au();
                            }
                            x = t + 8 | 0;
                            if ((c[x >> 2] | 0) == (r | 0)) {
                                c[w >> 2] = t;
                                c[x >> 2] = v;
                                y = t;
                                break;
                            } else {
                                au();
                            }
                        }
                    } while (0);
                    if ((m | 0) == 0) {
                        n = j;
                        o = k;
                        break;
                    }
                    t = d + (28 - h) | 0;
                    l = 1136 + (c[t >> 2] << 2) | 0;
                    do {
                        if ((r | 0) == (c[l >> 2] | 0)) {
                            c[l >> 2] = y;
                            if ((y | 0) != 0) {
                                break;
                            }
                            c[209] = c[209] & ~(1 << c[t >> 2]);
                            n = j;
                            o = k;
                            break L1325;
                        } else {
                            if (m >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            }
                            i = m + 16 | 0;
                            if ((c[i >> 2] | 0) == (r | 0)) {
                                c[i >> 2] = y;
                            } else {
                                c[m + 20 >> 2] = y;
                            }
                            if ((y | 0) == 0) {
                                n = j;
                                o = k;
                                break L1325;
                            }
                        }
                    } while (0);
                    if (y >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                    }
                    c[y + 24 >> 2] = m;
                    r = 16 - h | 0;
                    t = c[d + r >> 2] | 0;
                    do {
                        if ((t | 0) != 0) {
                            if (t >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            } else {
                                c[y + 16 >> 2] = t;
                                c[t + 24 >> 2] = y;
                                break;
                            }
                        }
                    } while (0);
                    t = c[d + (r + 4) >> 2] | 0;
                    if ((t | 0) == 0) {
                        n = j;
                        o = k;
                        break;
                    }
                    if (t >>> 0 < (c[212] | 0) >>> 0) {
                        au();
                    } else {
                        c[y + 20 >> 2] = t;
                        c[t + 24 >> 2] = y;
                        n = j;
                        o = k;
                        break;
                    }
                } else {
                    n = a;
                    o = b;
                }
            } while (0);
            a = c[212] | 0;
            if (e >>> 0 < a >>> 0) {
                au();
            }
            y = d + (b + 4) | 0;
            z = c[y >> 2] | 0;
            do {
                if ((z & 2 | 0) == 0) {
                    if ((f | 0) == (c[214] | 0)) {
                        A = (c[211] | 0) + o | 0;
                        c[211] = A;
                        c[214] = n;
                        c[n + 4 >> 2] = A | 1;
                        if ((n | 0) != (c[213] | 0)) {
                            return;
                        }
                        c[213] = 0;
                        c[210] = 0;
                        return;
                    }
                    if ((f | 0) == (c[213] | 0)) {
                        A = (c[210] | 0) + o | 0;
                        c[210] = A;
                        c[213] = n;
                        c[n + 4 >> 2] = A | 1;
                        c[n + A >> 2] = A;
                        return;
                    }
                    A = (z & -8) + o | 0;
                    s = z >>> 3;
                    L1424: do {
                        if (z >>> 0 < 256) {
                            g = c[d + (b + 8) >> 2] | 0;
                            t = c[d + (b + 12) >> 2] | 0;
                            h = 872 + (s << 1 << 2) | 0;
                            do {
                                if ((g | 0) != (h | 0)) {
                                    if (g >>> 0 < a >>> 0) {
                                        au();
                                    }
                                    if ((c[g + 12 >> 2] | 0) == (f | 0)) {
                                        break;
                                    }
                                    au();
                                }
                            } while (0);
                            if ((t | 0) == (g | 0)) {
                                c[208] = c[208] & ~(1 << s);
                                break;
                            }
                            do {
                                if ((t | 0) == (h | 0)) {
                                    B = t + 8 | 0;
                                } else {
                                    if (t >>> 0 < a >>> 0) {
                                        au();
                                    }
                                    m = t + 8 | 0;
                                    if ((c[m >> 2] | 0) == (f | 0)) {
                                        B = m;
                                        break;
                                    }
                                    au();
                                }
                            } while (0);
                            c[g + 12 >> 2] = t;
                            c[B >> 2] = g;
                        } else {
                            h = e;
                            m = c[d + (b + 24) >> 2] | 0;
                            l = c[d + (b + 12) >> 2] | 0;
                            do {
                                if ((l | 0) == (h | 0)) {
                                    i = d + (b + 20) | 0;
                                    p = c[i >> 2] | 0;
                                    if ((p | 0) == 0) {
                                        q = d + (b + 16) | 0;
                                        v = c[q >> 2] | 0;
                                        if ((v | 0) == 0) {
                                            C = 0;
                                            break;
                                        } else {
                                            D = v;
                                            E = q;
                                        }
                                    } else {
                                        D = p;
                                        E = i;
                                    }
                                    while (1) {
                                        i = D + 20 | 0;
                                        p = c[i >> 2] | 0;
                                        if ((p | 0) != 0) {
                                            D = p;
                                            E = i;
                                            continue;
                                        }
                                        i = D + 16 | 0;
                                        p = c[i >> 2] | 0;
                                        if ((p | 0) == 0) {
                                            break;
                                        } else {
                                            D = p;
                                            E = i;
                                        }
                                    }
                                    if (E >>> 0 < a >>> 0) {
                                        au();
                                    } else {
                                        c[E >> 2] = 0;
                                        C = D;
                                        break;
                                    }
                                } else {
                                    i = c[d + (b + 8) >> 2] | 0;
                                    if (i >>> 0 < a >>> 0) {
                                        au();
                                    }
                                    p = i + 12 | 0;
                                    if ((c[p >> 2] | 0) != (h | 0)) {
                                        au();
                                    }
                                    q = l + 8 | 0;
                                    if ((c[q >> 2] | 0) == (h | 0)) {
                                        c[p >> 2] = l;
                                        c[q >> 2] = i;
                                        C = l;
                                        break;
                                    } else {
                                        au();
                                    }
                                }
                            } while (0);
                            if ((m | 0) == 0) {
                                break;
                            }
                            l = d + (b + 28) | 0;
                            g = 1136 + (c[l >> 2] << 2) | 0;
                            do {
                                if ((h | 0) == (c[g >> 2] | 0)) {
                                    c[g >> 2] = C;
                                    if ((C | 0) != 0) {
                                        break;
                                    }
                                    c[209] = c[209] & ~(1 << c[l >> 2]);
                                    break L1424;
                                } else {
                                    if (m >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    }
                                    t = m + 16 | 0;
                                    if ((c[t >> 2] | 0) == (h | 0)) {
                                        c[t >> 2] = C;
                                    } else {
                                        c[m + 20 >> 2] = C;
                                    }
                                    if ((C | 0) == 0) {
                                        break L1424;
                                    }
                                }
                            } while (0);
                            if (C >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            }
                            c[C + 24 >> 2] = m;
                            h = c[d + (b + 16) >> 2] | 0;
                            do {
                                if ((h | 0) != 0) {
                                    if (h >>> 0 < (c[212] | 0) >>> 0) {
                                        au();
                                    } else {
                                        c[C + 16 >> 2] = h;
                                        c[h + 24 >> 2] = C;
                                        break;
                                    }
                                }
                            } while (0);
                            h = c[d + (b + 20) >> 2] | 0;
                            if ((h | 0) == 0) {
                                break;
                            }
                            if (h >>> 0 < (c[212] | 0) >>> 0) {
                                au();
                            } else {
                                c[C + 20 >> 2] = h;
                                c[h + 24 >> 2] = C;
                                break;
                            }
                        }
                    } while (0);
                    c[n + 4 >> 2] = A | 1;
                    c[n + A >> 2] = A;
                    if ((n | 0) != (c[213] | 0)) {
                        F = A;
                        break;
                    }
                    c[210] = A;
                    return;
                } else {
                    c[y >> 2] = z & -2;
                    c[n + 4 >> 2] = o | 1;
                    c[n + o >> 2] = o;
                    F = o;
                }
            } while (0);
            o = F >>> 3;
            if (F >>> 0 < 256) {
                z = o << 1;
                y = 872 + (z << 2) | 0;
                C = c[208] | 0;
                b = 1 << o;
                do {
                    if ((C & b | 0) == 0) {
                        c[208] = C | b;
                        G = y;
                        H = 872 + (z + 2 << 2) | 0;
                    } else {
                        o = 872 + (z + 2 << 2) | 0;
                        d = c[o >> 2] | 0;
                        if (d >>> 0 >= (c[212] | 0) >>> 0) {
                            G = d;
                            H = o;
                            break;
                        }
                        au();
                    }
                } while (0);
                c[H >> 2] = n;
                c[G + 12 >> 2] = n;
                c[n + 8 >> 2] = G;
                c[n + 12 >> 2] = y;
                return;
            }
            y = n;
            G = F >>> 8;
            do {
                if ((G | 0) == 0) {
                    I = 0;
                } else {
                    if (F >>> 0 > 16777215) {
                        I = 31;
                        break;
                    }
                    H = (G + 1048320 | 0) >>> 16 & 8;
                    z = G << H;
                    b = (z + 520192 | 0) >>> 16 & 4;
                    C = z << b;
                    z = (C + 245760 | 0) >>> 16 & 2;
                    o = 14 - (b | H | z) + (C << z >>> 15) | 0;
                    I = F >>> ((o + 7 | 0) >>> 0) & 1 | o << 1;
                }
            } while (0);
            G = 1136 + (I << 2) | 0;
            c[n + 28 >> 2] = I;
            c[n + 20 >> 2] = 0;
            c[n + 16 >> 2] = 0;
            o = c[209] | 0;
            z = 1 << I;
            if ((o & z | 0) == 0) {
                c[209] = o | z;
                c[G >> 2] = y;
                c[n + 24 >> 2] = G;
                c[n + 12 >> 2] = n;
                c[n + 8 >> 2] = n;
                return;
            }
            if ((I | 0) == 31) {
                J = 0;
            } else {
                J = 25 - (I >>> 1) | 0;
            }
            I = F << J;
            J = c[G >> 2] | 0;
            while (1) {
                if ((c[J + 4 >> 2] & -8 | 0) == (F | 0)) {
                    break;
                }
                K = J + 16 + (I >>> 31 << 2) | 0;
                G = c[K >> 2] | 0;
                if ((G | 0) == 0) {
                    L = 1120;
                    break;
                } else {
                    I = I << 1;
                    J = G;
                }
            }
            if ((L | 0) == 1120) {
                if (K >>> 0 < (c[212] | 0) >>> 0) {
                    au();
                }
                c[K >> 2] = y;
                c[n + 24 >> 2] = J;
                c[n + 12 >> 2] = n;
                c[n + 8 >> 2] = n;
                return;
            }
            K = J + 8 | 0;
            L = c[K >> 2] | 0;
            I = c[212] | 0;
            if (J >>> 0 < I >>> 0) {
                au();
            }
            if (L >>> 0 < I >>> 0) {
                au();
            }
            c[L + 12 >> 2] = y;
            c[K >> 2] = y;
            c[n + 8 >> 2] = L;
            c[n + 12 >> 2] = J;
            c[n + 24 >> 2] = 0;
            return;
        }
        function ca(a) {
            a = a | 0;
            var b = 0, d = 0, e = 0;
            b = (a | 0) == 0 ? 1 : a;
            while (1) {
                d = bL(b) | 0;
                if ((d | 0) != 0) {
                    e = 1164;
                    break;
                }
                a = (F = c[328] | 0, c[328] = F + 0, F);
                if ((a | 0) == 0) {
                    break;
                }
                a5[a & 1]();
            }
            if ((e | 0) == 1164) {
                return d | 0;
            }
            d = aJ(4) | 0;
            c[d >> 2] = 560;
            as(d | 0, 688, 6);
            return 0;
        }
        function cb(a, b) {
            a = a | 0;
            b = b | 0;
            return ca(a) | 0;
        }
        function cc(a) {
            a = a | 0;
            return;
        }
        function cd(a) {
            a = a | 0;
            return 360 | 0;
        }
        function ce(a) {
            a = a | 0;
            return 448 | 0;
        }
        function cf(a) {
            a = a | 0;
            return (F = c[328] | 0, c[328] = a, F) | 0;
        }
        function cg(a) {
            a = a | 0;
            c[a >> 2] = 560;
            return;
        }
        function ch(a) {
            a = a | 0;
            c[a >> 2] = 592;
            return;
        }
        function ci(a) {
            a = a | 0;
            if ((a | 0) != 0) {
                bM(a);
            }
            return;
        }
        function cj(a, b) {
            a = a | 0;
            b = b | 0;
            ci(a);
            return;
        }
        function ck(a) {
            a = a | 0;
            ci(a);
            return;
        }
        function cl(a, b) {
            a = a | 0;
            b = b | 0;
            ck(a);
            return;
        }
        function cm(a) {
            a = a | 0;
            ci(a);
            return;
        }
        function cn(a) {
            a = a | 0;
            ci(a);
            return;
        }
        function co(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            return cp(a, b, c, 0, 0, 0) | 0;
        }
        function cp(b, d, e, f, g, h) {
            b = b | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            g = g | 0;
            h = h | 0;
            var j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0, M = 0, N = 0, O = 0, P = 0, Q = 0, R = 0, S = 0, T = 0, U = 0, V = 0, W = 0, X = 0, Y = 0, Z = 0, _ = 0, $ = 0, aa = 0, ab = 0, ac = 0, ad = 0;
            j = i;
            if ((e | 0) == 0) {
                k = -1;
                i = j;
                return k | 0;
            }
            l = c[44] | 0;
            if ((l | 0) == 0) {
                c[196] = 1;
                c[44] = 1;
                m = 1;
                n = 1;
                o = 1190;
            } else {
                p = c[196] | 0;
                q = c[74] | 0;
                if ((q | 0) == -1 | (p | 0) != 0) {
                    m = p;
                    n = l;
                    o = 1190;
                } else {
                    r = q;
                    s = p;
                    t = l;
                }
            }
            if ((o | 0) == 1190) {
                l = (aP(344) | 0) != 0 | 0;
                c[74] = l;
                r = l;
                s = m;
                t = n;
            }
            n = a[e] | 0;
            if (n << 24 >> 24 == 45) {
                u = h | 2;
                o = 1194;
            } else {
                m = (r | 0) != 0 | n << 24 >> 24 == 43 ? h & -2 : h;
                if (n << 24 >> 24 == 43) {
                    u = m;
                    o = 1194;
                } else {
                    v = e;
                    w = m;
                }
            }
            if ((o | 0) == 1194) {
                v = e + 1 | 0;
                w = u;
            }
            c[198] = 0;
            if ((s | 0) == 0) {
                x = t;
                o = 1198;
            } else {
                c[50] = -1;
                c[48] = -1;
                z = t;
                A = s;
                o = 1197;
            }
            while (1) {
                if ((o | 0) == 1197) {
                    o = 0;
                    if ((A | 0) == 0) {
                        x = z;
                        o = 1198;
                        continue;
                    } else {
                        B = z;
                    }
                } else if ((o | 0) == 1198) {
                    o = 0;
                    s = c[40] | 0;
                    if ((a[s] | 0) == 0) {
                        B = x;
                    } else {
                        C = s;
                        D = x;
                        break;
                    }
                }
                c[196] = 0;
                if ((B | 0) >= (b | 0)) {
                    o = 1200;
                    break;
                }
                E = d + (B << 2) | 0;
                F = c[E >> 2] | 0;
                c[40] = F;
                if ((a[F] | 0) == 45) {
                    G = F + 1 | 0;
                    H = a[G] | 0;
                    if (H << 24 >> 24 != 0) {
                        o = 1232;
                        break;
                    }
                    if ((aB(v | 0, 45) | 0) != 0) {
                        o = 1232;
                        break;
                    }
                }
                c[40] = 824;
                if ((w & 2 | 0) != 0) {
                    o = 1217;
                    break;
                }
                if ((w & 1 | 0) == 0) {
                    k = -1;
                    o = 1298;
                    break;
                }
                s = c[48] | 0;
                do {
                    if ((s | 0) == -1) {
                        c[48] = B;
                        I = B;
                        J = 0;
                    } else {
                        t = c[50] | 0;
                        if ((t | 0) == -1) {
                            I = B;
                            J = 0;
                            break;
                        }
                        u = t - s | 0;
                        e = B - t | 0;
                        m = (u | 0) % (e | 0) | 0;
                        if ((m | 0) == 0) {
                            K = e;
                        } else {
                            n = e;
                            h = m;
                            while (1) {
                                m = (n | 0) % (h | 0) | 0;
                                if ((m | 0) == 0) {
                                    K = h;
                                    break;
                                } else {
                                    n = h;
                                    h = m;
                                }
                            }
                        }
                        h = (B - s | 0) / (K | 0) | 0;
                        do {
                            if ((K | 0) > 0) {
                                n = -u | 0;
                                if ((h | 0) > 0) {
                                    L = 0;
                                } else {
                                    M = B;
                                    N = t;
                                    O = s;
                                    P = 0;
                                    break;
                                }
                                do {
                                    m = L + t | 0;
                                    r = d + (m << 2) | 0;
                                    l = 0;
                                    p = m;
                                    m = c[r >> 2] | 0;
                                    while (1) {
                                        q = ((p | 0) < (t | 0) ? e : n) + p | 0;
                                        Q = d + (q << 2) | 0;
                                        R = c[Q >> 2] | 0;
                                        c[Q >> 2] = m;
                                        c[r >> 2] = R;
                                        Q = l + 1 | 0;
                                        if ((Q | 0) < (h | 0)) {
                                            l = Q;
                                            p = q;
                                            m = R;
                                        } else {
                                            break;
                                        }
                                    }
                                    L = L + 1 | 0;
                                } while ((L | 0) < (K | 0));
                                M = c[44] | 0;
                                N = c[50] | 0;
                                O = c[48] | 0;
                                P = c[196] | 0;
                            } else {
                                M = B;
                                N = t;
                                O = s;
                                P = 0;
                            }
                        } while (0);
                        c[48] = M - N + O;
                        c[50] = -1;
                        I = M;
                        J = P;
                    }
                } while (0);
                s = I + 1 | 0;
                c[44] = s;
                z = s;
                A = J;
                o = 1197;
            }
            do {
                if ((o | 0) == 1298) {
                    i = j;
                    return k | 0;
                } else if ((o | 0) == 1232) {
                    J = c[48] | 0;
                    A = c[50] | 0;
                    if ((J | 0) != -1 & (A | 0) == -1) {
                        c[50] = B;
                        S = a[G] | 0;
                        T = B;
                    } else {
                        S = H;
                        T = A;
                    }
                    if (S << 24 >> 24 == 0) {
                        C = F;
                        D = B;
                        break;
                    }
                    c[40] = G;
                    if ((a[G] | 0) != 45) {
                        C = G;
                        D = B;
                        break;
                    }
                    if ((a[F + 2 | 0] | 0) != 0) {
                        C = G;
                        D = B;
                        break;
                    }
                    A = B + 1 | 0;
                    c[44] = A;
                    c[40] = 824;
                    if ((T | 0) != -1) {
                        z = T - J | 0;
                        I = A - T | 0;
                        P = (z | 0) % (I | 0) | 0;
                        if ((P | 0) == 0) {
                            U = I;
                        } else {
                            M = I;
                            O = P;
                            while (1) {
                                P = (M | 0) % (O | 0) | 0;
                                if ((P | 0) == 0) {
                                    U = O;
                                    break;
                                } else {
                                    M = O;
                                    O = P;
                                }
                            }
                        }
                        O = (A - J | 0) / (U | 0) | 0;
                        do {
                            if ((U | 0) > 0) {
                                M = -z | 0;
                                if ((O | 0) > 0) {
                                    V = 0;
                                } else {
                                    W = T;
                                    X = J;
                                    Y = A;
                                    break;
                                }
                                do {
                                    P = V + T | 0;
                                    N = d + (P << 2) | 0;
                                    K = 0;
                                    L = P;
                                    P = c[N >> 2] | 0;
                                    while (1) {
                                        x = ((L | 0) < (T | 0) ? I : M) + L | 0;
                                        s = d + (x << 2) | 0;
                                        t = c[s >> 2] | 0;
                                        c[s >> 2] = P;
                                        c[N >> 2] = t;
                                        s = K + 1 | 0;
                                        if ((s | 0) < (O | 0)) {
                                            K = s;
                                            L = x;
                                            P = t;
                                        } else {
                                            break;
                                        }
                                    }
                                    V = V + 1 | 0;
                                } while ((V | 0) < (U | 0));
                                W = c[50] | 0;
                                X = c[48] | 0;
                                Y = c[44] | 0;
                            } else {
                                W = T;
                                X = J;
                                Y = A;
                            }
                        } while (0);
                        c[44] = X - W + Y;
                    }
                    c[50] = -1;
                    c[48] = -1;
                    k = -1;
                    i = j;
                    return k | 0;
                } else if ((o | 0) == 1200) {
                    c[40] = 824;
                    A = c[50] | 0;
                    J = c[48] | 0;
                    do {
                        if ((A | 0) == -1) {
                            if ((J | 0) == -1) {
                                break;
                            }
                            c[44] = J;
                        } else {
                            O = A - J | 0;
                            I = B - A | 0;
                            z = (O | 0) % (I | 0) | 0;
                            if ((z | 0) == 0) {
                                Z = I;
                            } else {
                                M = I;
                                P = z;
                                while (1) {
                                    z = (M | 0) % (P | 0) | 0;
                                    if ((z | 0) == 0) {
                                        Z = P;
                                        break;
                                    } else {
                                        M = P;
                                        P = z;
                                    }
                                }
                            }
                            P = (B - J | 0) / (Z | 0) | 0;
                            do {
                                if ((Z | 0) > 0) {
                                    M = -O | 0;
                                    if ((P | 0) > 0) {
                                        _ = 0;
                                    } else {
                                        $ = A;
                                        aa = J;
                                        ab = B;
                                        break;
                                    }
                                    do {
                                        z = _ + A | 0;
                                        L = d + (z << 2) | 0;
                                        K = 0;
                                        N = z;
                                        z = c[L >> 2] | 0;
                                        while (1) {
                                            t = ((N | 0) < (A | 0) ? I : M) + N | 0;
                                            x = d + (t << 2) | 0;
                                            s = c[x >> 2] | 0;
                                            c[x >> 2] = z;
                                            c[L >> 2] = s;
                                            x = K + 1 | 0;
                                            if ((x | 0) < (P | 0)) {
                                                K = x;
                                                N = t;
                                                z = s;
                                            } else {
                                                break;
                                            }
                                        }
                                        _ = _ + 1 | 0;
                                    } while ((_ | 0) < (Z | 0));
                                    $ = c[50] | 0;
                                    aa = c[48] | 0;
                                    ab = c[44] | 0;
                                } else {
                                    $ = A;
                                    aa = J;
                                    ab = B;
                                }
                            } while (0);
                            c[44] = aa - $ + ab;
                        }
                    } while (0);
                    c[50] = -1;
                    c[48] = -1;
                    k = -1;
                    i = j;
                    return k | 0;
                } else if ((o | 0) == 1217) {
                    c[44] = B + 1;
                    c[198] = c[E >> 2];
                    k = 1;
                    i = j;
                    return k | 0;
                }
            } while (0);
            E = (f | 0) != 0;
            L1659: do {
                if (E) {
                    if ((C | 0) == (c[d + (D << 2) >> 2] | 0)) {
                        ac = C;
                        break;
                    }
                    B = a[C] | 0;
                    do {
                        if (B << 24 >> 24 == 45) {
                            c[40] = C + 1;
                            ad = 0;
                        } else {
                            if ((w & 4 | 0) == 0) {
                                ac = C;
                                break L1659;
                            }
                            if (B << 24 >> 24 == 58) {
                                ad = 0;
                                break;
                            }
                            ad = (aB(v | 0, B << 24 >> 24 | 0) | 0) != 0 | 0;
                        }
                    } while (0);
                    B = cv(d, v, f, g, ad) | 0;
                    if ((B | 0) == -1) {
                        ac = c[40] | 0;
                        break;
                    }
                    c[40] = 824;
                    k = B;
                    i = j;
                    return k | 0;
                } else {
                    ac = C;
                }
            } while (0);
            C = ac + 1 | 0;
            c[40] = C;
            ad = a[ac] | 0;
            ac = ad << 24 >> 24;
            if ((ad << 24 >> 24 | 0) == 45) {
                if ((a[C] | 0) == 0) {
                    o = 1260;
                }
            } else if ((ad << 24 >> 24 | 0) == 58) {
                o = 1263;
            } else {
                o = 1260;
            }
            do {
                if ((o | 0) == 1260) {
                    w = aB(v | 0, ac | 0) | 0;
                    if ((w | 0) == 0) {
                        if (ad << 24 >> 24 != 45) {
                            o = 1263;
                            break;
                        }
                        if ((a[C] | 0) == 0) {
                            k = -1;
                        } else {
                            break;
                        }
                        i = j;
                        return k | 0;
                    }
                    D = a[w + 1 | 0] | 0;
                    if (E & ad << 24 >> 24 == 87 & D << 24 >> 24 == 59) {
                        do {
                            if ((a[C] | 0) == 0) {
                                B = (c[44] | 0) + 1 | 0;
                                c[44] = B;
                                if ((B | 0) < (b | 0)) {
                                    c[40] = c[d + (B << 2) >> 2];
                                    break;
                                }
                                c[40] = 824;
                                do {
                                    if ((c[46] | 0) != 0) {
                                        if ((a[v] | 0) == 58) {
                                            break;
                                        }
                                        cx(48, (y = i, i = i + 8 | 0, c[y >> 2] = ac, y) | 0);
                                    }
                                } while (0);
                                c[42] = ac;
                                k = (a[v] | 0) == 58 ? 58 : 63;
                                i = j;
                                return k | 0;
                            }
                        } while (0);
                        B = cv(d, v, f, g, 0) | 0;
                        c[40] = 824;
                        k = B;
                        i = j;
                        return k | 0;
                    }
                    if (D << 24 >> 24 != 58) {
                        if ((a[C] | 0) != 0) {
                            k = ac;
                            i = j;
                            return k | 0;
                        }
                        c[44] = (c[44] | 0) + 1;
                        k = ac;
                        i = j;
                        return k | 0;
                    }
                    c[198] = 0;
                    do {
                        if ((a[C] | 0) == 0) {
                            if ((a[w + 2 | 0] | 0) == 58) {
                                break;
                            }
                            B = (c[44] | 0) + 1 | 0;
                            c[44] = B;
                            if ((B | 0) < (b | 0)) {
                                c[198] = c[d + (B << 2) >> 2];
                                break;
                            }
                            c[40] = 824;
                            do {
                                if ((c[46] | 0) != 0) {
                                    if ((a[v] | 0) == 58) {
                                        break;
                                    }
                                    cx(48, (y = i, i = i + 8 | 0, c[y >> 2] = ac, y) | 0);
                                }
                            } while (0);
                            c[42] = ac;
                            k = (a[v] | 0) == 58 ? 58 : 63;
                            i = j;
                            return k | 0;
                        } else {
                            c[198] = C;
                        }
                    } while (0);
                    c[40] = 824;
                    c[44] = (c[44] | 0) + 1;
                    k = ac;
                    i = j;
                    return k | 0;
                }
            } while (0);
            do {
                if ((o | 0) == 1263) {
                    if ((a[C] | 0) != 0) {
                        break;
                    }
                    c[44] = (c[44] | 0) + 1;
                }
            } while (0);
            do {
                if ((c[46] | 0) != 0) {
                    if ((a[v] | 0) == 58) {
                        break;
                    }
                    cx(272, (y = i, i = i + 8 | 0, c[y >> 2] = ac, y) | 0);
                }
            } while (0);
            c[42] = ac;
            k = 63;
            i = j;
            return k | 0;
        }
        function cq(a, b, c, d, e) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            e = e | 0;
            return cp(a, b, c, d, e, 1) | 0;
        }
        function cr(a, b, c, d, e) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            e = e | 0;
            return cp(a, b, c, d, e, 5) | 0;
        }
        function cs(a) {
            a = a | 0;
            return ca(a) | 0;
        }
        function ct(a, b) {
            a = a | 0;
            b = b | 0;
            return cs(a) | 0;
        }
        function cu() {
            var a = 0;
            a = aJ(4) | 0;
            c[a >> 2] = 560;
            as(a | 0, 688, 6);
        }
        function cv(b, d, e, f, g) {
            b = b | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            g = g | 0;
            var h = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, z = 0;
            h = i;
            j = c[40] | 0;
            k = c[44] | 0;
            l = k + 1 | 0;
            c[44] = l;
            m = aB(j | 0, 61) | 0;
            if ((m | 0) == 0) {
                n = cM(j | 0) | 0;
                o = 0;
            } else {
                n = m - j | 0;
                o = m + 1 | 0;
            }
            m = c[e >> 2] | 0;
            L1739: do {
                if ((m | 0) != 0) {
                    L1741: do {
                        if ((g | 0) != 0 & (n | 0) == 1) {
                            p = 0;
                            q = m;
                            while (1) {
                                if ((a[j] | 0) == (a[q] | 0)) {
                                    if ((cM(q | 0) | 0) == 1) {
                                        r = p;
                                        break L1741;
                                    }
                                }
                                p = p + 1 | 0;
                                q = c[e + (p << 4) >> 2] | 0;
                                if ((q | 0) == 0) {
                                    break L1739;
                                }
                            }
                        } else {
                            q = 0;
                            p = -1;
                            s = m;
                            while (1) {
                                if ((ap(j | 0, s | 0, n | 0) | 0) == 0) {
                                    if ((cM(s | 0) | 0) == (n | 0)) {
                                        r = q;
                                        break L1741;
                                    }
                                    if ((p | 0) == -1) {
                                        t = q;
                                    } else {
                                        break;
                                    }
                                } else {
                                    t = p;
                                }
                                u = q + 1 | 0;
                                v = c[e + (u << 4) >> 2] | 0;
                                if ((v | 0) == 0) {
                                    r = t;
                                    break L1741;
                                } else {
                                    q = u;
                                    p = t;
                                    s = v;
                                }
                            }
                            do {
                                if ((c[46] | 0) != 0) {
                                    if ((a[d] | 0) == 58) {
                                        break;
                                    }
                                    cx(304, (y = i, i = i + 16 | 0, c[y >> 2] = n, c[y + 8 >> 2] = j, y) | 0);
                                }
                            } while (0);
                            c[42] = 0;
                            w = 63;
                            i = h;
                            return w | 0;
                        }
                    } while (0);
                    if ((r | 0) == -1) {
                        break;
                    }
                    s = e + (r << 4) + 4 | 0;
                    p = c[s >> 2] | 0;
                    q = (o | 0) == 0;
                    if (!((p | 0) != 0 | q)) {
                        do {
                            if ((c[46] | 0) != 0) {
                                if ((a[d] | 0) == 58) {
                                    break;
                                }
                                cx(208, (y = i, i = i + 16 | 0, c[y >> 2] = n, c[y + 8 >> 2] = j, y) | 0);
                            }
                        } while (0);
                        if ((c[e + (r << 4) + 8 >> 2] | 0) == 0) {
                            x = c[e + (r << 4) + 12 >> 2] | 0;
                        } else {
                            x = 0;
                        }
                        c[42] = x;
                        w = (a[d] | 0) == 58 ? 58 : 63;
                        i = h;
                        return w | 0;
                    }
                    do {
                        if ((p - 1 | 0) >>> 0 < 2) {
                            if (!q) {
                                c[198] = o;
                                break;
                            }
                            if ((p | 0) != 1) {
                                break;
                            }
                            c[44] = k + 2;
                            c[198] = c[b + (l << 2) >> 2];
                        }
                    } while (0);
                    if (!((c[s >> 2] | 0) == 1 & (c[198] | 0) == 0)) {
                        if ((f | 0) != 0) {
                            c[f >> 2] = r;
                        }
                        p = c[e + (r << 4) + 8 >> 2] | 0;
                        q = c[e + (r << 4) + 12 >> 2] | 0;
                        if ((p | 0) == 0) {
                            w = q;
                            i = h;
                            return w | 0;
                        }
                        c[p >> 2] = q;
                        w = 0;
                        i = h;
                        return w | 0;
                    }
                    do {
                        if ((c[46] | 0) != 0) {
                            if ((a[d] | 0) == 58) {
                                break;
                            }
                            cx(8, (y = i, i = i + 8 | 0, c[y >> 2] = j, y) | 0);
                        }
                    } while (0);
                    if ((c[e + (r << 4) + 8 >> 2] | 0) == 0) {
                        z = c[e + (r << 4) + 12 >> 2] | 0;
                    } else {
                        z = 0;
                    }
                    c[42] = z;
                    c[44] = (c[44] | 0) - 1;
                    w = (a[d] | 0) == 58 ? 58 : 63;
                    i = h;
                    return w | 0;
                }
            } while (0);
            if ((g | 0) != 0) {
                c[44] = k;
                w = -1;
                i = h;
                return w | 0;
            }
            do {
                if ((c[46] | 0) != 0) {
                    if ((a[d] | 0) == 58) {
                        break;
                    }
                    cx(248, (y = i, i = i + 8 | 0, c[y >> 2] = j, y) | 0);
                }
            } while (0);
            c[42] = 0;
            w = 63;
            i = h;
            return w | 0;
        }
        function cw(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0;
            d = i;
            i = i + 16 | 0;
            e = d | 0;
            f = e;
            c[f >> 2] = b;
            c[f + 4 >> 2] = 0;
            cy(a, e | 0);
            i = d;
            return;
        }
        function cx(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0;
            d = i;
            i = i + 16 | 0;
            e = d | 0;
            f = e;
            c[f >> 2] = b;
            c[f + 4 >> 2] = 0;
            cz(a, e | 0);
            i = d;
            return;
        }
        function cy(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0, f = 0;
            d = i;
            e = c[(aX() | 0) >> 2] | 0;
            f = c[r >> 2] | 0;
            av(c[o >> 2] | 0, 432, (y = i, i = i + 8 | 0, c[y >> 2] = f, y) | 0) | 0;
            if ((a | 0) != 0) {
                f = c[o >> 2] | 0;
                aQ(f | 0, a | 0, b | 0) | 0;
                b = c[o >> 2] | 0;
                aE(472, 2, 1, b | 0) | 0;
            }
            b = c[o >> 2] | 0;
            a = at(e | 0) | 0;
            av(b | 0, 384, (y = i, i = i + 8 | 0, c[y >> 2] = a, y) | 0) | 0;
            i = d;
            return;
        }
        function cz(a, b) {
            a = a | 0;
            b = b | 0;
            var d = 0, e = 0;
            d = i;
            e = c[r >> 2] | 0;
            av(c[o >> 2] | 0, 376, (y = i, i = i + 8 | 0, c[y >> 2] = e, y) | 0) | 0;
            if ((a | 0) != 0) {
                e = c[o >> 2] | 0;
                aQ(e | 0, a | 0, b | 0) | 0;
            }
            aC(10, c[o >> 2] | 0) | 0;
            i = d;
            return;
        }
        function cA(b, d) {
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0, g = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0, I = 0, J = 0, K = 0, L = 0, M = 0, N = 0, O = 0, P = 0, Q = 0, R = 0, S = 0;
            e = b;
            while (1) {
                f = e + 1 | 0;
                if ((aK(a[e] | 0) | 0) == 0) {
                    break;
                } else {
                    e = f;
                }
            }
            g = a[e] | 0;
            if ((g << 24 >> 24 | 0) == 45) {
                i = f;
                j = 1;
            } else if ((g << 24 >> 24 | 0) == 43) {
                i = f;
                j = 0;
            } else {
                i = e;
                j = 0;
            }
            e = -1;
            f = 0;
            g = i;
            while (1) {
                k = a[g] | 0;
                if (((k << 24 >> 24) - 48 | 0) >>> 0 < 10) {
                    l = e;
                } else {
                    if (k << 24 >> 24 != 46 | (e | 0) > -1) {
                        break;
                    } else {
                        l = f;
                    }
                }
                e = l;
                f = f + 1 | 0;
                g = g + 1 | 0;
            }
            l = g + (-f | 0) | 0;
            i = (e | 0) < 0;
            m = ((i ^ 1) << 31 >> 31) + f | 0;
            n = (m | 0) > 18;
            o = (n ? -18 : -m | 0) + (i ? f : e) | 0;
            e = n ? 18 : m;
            do {
                if ((e | 0) == 0) {
                    p = b;
                    q = 0;
                } else {
                    if ((e | 0) > 9) {
                        m = l;
                        n = e;
                        f = 0;
                        while (1) {
                            i = a[m] | 0;
                            r = m + 1 | 0;
                            if (i << 24 >> 24 == 46) {
                                s = a[r] | 0;
                                t = m + 2 | 0;
                            } else {
                                s = i;
                                t = r;
                            }
                            u = (f * 10 | 0) - 48 + (s << 24 >> 24) | 0;
                            r = n - 1 | 0;
                            if ((r | 0) > 9) {
                                m = t;
                                n = r;
                                f = u;
                            } else {
                                break;
                            }
                        }
                        v = +(u | 0) * 1e9;
                        w = 9;
                        x = t;
                        y = 1393;
                    } else {
                        if ((e | 0) > 0) {
                            v = 0;
                            w = e;
                            x = l;
                            y = 1393;
                        } else {
                            z = 0;
                            A = 0;
                        }
                    }
                    if ((y | 0) == 1393) {
                        f = x;
                        n = w;
                        m = 0;
                        while (1) {
                            r = a[f] | 0;
                            i = f + 1 | 0;
                            if (r << 24 >> 24 == 46) {
                                B = a[i] | 0;
                                C = f + 2 | 0;
                            } else {
                                B = r;
                                C = i;
                            }
                            D = (m * 10 | 0) - 48 + (B << 24 >> 24) | 0;
                            i = n - 1 | 0;
                            if ((i | 0) > 0) {
                                f = C;
                                n = i;
                                m = D;
                            } else {
                                break;
                            }
                        }
                        z = +(D | 0);
                        A = v;
                    }
                    E = A + z;
                    do {
                        if ((k << 24 >> 24 | 0) == 69 | (k << 24 >> 24 | 0) == 101) {
                            m = g + 1 | 0;
                            n = a[m] | 0;
                            if ((n << 24 >> 24 | 0) == 43) {
                                F = g + 2 | 0;
                                G = 0;
                            } else if ((n << 24 >> 24 | 0) == 45) {
                                F = g + 2 | 0;
                                G = 1;
                            } else {
                                F = m;
                                G = 0;
                            }
                            m = a[F] | 0;
                            if (((m << 24 >> 24) - 48 | 0) >>> 0 < 10) {
                                H = F;
                                I = 0;
                                J = m;
                            } else {
                                K = 0;
                                L = F;
                                M = G;
                                break;
                            }
                            while (1) {
                                m = (I * 10 | 0) - 48 + (J << 24 >> 24) | 0;
                                n = H + 1 | 0;
                                f = a[n] | 0;
                                if (((f << 24 >> 24) - 48 | 0) >>> 0 < 10) {
                                    H = n;
                                    I = m;
                                    J = f;
                                } else {
                                    K = m;
                                    L = n;
                                    M = G;
                                    break;
                                }
                            }
                        } else {
                            K = 0;
                            L = g;
                            M = 0;
                        }
                    } while (0);
                    n = o + ((M | 0) == 0 ? K : -K | 0) | 0;
                    m = (n | 0) < 0 ? -n | 0 : n;
                    if ((m | 0) > 511) {
                        c[(aX() | 0) >> 2] = 34;
                        N = 1;
                        O = 88;
                        P = 511;
                        y = 1410;
                    } else {
                        if ((m | 0) == 0) {
                            Q = 1;
                        } else {
                            N = 1;
                            O = 88;
                            P = m;
                            y = 1410;
                        }
                    }
                    if ((y | 0) == 1410) {
                        while (1) {
                            y = 0;
                            if ((P & 1 | 0) == 0) {
                                R = N;
                            } else {
                                R = N * +h[O >> 3];
                            }
                            m = P >> 1;
                            if ((m | 0) == 0) {
                                Q = R;
                                break;
                            } else {
                                N = R;
                                O = O + 8 | 0;
                                P = m;
                                y = 1410;
                            }
                        }
                    }
                    if ((n | 0) > -1) {
                        p = L;
                        q = E * Q;
                        break;
                    } else {
                        p = L;
                        q = E / Q;
                        break;
                    }
                }
            } while (0);
            if ((d | 0) != 0) {
                c[d >> 2] = p;
            }
            if ((j | 0) == 0) {
                S = q;
                return +S;
            }
            S = -0 - q;
            return +S;
        }
        function cB(a, b) {
            a = a | 0;
            b = b | 0;
            return ++cA(a, b);
        }
        function cC(a, b) {
            a = a | 0;
            b = b | 0;
            return ++cA(a, b);
        }
        function cD(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            return ++cA(a, b);
        }
        function cE(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            return ++cA(a, b);
        }
        function cF(a) {
            a = a | 0;
            return ++cA(a, 0);
        }
        function cG(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = i;
            i = i + 16 | 0;
            f = e | 0;
            e = f;
            c[e >> 2] = d;
            c[e + 4 >> 2] = 0;
            cI(a, b, f | 0);
        }
        function cH(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = i;
            i = i + 16 | 0;
            f = e | 0;
            e = f;
            c[e >> 2] = d;
            c[e + 4 >> 2] = 0;
            cJ(a, b, f | 0);
        }
        function cI(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = c[(aX() | 0) >> 2] | 0;
            f = c[r >> 2] | 0;
            av(c[o >> 2] | 0, 336, (y = i, i = i + 8 | 0, c[y >> 2] = f, y) | 0) | 0;
            if ((b | 0) != 0) {
                f = c[o >> 2] | 0;
                aQ(f | 0, b | 0, d | 0) | 0;
                d = c[o >> 2] | 0;
                aE(480, 2, 1, d | 0) | 0;
            }
            d = c[o >> 2] | 0;
            b = at(e | 0) | 0;
            av(d | 0, 392, (y = i, i = i + 8 | 0, c[y >> 2] = b, y) | 0) | 0;
            aH(a | 0);
        }
        function cJ(a, b, d) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            var e = 0;
            e = c[r >> 2] | 0;
            av(c[o >> 2] | 0, 440, (y = i, i = i + 8 | 0, c[y >> 2] = e, y) | 0) | 0;
            if ((b | 0) != 0) {
                e = c[o >> 2] | 0;
                aQ(e | 0, b | 0, d | 0) | 0;
            }
            aC(10, c[o >> 2] | 0) | 0;
            aH(a | 0);
        }
        function cK(b, d, e) {
            b = b | 0;
            d = d | 0;
            e = e | 0;
            var f = 0;
            f = b | 0;
            if ((b & 3) == (d & 3)) {
                while (b & 3) {
                    if ((e | 0) == 0) return f | 0;
                    a[b] = a[d] | 0;
                    b = b + 1 | 0;
                    d = d + 1 | 0;
                    e = e - 1 | 0;
                }
                while ((e | 0) >= 4) {
                    c[b >> 2] = c[d >> 2];
                    b = b + 4 | 0;
                    d = d + 4 | 0;
                    e = e - 4 | 0;
                }
            }
            while ((e | 0) > 0) {
                a[b] = a[d] | 0;
                b = b + 1 | 0;
                d = d + 1 | 0;
                e = e - 1 | 0;
            }
            return f | 0;
        }
        function cL(b, d, e) {
            b = b | 0;
            d = d | 0;
            e = e | 0;
            var f = 0, g = 0, h = 0;
            f = b + e | 0;
            if ((e | 0) >= 20) {
                d = d & 255;
                e = b & 3;
                g = d | d << 8 | d << 16 | d << 24;
                h = f & ~3;
                if (e) {
                    e = b + 4 - e | 0;
                    while ((b | 0) < (e | 0)) {
                        a[b] = d;
                        b = b + 1 | 0;
                    }
                }
                while ((b | 0) < (h | 0)) {
                    c[b >> 2] = g;
                    b = b + 4 | 0;
                }
            }
            while ((b | 0) < (f | 0)) {
                a[b] = d;
                b = b + 1 | 0;
            }
        }
        function cM(b) {
            b = b | 0;
            var c = 0;
            c = b;
            while (a[c] | 0) {
                c = c + 1 | 0;
            }
            return c - b | 0;
        }
        function cN(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0;
            e = a + c >>> 0;
            return (H = b + d + (e >>> 0 < a >>> 0 | 0) >>> 0, e | 0) | 0;
        }
        function cO(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0;
            e = b - d >>> 0;
            e = b - d - (c >>> 0 > a >>> 0 | 0) >>> 0;
            return (H = e, a - c >>> 0 | 0) | 0;
        }
        function cP(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            if ((c | 0) < 32) {
                H = b << c | (a & (1 << c) - 1 << 32 - c) >>> 32 - c;
                return a << c;
            }
            H = a << c - 32;
            return 0;
        }
        function cQ(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            if ((c | 0) < 32) {
                H = b >>> c;
                return a >>> c | (b & (1 << c) - 1) << 32 - c;
            }
            H = 0;
            return b >>> c - 32 | 0;
        }
        function cR(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            if ((c | 0) < 32) {
                H = b >> c;
                return a >>> c | (b & (1 << c) - 1) << 32 - c;
            }
            H = (b | 0) < 0 ? -1 : 0;
            return b >> c - 32 | 0;
        }
        function cS(b) {
            b = b | 0;
            var c = 0;
            c = a[n + (b >>> 24) | 0] | 0;
            if ((c | 0) < 8) return c | 0;
            c = a[n + (b >> 16 & 255) | 0] | 0;
            if ((c | 0) < 8) return c + 8 | 0;
            c = a[n + (b >> 8 & 255) | 0] | 0;
            if ((c | 0) < 8) return c + 16 | 0;
            return (a[n + (b & 255) | 0] | 0) + 24 | 0;
        }
        function cT(b) {
            b = b | 0;
            var c = 0;
            c = a[m + (b & 255) | 0] | 0;
            if ((c | 0) < 8) return c | 0;
            c = a[m + (b >> 8 & 255) | 0] | 0;
            if ((c | 0) < 8) return c + 8 | 0;
            c = a[m + (b >> 16 & 255) | 0] | 0;
            if ((c | 0) < 8) return c + 16 | 0;
            return (a[m + (b >>> 24) | 0] | 0) + 24 | 0;
        }
        function cU(a, b) {
            a = a | 0;
            b = b | 0;
            var c = 0, d = 0, e = 0, f = 0;
            c = a & 65535;
            d = b & 65535;
            e = ad(d, c) | 0;
            f = a >>> 16;
            a = (e >>> 16) + (ad(d, f) | 0) | 0;
            d = b >>> 16;
            b = ad(d, c) | 0;
            return (H = (a >>> 16) + (ad(d, f) | 0) + (((a & 65535) + b | 0) >>> 16) | 0, a + b << 16 | e & 65535 | 0) | 0;
        }
        function cV(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0, f = 0, g = 0, h = 0, i = 0;
            e = b >> 31 | ((b | 0) < 0 ? -1 : 0) << 1;
            f = ((b | 0) < 0 ? -1 : 0) >> 31 | ((b | 0) < 0 ? -1 : 0) << 1;
            g = d >> 31 | ((d | 0) < 0 ? -1 : 0) << 1;
            h = ((d | 0) < 0 ? -1 : 0) >> 31 | ((d | 0) < 0 ? -1 : 0) << 1;
            i = cO(e ^ a, f ^ b, e, f) | 0;
            b = H;
            a = g ^ e;
            e = h ^ f;
            f = cO((c_(i, b, cO(g ^ c, h ^ d, g, h) | 0, H, 0) | 0) ^ a, H ^ e, a, e) | 0;
            return (H = H, f) | 0;
        }
        function cW(a, b, d, e) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            e = e | 0;
            var f = 0, g = 0, h = 0, j = 0, k = 0, l = 0, m = 0;
            f = i;
            i = i + 8 | 0;
            g = f | 0;
            h = b >> 31 | ((b | 0) < 0 ? -1 : 0) << 1;
            j = ((b | 0) < 0 ? -1 : 0) >> 31 | ((b | 0) < 0 ? -1 : 0) << 1;
            k = e >> 31 | ((e | 0) < 0 ? -1 : 0) << 1;
            l = ((e | 0) < 0 ? -1 : 0) >> 31 | ((e | 0) < 0 ? -1 : 0) << 1;
            m = cO(h ^ a, j ^ b, h, j) | 0;
            b = H;
            a = cO(k ^ d, l ^ e, k, l) | 0;
            c_(m, b, a, H, g) | 0;
            a = cO(c[g >> 2] ^ h, c[g + 4 >> 2] ^ j, h, j) | 0;
            j = H;
            i = f;
            return (H = j, a) | 0;
        }
        function cX(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0, f = 0;
            e = a;
            a = c;
            c = cU(e, a) | 0;
            f = H;
            return (H = (ad(b, a) | 0) + (ad(d, e) | 0) + f | f & 0, c | 0 | 0) | 0;
        }
        function cY(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            var e = 0;
            e = c_(a, b, c, d, 0) | 0;
            return (H = H, e) | 0;
        }
        function cZ(a, b, d, e) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            e = e | 0;
            var f = 0, g = 0;
            f = i;
            i = i + 8 | 0;
            g = f | 0;
            c_(a, b, d, e, g) | 0;
            i = f;
            return (H = c[g + 4 >> 2] | 0, c[g >> 2] | 0) | 0;
        }
        function c_(a, b, d, e, f) {
            a = a | 0;
            b = b | 0;
            d = d | 0;
            e = e | 0;
            f = f | 0;
            var g = 0, h = 0, i = 0, j = 0, k = 0, l = 0, m = 0, n = 0, o = 0, p = 0, q = 0, r = 0, s = 0, t = 0, u = 0, v = 0, w = 0, x = 0, y = 0, z = 0, A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, I = 0, J = 0, K = 0, L = 0, M = 0;
            g = a;
            h = b;
            i = h;
            j = d;
            k = e;
            l = k;
            if ((i | 0) == 0) {
                m = (f | 0) != 0;
                if ((l | 0) == 0) {
                    if (m) {
                        c[f >> 2] = (g >>> 0) % (j >>> 0);
                        c[f + 4 >> 2] = 0;
                    }
                    n = 0;
                    o = (g >>> 0) / (j >>> 0) >>> 0;
                    return (H = n, o) | 0;
                } else {
                    if (!m) {
                        n = 0;
                        o = 0;
                        return (H = n, o) | 0;
                    }
                    c[f >> 2] = a | 0;
                    c[f + 4 >> 2] = b & 0;
                    n = 0;
                    o = 0;
                    return (H = n, o) | 0;
                }
            }
            m = (l | 0) == 0;
            do {
                if ((j | 0) == 0) {
                    if (m) {
                        if ((f | 0) != 0) {
                            c[f >> 2] = (i >>> 0) % (j >>> 0);
                            c[f + 4 >> 2] = 0;
                        }
                        n = 0;
                        o = (i >>> 0) / (j >>> 0) >>> 0;
                        return (H = n, o) | 0;
                    }
                    if ((g | 0) == 0) {
                        if ((f | 0) != 0) {
                            c[f >> 2] = 0;
                            c[f + 4 >> 2] = (i >>> 0) % (l >>> 0);
                        }
                        n = 0;
                        o = (i >>> 0) / (l >>> 0) >>> 0;
                        return (H = n, o) | 0;
                    }
                    p = l - 1 | 0;
                    if ((p & l | 0) == 0) {
                        if ((f | 0) != 0) {
                            c[f >> 2] = a | 0;
                            c[f + 4 >> 2] = p & i | b & 0;
                        }
                        n = 0;
                        o = i >>> ((cT(l | 0) | 0) >>> 0);
                        return (H = n, o) | 0;
                    }
                    p = (cS(l | 0) | 0) - (cS(i | 0) | 0) | 0;
                    if (p >>> 0 <= 30) {
                        q = p + 1 | 0;
                        r = 31 - p | 0;
                        s = q;
                        t = i << r | g >>> (q >>> 0);
                        u = i >>> (q >>> 0);
                        v = 0;
                        w = g << r;
                        break;
                    }
                    if ((f | 0) == 0) {
                        n = 0;
                        o = 0;
                        return (H = n, o) | 0;
                    }
                    c[f >> 2] = a | 0;
                    c[f + 4 >> 2] = h | b & 0;
                    n = 0;
                    o = 0;
                    return (H = n, o) | 0;
                } else {
                    if (!m) {
                        r = (cS(l | 0) | 0) - (cS(i | 0) | 0) | 0;
                        if (r >>> 0 <= 31) {
                            q = r + 1 | 0;
                            p = 31 - r | 0;
                            x = r - 31 >> 31;
                            s = q;
                            t = g >>> (q >>> 0) & x | i << p;
                            u = i >>> (q >>> 0) & x;
                            v = 0;
                            w = g << p;
                            break;
                        }
                        if ((f | 0) == 0) {
                            n = 0;
                            o = 0;
                            return (H = n, o) | 0;
                        }
                        c[f >> 2] = a | 0;
                        c[f + 4 >> 2] = h | b & 0;
                        n = 0;
                        o = 0;
                        return (H = n, o) | 0;
                    }
                    p = j - 1 | 0;
                    if ((p & j | 0) != 0) {
                        x = (cS(j | 0) | 0) + 33 - (cS(i | 0) | 0) | 0;
                        q = 64 - x | 0;
                        r = 32 - x | 0;
                        y = r >> 31;
                        z = x - 32 | 0;
                        A = z >> 31;
                        s = x;
                        t = r - 1 >> 31 & i >>> (z >>> 0) | (i << r | g >>> (x >>> 0)) & A;
                        u = A & i >>> (x >>> 0);
                        v = g << q & y;
                        w = (i << q | g >>> (z >>> 0)) & y | g << r & x - 33 >> 31;
                        break;
                    }
                    if ((f | 0) != 0) {
                        c[f >> 2] = p & g;
                        c[f + 4 >> 2] = 0;
                    }
                    if ((j | 0) == 1) {
                        n = h | b & 0;
                        o = a | 0 | 0;
                        return (H = n, o) | 0;
                    } else {
                        p = cT(j | 0) | 0;
                        n = i >>> (p >>> 0) | 0;
                        o = i << 32 - p | g >>> (p >>> 0) | 0;
                        return (H = n, o) | 0;
                    }
                }
            } while (0);
            if ((s | 0) == 0) {
                B = w;
                C = v;
                D = u;
                E = t;
                F = 0;
                G = 0;
            } else {
                g = d | 0 | 0;
                d = k | e & 0;
                e = cN(g, d, -1, -1) | 0;
                k = H;
                i = w;
                w = v;
                v = u;
                u = t;
                t = s;
                s = 0;
                while (1) {
                    I = w >>> 31 | i << 1;
                    J = s | w << 1;
                    j = u << 1 | i >>> 31 | 0;
                    a = u >>> 31 | v << 1 | 0;
                    cO(e, k, j, a) | 0;
                    b = H;
                    h = b >> 31 | ((b | 0) < 0 ? -1 : 0) << 1;
                    K = h & 1;
                    L = cO(j, a, h & g, (((b | 0) < 0 ? -1 : 0) >> 31 | ((b | 0) < 0 ? -1 : 0) << 1) & d) | 0;
                    M = H;
                    b = t - 1 | 0;
                    if ((b | 0) == 0) {
                        break;
                    } else {
                        i = I;
                        w = J;
                        v = M;
                        u = L;
                        t = b;
                        s = K;
                    }
                }
                B = I;
                C = J;
                D = M;
                E = L;
                F = 0;
                G = K;
            }
            K = C;
            C = 0;
            if ((f | 0) != 0) {
                c[f >> 2] = E;
                c[f + 4 >> 2] = D;
            }
            n = (K | 0) >>> 31 | (B | C) << 1 | (C << 1 | K >>> 31) & 0 | F;
            o = (K << 1 | 0 >>> 31) & -2 | G;
            return (H = n, o) | 0;
        }
        function c$(a, b) {
            a = a | 0;
            b = b | 0;
            a1[a & 15](b | 0);
        }
        function c0(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            a2[a & 15](b | 0, c | 0);
        }
        function c1(a, b) {
            a = a | 0;
            b = b | 0;
            return a3[a & 7](b | 0) | 0;
        }
        function c2(a, b, c, d) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            d = d | 0;
            a4[a & 15](b | 0, c | 0, d | 0);
        }
        function c3(a) {
            a = a | 0;
            a5[a & 1]();
        }
        function c4(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            return a6[a & 1](b | 0, c | 0) | 0;
        }
        function c5(a) {
            a = a | 0;
            ae(0);
        }
        function c6(a, b) {
            a = a | 0;
            b = b | 0;
            ae(1);
        }
        function c7(a) {
            a = a | 0;
            ae(2);
            return 0;
        }
        function c8(a, b, c) {
            a = a | 0;
            b = b | 0;
            c = c | 0;
            ae(3);
        }
        function c9() {
            ae(4);
        }
        function da(a, b) {
            a = a | 0;
            b = b | 0;
            ae(5);
            return 0;
        }
        var a1 = [ c5, c5, ch, c5, cn, c5, cc, c5, cg, c5, cm, c5, c5, c5, c5, c5 ];
        var a2 = [ c6, c6, cw, c6, cy, c6, cx, c6, cz, c6, c6, c6, c6, c6, c6, c6 ];
        var a3 = [ c7, c7, cd, c7, ce, c7, c7, c7 ];
        var a4 = [ c8, c8, cJ, c8, cI, c8, cG, c8, cH, c8, c8, c8, c8, c8, c8, c8 ];
        var a5 = [ c9, c9 ];
        var a6 = [ da, da ];
        return {
            _crypto_scrypt: bu,
            _strlen: cM,
            _free: bM,
            _realloc: bO,
            _memset: cL,
            _malloc: bL,
            _memcpy: cK,
            _calloc: bN,
            runPostSets: bn,
            stackAlloc: a7,
            stackSave: a8,
            stackRestore: a9,
            setThrew: ba,
            setTempRet0: bd,
            setTempRet1: be,
            setTempRet2: bf,
            setTempRet3: bg,
            setTempRet4: bh,
            setTempRet5: bi,
            setTempRet6: bj,
            setTempRet7: bk,
            setTempRet8: bl,
            setTempRet9: bm,
            dynCall_vi: c$,
            dynCall_vii: c0,
            dynCall_ii: c1,
            dynCall_viii: c2,
            dynCall_v: c3,
            dynCall_iii: c4
        };
    }({
        Math: Math,
        Int8Array: Int8Array,
        Int16Array: Int16Array,
        Int32Array: Int32Array,
        Uint8Array: Uint8Array,
        Uint16Array: Uint16Array,
        Uint32Array: Uint32Array,
        Float32Array: Float32Array,
        Float64Array: Float64Array
    }, {
        abort: wa,
        assert: w,
        asmPrintInt: function(a, b) {
            s.print("int " + a + "," + b);
        },
        asmPrintFloat: function(a, b) {
            s.print("float " + a + "," + b);
        },
        min: Xc,
        invoke_vi: function(a, b) {
            try {
                s.dynCall_vi(a, b);
            } catch (c) {
                "number" !== typeof c && "longjmp" !== c && g(c), V.setThrew(1, 0);
            }
        },
        invoke_vii: function(a, b, c) {
            try {
                s.dynCall_vii(a, b, c);
            } catch (d) {
                "number" !== typeof d && "longjmp" !== d && g(d), V.setThrew(1, 0);
            }
        },
        invoke_ii: function(a, b) {
            try {
                return s.dynCall_ii(a, b);
            } catch (c) {
                "number" !== typeof c && "longjmp" !== c && g(c), V.setThrew(1, 0);
            }
        },
        invoke_viii: function(a, b, c, d) {
            try {
                s.dynCall_viii(a, b, c, d);
            } catch (e) {
                "number" !== typeof e && "longjmp" !== e && g(e), V.setThrew(1, 0);
            }
        },
        invoke_v: function(a) {
            try {
                s.dynCall_v(a);
            } catch (b) {
                "number" !== typeof b && "longjmp" !== b && g(b), V.setThrew(1, 0);
            }
        },
        invoke_iii: function(a, b, c) {
            try {
                return s.dynCall_iii(a, b, c);
            } catch (d) {
                "number" !== typeof d && "longjmp" !== d && g(d), V.setThrew(1, 0);
            }
        },
        _strncmp: function(a, b, c) {
            for (var d = 0; d < c; ) {
                var e = G[a + d | 0], f = G[b + d | 0];
                if (e == f && 0 == e) {
                    break;
                }
                if (0 == e) {
                    return -1;
                }
                if (0 == f) {
                    return 1;
                }
                if (e == f) {
                    d++;
                } else {
                    return e > f ? 1 : -1;
                }
            }
            return 0;
        },
        _llvm_va_end: aa(),
        _sysconf: function(a) {
            switch (a) {
              case 8:
                return 4096;

              case 54:
                ;

              case 56:
                ;

              case 21:
                ;

              case 61:
                ;

              case 63:
                ;

              case 22:
                ;

              case 67:
                ;

              case 23:
                ;

              case 24:
                ;

              case 25:
                ;

              case 26:
                ;

              case 27:
                ;

              case 69:
                ;

              case 28:
                ;

              case 101:
                ;

              case 70:
                ;

              case 71:
                ;

              case 29:
                ;

              case 30:
                ;

              case 199:
                ;

              case 75:
                ;

              case 76:
                ;

              case 32:
                ;

              case 43:
                ;

              case 44:
                ;

              case 80:
                ;

              case 46:
                ;

              case 47:
                ;

              case 45:
                ;

              case 48:
                ;

              case 49:
                ;

              case 42:
                ;

              case 82:
                ;

              case 33:
                ;

              case 7:
                ;

              case 108:
                ;

              case 109:
                ;

              case 107:
                ;

              case 112:
                ;

              case 119:
                ;

              case 121:
                return 200809;

              case 13:
                ;

              case 104:
                ;

              case 94:
                ;

              case 95:
                ;

              case 34:
                ;

              case 35:
                ;

              case 77:
                ;

              case 81:
                ;

              case 83:
                ;

              case 84:
                ;

              case 85:
                ;

              case 86:
                ;

              case 87:
                ;

              case 88:
                ;

              case 89:
                ;

              case 90:
                ;

              case 91:
                ;

              case 94:
                ;

              case 95:
                ;

              case 110:
                ;

              case 111:
                ;

              case 113:
                ;

              case 114:
                ;

              case 115:
                ;

              case 116:
                ;

              case 117:
                ;

              case 118:
                ;

              case 120:
                ;

              case 40:
                ;

              case 16:
                ;

              case 79:
                ;

              case 19:
                return -1;

              case 92:
                ;

              case 93:
                ;

              case 5:
                ;

              case 72:
                ;

              case 6:
                ;

              case 74:
                ;

              case 92:
                ;

              case 93:
                ;

              case 96:
                ;

              case 97:
                ;

              case 98:
                ;

              case 99:
                ;

              case 102:
                ;

              case 103:
                ;

              case 105:
                return 1;

              case 38:
                ;

              case 66:
                ;

              case 50:
                ;

              case 51:
                ;

              case 4:
                return 1024;

              case 15:
                ;

              case 64:
                ;

              case 41:
                return 32;

              case 55:
                ;

              case 37:
                ;

              case 17:
                return 2147483647;

              case 18:
                ;

              case 1:
                return 47839;

              case 59:
                ;

              case 57:
                return 99;

              case 68:
                ;

              case 58:
                return 2048;

              case 0:
                return 2097152;

              case 3:
                return 65536;

              case 14:
                return 32768;

              case 73:
                return 32767;

              case 39:
                return 16384;

              case 60:
                return 1e3;

              case 106:
                return 700;

              case 52:
                return 256;

              case 62:
                return 255;

              case 2:
                return 100;

              case 65:
                return 64;

              case 36:
                return 20;

              case 100:
                return 16;

              case 20:
                return 6;

              case 53:
                return 4;

              case 10:
                return 1;
            }
            M(N.A);
            return -1;
        },
        ___cxa_throw: rc,
        _strerror: zc,
        _abort: function() {
            s.abort();
        },
        _fprintf: mc,
        _llvm_eh_exception: U,
        ___cxa_free_exception: sc,
        _fflush: aa(),
        ___buildEnvironment: wc,
        __reallyNegative: jc,
        _strchr: function(a, b) {
            a--;
            do {
                a++;
                var c = A[a];
                if (c == b) {
                    return a;
                }
            } while (c);
            return 0;
        },
        _fputc: Bc,
        ___setErrNo: M,
        _fwrite: hc,
        _send: fc,
        _write: gc,
        _exit: function(a) {
            Ac(a);
        },
        ___cxa_find_matching_catch: function(a, b) {
            -1 == a && (a = B[U.m >> 2]);
            -1 == b && (b = B[U.m + 4 >> 2]);
            var c = Array.prototype.slice.call(arguments, 2);
            0 != b && !pc(b) && 0 == B[B[b >> 2] - 8 >> 2] && (a = B[a >> 2]);
            for (var d = 0; d < c.length; d++) {
                if (qc(c[d], b, a)) {
                    return (V.setTempRet0(c[d]), a) | 0;
                }
            }
            return (V.setTempRet0(b), a) | 0;
        },
        ___cxa_allocate_exception: function(a) {
            return Oa(a);
        },
        _isspace: function(a) {
            return 32 == a || 9 <= a && 13 >= a;
        },
        __formatString: kc,
        ___resumeException: function(a) {
            0 == B[U.m >> 2] && (B[U.m >> 2] = a);
            g(a + " - Exception catching is disabled, this exception cannot be caught. Compile with -s DISABLE_EXCEPTION_CATCHING=0 or DISABLE_EXCEPTION_CATCHING=2 to catch.");
        },
        _llvm_uadd_with_overflow_i32: function(a, b) {
            a >>>= 0;
            b >>>= 0;
            return (V.setTempRet0(4294967295 < a + b), a + b >>> 0) | 0;
        },
        ___cxa_does_inherit: qc,
        _getenv: xc,
        _vfprintf: function(a, b, c) {
            return mc(a, b, B[c >> 2]);
        },
        ___cxa_begin_catch: function(a) {
            oc.ta--;
            return a;
        },
        __ZSt18uncaught_exceptionv: oc,
        _pwrite: function(a, b, c, d) {
            a = R[a];
            if (!a) {
                return M(N.$), -1;
            }
            try {
                return Ib(a, A, b, c, d);
            } catch (e) {
                return Zb(e), -1;
            }
        },
        ___cxa_call_unexpected: function(a) {
            s.P("Unexpected exception thrown, this is not properly supported - aborting");
            za = l;
            g(a);
        },
        _sbrk: nc,
        _strerror_r: yc,
        ___errno_location: function() {
            return rb;
        },
        ___gxx_personality_v0: aa(),
        ___cxa_is_number_type: pc,
        _time: function(a) {
            var b = Math.floor(Date.now() / 1e3);
            a && (B[a >> 2] = b);
            return b;
        },
        __exit: Ac,
        ___cxa_end_catch: uc,
        STACKTOP: u,
        STACK_MAX: Ta,
        tempDoublePtr: qb,
        ABORT: za,
        cttz_i8: Wc,
        ctlz_i8: Vc,
        NaN: NaN,
        Infinity: Infinity,
        _stderr: nb,
        __ZTVN10__cxxabiv120__si_class_type_infoE: ob,
        __ZTVN10__cxxabiv117__class_type_infoE: pb,
        ___progname: k
    }, I);
    s._crypto_scrypt = V._crypto_scrypt;
    var ic = s._strlen = V._strlen, tc = s._free = V._free;
    s._realloc = V._realloc;
    var tb = s._memset = V._memset, Oa = s._malloc = V._malloc, sb = s._memcpy = V._memcpy;
    s._calloc = V._calloc;
    var mb = s.runPostSets = V.runPostSets;
    s.dynCall_vi = V.dynCall_vi;
    s.dynCall_vii = V.dynCall_vii;
    s.dynCall_ii = V.dynCall_ii;
    s.dynCall_viii = V.dynCall_viii;
    s.dynCall_v = V.dynCall_v;
    s.dynCall_iii = V.dynCall_iii;
    var qa = function(a) {
        return V.stackAlloc(a);
    }, ja = function() {
        return V.stackSave();
    }, ka = function(a) {
        V.stackRestore(a);
    }, lc;
    function X(a, b) {
        a != m && ("number" == typeof a ? this.p(a) : b == m && "string" != typeof a ? this.k(a, 256) : this.k(a, b));
    }
    function Yc() {
        return new X(m);
    }
    function Zc(a, b) {
        var c = $c[a.charCodeAt(b)];
        return c == m ? -1 : c;
    }
    function ad(a) {
        var b = Yc();
        b.D(a);
        return b;
    }
    function Y(a, b) {
        this.h = a | 0;
        this.j = b | 0;
    }
    Y.Ca = {};
    Y.D = function(a) {
        if (-128 <= a && 128 > a) {
            var b = Y.Ca[a];
            if (b) {
                return b;
            }
        }
        b = new Y(a | 0, 0 > a ? -1 : 0);
        -128 <= a && 128 > a && (Y.Ca[a] = b);
        return b;
    };
    Y.p = function(a) {
        return isNaN(a) || !isFinite(a) ? Y.ZERO : a <= -Y.Ea ? Y.MIN_VALUE : a + 1 >= Y.Ea ? Y.MAX_VALUE : 0 > a ? Y.p(-a).i() : new Y(a % Y.B | 0, a / Y.B | 0);
    };
    Y.v = function(a, b) {
        return new Y(a, b);
    };
    Y.k = function(a, b) {
        0 == a.length && g(Error("number format error: empty string"));
        var c = b || 10;
        (2 > c || 36 < c) && g(Error("radix out of range: " + c));
        if ("-" == a.charAt(0)) {
            return Y.k(a.substring(1), c).i();
        }
        0 <= a.indexOf("-") && g(Error('number format error: interior "-" character: ' + a));
        for (var d = Y.p(Math.pow(c, 8)), e = Y.ZERO, f = 0; f < a.length; f += 8) {
            var h = Math.min(8, a.length - f), i = parseInt(a.substring(f, f + h), c);
            8 > h ? (h = Y.p(Math.pow(c, h)), e = e.multiply(h).add(Y.p(i))) : (e = e.multiply(d), 
            e = e.add(Y.p(i)));
        }
        return e;
    };
    Y.ea = 65536;
    Y.Od = 16777216;
    Y.B = Y.ea * Y.ea;
    Y.Pd = Y.B / 2;
    Y.Qd = Y.B * Y.ea;
    Y.eb = Y.B * Y.B;
    Y.Ea = Y.eb / 2;
    Y.ZERO = Y.D(0);
    Y.ONE = Y.D(1);
    Y.Da = Y.D(-1);
    Y.MAX_VALUE = Y.v(-1, 2147483647);
    Y.MIN_VALUE = Y.v(0, -2147483648);
    Y.cb = Y.D(16777216);
    q = Y.prototype;
    q.Z = function() {
        return this.j * Y.B + this.ob();
    };
    q.toString = function(a) {
        a = a || 10;
        (2 > a || 36 < a) && g(Error("radix out of range: " + a));
        if (this.G()) {
            return "0";
        }
        if (this.n()) {
            if (this.o(Y.MIN_VALUE)) {
                var b = Y.p(a), c = this.F(b), b = c.multiply(b).R(this);
                return c.toString(a) + b.h.toString(a);
            }
            return "-" + this.i().toString(a);
        }
        for (var c = Y.p(Math.pow(a, 6)), b = this, d = ""; ;) {
            var e = b.F(c), f = b.R(e.multiply(c)).h.toString(a), b = e;
            if (b.G()) {
                return f + d;
            }
            for (;6 > f.length; ) {
                f = "0" + f;
            }
            d = "" + f + d;
        }
    };
    q.ob = function() {
        return 0 <= this.h ? this.h : Y.B + this.h;
    };
    q.G = function() {
        return 0 == this.j && 0 == this.h;
    };
    q.n = function() {
        return 0 > this.j;
    };
    q.Pa = function() {
        return 1 == (this.h & 1);
    };
    q.o = function(a) {
        return this.j == a.j && this.h == a.h;
    };
    q.Ra = function() {
        return 0 > this.ja(Y.cb);
    };
    q.qb = function(a) {
        return 0 < this.ja(a);
    };
    q.rb = function(a) {
        return 0 <= this.ja(a);
    };
    q.ja = function(a) {
        if (this.o(a)) {
            return 0;
        }
        var b = this.n(), c = a.n();
        return b && !c ? -1 : !b && c ? 1 : this.R(a).n() ? -1 : 1;
    };
    q.i = function() {
        return this.o(Y.MIN_VALUE) ? Y.MIN_VALUE : this.xb().add(Y.ONE);
    };
    q.add = function(a) {
        var b = this.j >>> 16, c = this.j & 65535, d = this.h >>> 16, e = a.j >>> 16, f = a.j & 65535, h = a.h >>> 16, i;
        i = 0 + ((this.h & 65535) + (a.h & 65535));
        a = 0 + (i >>> 16);
        a += d + h;
        d = 0 + (a >>> 16);
        d += c + f;
        c = 0 + (d >>> 16);
        c = c + (b + e) & 65535;
        return Y.v((a & 65535) << 16 | i & 65535, c << 16 | d & 65535);
    };
    q.R = function(a) {
        return this.add(a.i());
    };
    q.multiply = function(a) {
        if (this.G() || a.G()) {
            return Y.ZERO;
        }
        if (this.o(Y.MIN_VALUE)) {
            return a.Pa() ? Y.MIN_VALUE : Y.ZERO;
        }
        if (a.o(Y.MIN_VALUE)) {
            return this.Pa() ? Y.MIN_VALUE : Y.ZERO;
        }
        if (this.n()) {
            return a.n() ? this.i().multiply(a.i()) : this.i().multiply(a).i();
        }
        if (a.n()) {
            return this.multiply(a.i()).i();
        }
        if (this.Ra() && a.Ra()) {
            return Y.p(this.Z() * a.Z());
        }
        var b = this.j >>> 16, c = this.j & 65535, d = this.h >>> 16, e = this.h & 65535, f = a.j >>> 16, h = a.j & 65535, i = a.h >>> 16, a = a.h & 65535, j, n, y, v;
        v = 0 + e * a;
        y = 0 + (v >>> 16);
        y += d * a;
        n = 0 + (y >>> 16);
        y = (y & 65535) + e * i;
        n += y >>> 16;
        y &= 65535;
        n += c * a;
        j = 0 + (n >>> 16);
        n = (n & 65535) + d * i;
        j += n >>> 16;
        n &= 65535;
        n += e * h;
        j += n >>> 16;
        n &= 65535;
        j = j + (b * a + c * i + d * h + e * f) & 65535;
        return Y.v(y << 16 | v & 65535, j << 16 | n);
    };
    q.F = function(a) {
        a.G() && g(Error("division by zero"));
        if (this.G()) {
            return Y.ZERO;
        }
        if (this.o(Y.MIN_VALUE)) {
            if (a.o(Y.ONE) || a.o(Y.Da)) {
                return Y.MIN_VALUE;
            }
            if (a.o(Y.MIN_VALUE)) {
                return Y.ONE;
            }
            var b = this.Db().F(a).shiftLeft(1);
            if (b.o(Y.ZERO)) {
                return a.n() ? Y.ONE : Y.Da;
            }
            var c = this.R(a.multiply(b));
            return b.add(c.F(a));
        }
        if (a.o(Y.MIN_VALUE)) {
            return Y.ZERO;
        }
        if (this.n()) {
            return a.n() ? this.i().F(a.i()) : this.i().F(a).i();
        }
        if (a.n()) {
            return this.F(a.i()).i();
        }
        for (var d = Y.ZERO, c = this; c.rb(a); ) {
            for (var b = Math.max(1, Math.floor(c.Z() / a.Z())), e = Math.ceil(Math.log(b) / Math.LN2), e = 48 >= e ? 1 : Math.pow(2, e - 48), f = Y.p(b), h = f.multiply(a); h.n() || h.qb(c); ) {
                b -= e, f = Y.p(b), h = f.multiply(a);
            }
            f.G() && (f = Y.ONE);
            d = d.add(f);
            c = c.R(h);
        }
        return d;
    };
    q.xb = function() {
        return Y.v(~this.h, ~this.j);
    };
    q.shiftLeft = function(a) {
        a &= 63;
        if (0 == a) {
            return this;
        }
        var b = this.h;
        return 32 > a ? Y.v(b << a, this.j << a | b >>> 32 - a) : Y.v(0, b << a - 32);
    };
    q.Db = function() {
        var a;
        a = 1;
        if (0 == a) {
            return this;
        }
        var b = this.j;
        return 32 > a ? Y.v(this.h >>> a | b << 32 - a, b >> a) : Y.v(b >> a - 32, 0 <= b ? 0 : -1);
    };
    q = X.prototype;
    q.ga = function(a, b, c, d) {
        for (var e = 0, f = 0; 0 <= --d; ) {
            var h = a * this[e++] + b[c] + f, f = Math.floor(h / 67108864);
            b[c++] = h & 67108863;
        }
        return f;
    };
    q.f = 26;
    q.u = 67108863;
    q.K = 67108864;
    q.bb = Math.pow(2, 52);
    q.Aa = 26;
    q.Ba = 0;
    var $c = [], bd, Z;
    bd = 48;
    for (Z = 0; 9 >= Z; ++Z) {
        $c[bd++] = Z;
    }
    bd = 97;
    for (Z = 10; 36 > Z; ++Z) {
        $c[bd++] = Z;
    }
    bd = 65;
    for (Z = 10; 36 > Z; ++Z) {
        $c[bd++] = Z;
    }
    q = X.prototype;
    q.copyTo = function(a) {
        for (var b = this.b - 1; 0 <= b; --b) {
            a[b] = this[b];
        }
        a.b = this.b;
        a.c = this.c;
    };
    q.D = function(a) {
        this.b = 1;
        this.c = 0 > a ? -1 : 0;
        0 < a ? this[0] = a : -1 > a ? this[0] = a + DV : this.b = 0;
    };
    q.k = function(a, b) {
        var c;
        if (16 == b) {
            c = 4;
        } else {
            if (8 == b) {
                c = 3;
            } else {
                if (256 == b) {
                    c = 8;
                } else {
                    if (2 == b) {
                        c = 1;
                    } else {
                        if (32 == b) {
                            c = 5;
                        } else {
                            if (4 == b) {
                                c = 2;
                            } else {
                                this.nb(a, b);
                                return;
                            }
                        }
                    }
                }
            }
        }
        this.c = this.b = 0;
        for (var d = a.length, e = p, f = 0; 0 <= --d; ) {
            var h = 8 == c ? a[d] & 255 : Zc(a, d);
            0 > h ? "-" == a.charAt(d) && (e = l) : (e = p, 0 == f ? this[this.b++] = h : f + c > this.f ? (this[this.b - 1] |= (h & (1 << this.f - f) - 1) << f, 
            this[this.b++] = h >> this.f - f) : this[this.b - 1] |= h << f, f += c, f >= this.f && (f -= this.f));
        }
        8 == c && 0 != (a[0] & 128) && (this.c = -1, 0 < f && (this[this.b - 1] |= (1 << this.f - f) - 1 << f));
        this.C();
        e && X.ZERO.t(this, this);
    };
    q.C = function() {
        for (var a = this.c & this.u; 0 < this.b && this[this.b - 1] == a; ) {
            --this.b;
        }
    };
    q.la = function(a, b) {
        var c;
        for (c = this.b - 1; 0 <= c; --c) {
            b[c + a] = this[c];
        }
        for (c = a - 1; 0 <= c; --c) {
            b[c] = 0;
        }
        b.b = this.b + a;
        b.c = this.c;
    };
    q.jb = function(a, b) {
        for (var c = a; c < this.b; ++c) {
            b[c - a] = this[c];
        }
        b.b = Math.max(this.b - a, 0);
        b.c = this.c;
    };
    q.Qa = function(a, b) {
        var c = a % this.f, d = this.f - c, e = (1 << d) - 1, f = Math.floor(a / this.f), h = this.c << c & this.u, i;
        for (i = this.b - 1; 0 <= i; --i) {
            b[i + f + 1] = this[i] >> d | h, h = (this[i] & e) << c;
        }
        for (i = f - 1; 0 <= i; --i) {
            b[i] = 0;
        }
        b[f] = h;
        b.b = this.b + f + 1;
        b.c = this.c;
        b.C();
    };
    q.zb = function(a, b) {
        b.c = this.c;
        var c = Math.floor(a / this.f);
        if (c >= this.b) {
            b.b = 0;
        } else {
            var d = a % this.f, e = this.f - d, f = (1 << d) - 1;
            b[0] = this[c] >> d;
            for (var h = c + 1; h < this.b; ++h) {
                b[h - c - 1] |= (this[h] & f) << e, b[h - c] = this[h] >> d;
            }
            0 < d && (b[this.b - c - 1] |= (this.c & f) << e);
            b.b = this.b - c;
            b.C();
        }
    };
    q.t = function(a, b) {
        for (var c = 0, d = 0, e = Math.min(a.b, this.b); c < e; ) {
            d += this[c] - a[c], b[c++] = d & this.u, d >>= this.f;
        }
        if (a.b < this.b) {
            for (d -= a.c; c < this.b; ) {
                d += this[c], b[c++] = d & this.u, d >>= this.f;
            }
            d += this.c;
        } else {
            for (d += this.c; c < a.b; ) {
                d -= a[c], b[c++] = d & this.u, d >>= this.f;
            }
            d -= a.c;
        }
        b.c = 0 > d ? -1 : 0;
        -1 > d ? b[c++] = this.K + d : 0 < d && (b[c++] = d);
        b.b = c;
        b.C();
    };
    q.vb = function(a) {
        var b = $.Xa, c = this.abs(), d = b.abs(), e = c.b;
        for (a.b = e + d.b; 0 <= --e; ) {
            a[e] = 0;
        }
        for (e = 0; e < d.b; ++e) {
            a[e + c.b] = c.ga(d[e], a, e, c.b);
        }
        a.c = 0;
        a.C();
        this.c != b.c && X.ZERO.t(a, a);
    };
    q.Ja = function(a, b, c) {
        var d = a.abs();
        if (!(0 >= d.b)) {
            var e = this.abs();
            if (e.b < d.b) {
                b != m && b.D(0), c != m && this.copyTo(c);
            } else {
                c == m && (c = Yc());
                var f = Yc(), h = this.c, a = a.c, i = d[d.b - 1], j = 1, n;
                if (0 != (n = i >>> 16)) {
                    i = n, j += 16;
                }
                if (0 != (n = i >> 8)) {
                    i = n, j += 8;
                }
                if (0 != (n = i >> 4)) {
                    i = n, j += 4;
                }
                if (0 != (n = i >> 2)) {
                    i = n, j += 2;
                }
                0 != i >> 1 && (j += 1);
                i = this.f - j;
                0 < i ? (d.Qa(i, f), e.Qa(i, c)) : (d.copyTo(f), e.copyTo(c));
                d = f.b;
                e = f[d - 1];
                if (0 != e) {
                    n = e * (1 << this.Aa) + (1 < d ? f[d - 2] >> this.Ba : 0);
                    j = this.bb / n;
                    n = (1 << this.Aa) / n;
                    var y = 1 << this.Ba, v = c.b, C = v - d, D = b == m ? Yc() : b;
                    f.la(C, D);
                    0 <= c.U(D) && (c[c.b++] = 1, c.t(D, c));
                    X.ONE.la(d, D);
                    for (D.t(f, f); f.b < d; ) {
                        f[f.b++] = 0;
                    }
                    for (;0 <= --C; ) {
                        var K = c[--v] == e ? this.u : Math.floor(c[v] * j + (c[v - 1] + y) * n);
                        if ((c[v] += f.ga(K, c, C, d)) < K) {
                            f.la(C, D);
                            for (c.t(D, c); c[v] < --K; ) {
                                c.t(D, c);
                            }
                        }
                    }
                    b != m && (c.jb(d, b), h != a && X.ZERO.t(b, b));
                    c.b = d;
                    c.C();
                    0 < i && c.zb(i, c);
                    0 > h && X.ZERO.t(c, c);
                }
            }
        }
    };
    q.toString = function(a) {
        if (0 > this.c) {
            return "-" + this.i().toString(a);
        }
        if (16 == a) {
            a = 4;
        } else {
            if (8 == a) {
                a = 3;
            } else {
                if (2 == a) {
                    a = 1;
                } else {
                    if (32 == a) {
                        a = 5;
                    } else {
                        if (4 == a) {
                            a = 2;
                        } else {
                            return this.Fb(a);
                        }
                    }
                }
            }
        }
        var b = (1 << a) - 1, c, d = p, e = "", f = this.b, h = this.f - f * this.f % a;
        if (0 < f--) {
            if (h < this.f && 0 < (c = this[f] >> h)) {
                d = l, e = "0123456789abcdefghijklmnopqrstuvwxyz".charAt(c);
            }
            for (;0 <= f; ) {
                h < a ? (c = (this[f] & (1 << h) - 1) << a - h, c |= this[--f] >> (h += this.f - a)) : (c = this[f] >> (h -= a) & b, 
                0 >= h && (h += this.f, --f)), 0 < c && (d = l), d && (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(c));
            }
        }
        return d ? e : "0";
    };
    q.i = function() {
        var a = Yc();
        X.ZERO.t(this, a);
        return a;
    };
    q.abs = function() {
        return 0 > this.c ? this.i() : this;
    };
    q.U = function(a) {
        var b = this.c - a.c;
        if (0 != b) {
            return b;
        }
        var c = this.b, b = c - a.b;
        if (0 != b) {
            return 0 > this.c ? -b : b;
        }
        for (;0 <= --c; ) {
            if (0 != (b = this[c] - a[c])) {
                return b;
            }
        }
        return 0;
    };
    X.ZERO = ad(0);
    X.ONE = ad(1);
    q = X.prototype;
    q.nb = function(a, b) {
        this.D(0);
        b == m && (b = 10);
        for (var c = this.S(b), d = Math.pow(b, c), e = p, f = 0, h = 0, i = 0; i < a.length; ++i) {
            var j = Zc(a, i);
            0 > j ? "-" == a.charAt(i) && 0 == this.ra() && (e = l) : (h = b * h + j, ++f >= c && (this.Ia(d), 
            this.Ha(h), h = f = 0));
        }
        0 < f && (this.Ia(Math.pow(b, f)), this.Ha(h));
        e && X.ZERO.t(this, this);
    };
    q.S = function(a) {
        return Math.floor(Math.LN2 * this.f / Math.log(a));
    };
    q.ra = function() {
        return 0 > this.c ? -1 : 0 >= this.b || 1 == this.b && 0 >= this[0] ? 0 : 1;
    };
    q.Ia = function(a) {
        this[this.b] = this.ga(a - 1, this, 0, this.b);
        ++this.b;
        this.C();
    };
    q.Ha = function(a) {
        var b = 0;
        if (0 != a) {
            for (;this.b <= b; ) {
                this[this.b++] = 0;
            }
            for (this[b] += a; this[b] >= this.K; ) {
                this[b] -= this.K, ++b >= this.b && (this[this.b++] = 0), ++this[b];
            }
        }
    };
    q.Fb = function(a) {
        a == m && (a = 10);
        if (0 == this.ra() || 2 > a || 36 < a) {
            return "0";
        }
        var b = this.S(a), b = Math.pow(a, b), c = ad(b), d = Yc(), e = Yc(), f = "";
        for (this.Ja(c, d, e); 0 < d.ra(); ) {
            f = (b + e.Oa()).toString(a).substr(1) + f, d.Ja(c, d, e);
        }
        return e.Oa().toString(a) + f;
    };
    q.Oa = function() {
        if (0 > this.c) {
            if (1 == this.b) {
                return this[0] - this.K;
            }
            if (0 == this.b) {
                return -1;
            }
        } else {
            if (1 == this.b) {
                return this[0];
            }
            if (0 == this.b) {
                return 0;
            }
        }
        return (this[1] & (1 << 32 - this.f) - 1) << this.f | this[0];
    };
    q.fa = function(a, b) {
        for (var c = 0, d = 0, e = Math.min(a.b, this.b); c < e; ) {
            d += this[c] + a[c], b[c++] = d & this.u, d >>= this.f;
        }
        if (a.b < this.b) {
            for (d += a.c; c < this.b; ) {
                d += this[c], b[c++] = d & this.u, d >>= this.f;
            }
            d += this.c;
        } else {
            for (d += this.c; c < a.b; ) {
                d += a[c], b[c++] = d & this.u, d >>= this.f;
            }
            d += a.c;
        }
        b.c = 0 > d ? -1 : 0;
        0 < d ? b[c++] = d : -1 > d && (b[c++] = this.K + d);
        b.b = c;
        b.C();
    };
    var $ = {
        abs: function(a, b) {
            var c = new Y(a, b), c = c.n() ? c.i() : c;
            B[qb >> 2] = c.h;
            B[qb + 4 >> 2] = c.j;
        },
        Ka: function() {
            $.kb || ($.kb = l, $.Xa = new X(), $.Xa.k("4294967296", 10), $.sa = new X(), $.sa.k("18446744073709551616", 10), 
            $.xe = new X(), $.ye = new X());
        },
        me: function(a, b) {
            var c = new X();
            c.k(b.toString(), 10);
            var d = new X();
            c.vb(d);
            c = new X();
            c.k(a.toString(), 10);
            var e = new X();
            c.fa(d, e);
            return e;
        },
        stringify: function(a, b, c) {
            a = new Y(a, b).toString();
            c && "-" == a[0] && ($.Ka(), c = new X(), c.k(a, 10), a = new X(), $.sa.fa(c, a), 
            a = a.toString(10));
            return a;
        },
        k: function(a, b, c, d, e) {
            $.Ka();
            var f = new X();
            f.k(a, b);
            a = new X();
            a.k(c, 10);
            c = new X();
            c.k(d, 10);
            e && 0 > f.U(X.ZERO) && (d = new X(), f.fa($.sa, d), f = d);
            d = p;
            0 > f.U(a) ? (f = a, d = l) : 0 < f.U(c) && (f = c, d = l);
            f = Y.k(f.toString());
            B[qb >> 2] = f.h;
            B[qb + 4 >> 2] = f.j;
            d && g("range error");
        }
    };
    lc = $;
    var cd, dd;
    s.callMain = s.$d = function(a) {
        function b() {
            for (var a = 0; 3 > a; a++) {
                d.push(0);
            }
        }
        w(0 == L, "cannot call main when async dependencies remain! (listen on __ATMAIN__)");
        w(0 == Wa.length, "cannot call main when preRun functions remain to be called");
        a = a || [];
        ab || (ab = l, Va(Xa));
        var c = a.length + 1, d = [ F(J("/bin/this.program"), "i8", Ka) ];
        b();
        for (var e = 0; e < c - 1; e += 1) {
            d.push(F(J(a[e]), "i8", Ka)), b();
        }
        d.push(0);
        d = F(d, "i32", Ka);
        cd = u;
        dd = l;
        var f;
        try {
            f = s._main(c, d, 0);
        } catch (h) {
            if (h && "object" == typeof h && "ExitStatus" == h.type) {
                return s.print("Exit Status: " + h.value), h.value;
            }
            "SimulateInfiniteLoop" == h ? s.noExitRuntime = l : g(h);
        } finally {
            dd = p;
        }
        s.noExitRuntime || ed(f);
    };
    function lb(a) {
        function b() {
            ab || (ab = l, Va(Xa));
            Va(Ya);
            gb = l;
            s._main && kb && s.callMain(a);
            if (s.postRun) {
                for ("function" == typeof s.postRun && (s.postRun = [ s.postRun ]); s.postRun.length; ) {
                    cb(s.postRun.shift());
                }
            }
            Va($a);
        }
        a = a || s.arguments;
        if (0 < L) {
            s.P("run() called, but dependencies remain, so not running");
        } else {
            if (s.preRun) {
                for ("function" == typeof s.preRun && (s.preRun = [ s.preRun ]); s.preRun.length; ) {
                    bb(s.preRun.shift());
                }
            }
            Va(Wa);
            0 < L || (s.setStatus ? (s.setStatus("Running..."), setTimeout(function() {
                setTimeout(function() {
                    s.setStatus("");
                }, 1);
                za || b();
            }, 1)) : b());
        }
    }
    s.run = s.we = lb;
    function ed(a) {
        za = l;
        u = cd;
        Va(Za);
        dd && g({
            type: "ExitStatus",
            value: a
        });
    }
    s.exit = s.de = ed;
    function wa(a) {
        a && s.print(a);
        za = l;
        g("abort() at " + Error().stack);
    }
    s.abort = s.abort = wa;
    if (s.preInit) {
        for ("function" == typeof s.preInit && (s.preInit = [ s.preInit ]); 0 < s.preInit.length; ) {
            s.preInit.pop()();
        }
    }
    var kb = l;
    s.noInitialRun && (kb = p);
    lb();
    var scrypt = function() {
        var exports = {};
        function encode_utf8(s) {
            return encode_latin1(unescape(encodeURIComponent(s)));
        }
        function encode_latin1(s) {
            var result = new Uint8Array(s.length);
            for (var i = 0; i < s.length; i++) {
                var c = s.charCodeAt(i);
                if ((c & 255) !== c) throw {
                    message: "Cannot encode string in Latin1",
                    str: s
                };
                result[i] = c & 255;
            }
            return result;
        }
        function decode_utf8(bs) {
            return decodeURIComponent(escape(decode_latin1(bs)));
        }
        function decode_latin1(bs) {
            var encoded = [];
            for (var i = 0; i < bs.length; i++) {
                encoded.push(String.fromCharCode(bs[i]));
            }
            return encoded.join("");
        }
        function to_hex(bs) {
            var encoded = [];
            for (var i = 0; i < bs.length; i++) {
                encoded.push("0123456789abcdef"[bs[i] >> 4 & 15]);
                encoded.push("0123456789abcdef"[bs[i] & 15]);
            }
            return encoded.join("");
        }
        function injectBytes(bs, leftPadding) {
            var p = leftPadding || 0;
            var address = scrypt_raw._malloc(bs.length + p);
            scrypt_raw.HEAPU8.set(bs, address + p);
            for (var i = address; i < address + p; i++) {
                scrypt_raw.HEAPU8[i] = 0;
            }
            return address;
        }
        function check_injectBytes(function_name, what, thing, expected_length, leftPadding) {
            check_length(function_name, what, thing, expected_length);
            return injectBytes(thing, leftPadding);
        }
        function extractBytes(address, length) {
            var result = new Uint8Array(length);
            result.set(scrypt_raw.HEAPU8.subarray(address, address + length));
            return result;
        }
        function check(function_name, result) {
            if (result !== 0) {
                throw {
                    message: "scrypt_raw." + function_name + " signalled an error"
                };
            }
        }
        function check_length(function_name, what, thing, expected_length) {
            if (thing.length !== expected_length) {
                throw {
                    message: "scrypt." + function_name + " expected " + expected_length + "-byte " + what + " but got length " + thing.length
                };
            }
        }
        function Target(length) {
            this.length = length;
            this.address = scrypt_raw._malloc(length);
        }
        Target.prototype.extractBytes = function(offset) {
            var result = extractBytes(this.address + (offset || 0), this.length - (offset || 0));
            scrypt_raw._free(this.address);
            this.address = null;
            return result;
        };
        function free_all(addresses) {
            for (var i = 0; i < addresses.length; i++) {
                scrypt_raw._free(addresses[i]);
            }
        }
        function crypto_scrypt(passwd, salt, n, r, p, buflen) {
            var buf = new Target(buflen);
            var pa = injectBytes(passwd);
            var sa = injectBytes(salt);
            check("_crypto_scrypt", scrypt_raw._crypto_scrypt(pa, passwd.length, sa, salt.length, n, 0, r, p, buf.address, buf.length));
            free_all([ pa, sa ]);
            return buf.extractBytes();
        }
        exports.encode_utf8 = encode_utf8;
        exports.encode_latin1 = encode_latin1;
        exports.decode_utf8 = decode_utf8;
        exports.decode_latin1 = decode_latin1;
        exports.to_hex = to_hex;
        exports.crypto_scrypt = crypto_scrypt;
        return exports;
    }();
    return scrypt;
};

var MAX_VALUE = 2147483647;

var SCRYPT_ALLOC = Math.pow(2, 25);

var scrypt_module = scrypt_module_factory(SCRYPT_ALLOC);

function scrypt(passwd, salt, N, r, p, dkLen) {
    if (N == 0 || (N & N - 1) != 0) throw Error("N must be > 0 and a power of 2");
    if (N > MAX_VALUE / 128 / r) throw Error("Parameter N is too large");
    if (r > MAX_VALUE / 128 / p) throw Error("Parameter r is too large");
    if (passwd.constructor == String) passwd = scrypt_module.encode_utf8(passwd);
    if (salt.constructor == String) salt = scrypt_module.encode_utf8(salt);
    passwd = new Uint8Array(passwd);
    salt = new Uint8Array(salt);
    var result = scrypt_module.crypto_scrypt(passwd, salt, N, r, p, dkLen);
    var resultBytes = [];
    for (var i = 0; i < result.length; i++) {
        resultBytes[i] = result[i];
    }
    return resultBytes;
}

function Arcfour() {
    this.i = 0;
    this.j = 0;
    this.S = new Array();
}

function ARC4init(key) {
    var i, j, t;
    for (i = 0; i < 256; ++i) this.S[i] = i;
    j = 0;
    for (i = 0; i < 256; ++i) {
        j = j + this.S[i] + key[i % key.length] & 255;
        t = this.S[i];
        this.S[i] = this.S[j];
        this.S[j] = t;
    }
    this.i = 0;
    this.j = 0;
}

function ARC4next() {
    var t;
    this.i = this.i + 1 & 255;
    this.j = this.j + this.S[this.i] & 255;
    t = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = t;
    return this.S[t + this.S[this.i] & 255];
}

Arcfour.prototype.init = ARC4init;

Arcfour.prototype.next = ARC4next;

function prng_newstate() {
    return new Arcfour();
}

var rng_psize = 256;

var rng_state;

var rng_pool;

var rng_pptr;

function rng_seed_int(x) {
    rng_pool[rng_pptr++] ^= x & 255;
    rng_pool[rng_pptr++] ^= x >> 8 & 255;
    rng_pool[rng_pptr++] ^= x >> 16 & 255;
    rng_pool[rng_pptr++] ^= x >> 24 & 255;
    if (rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

function rng_seed_time() {
    rng_seed_int(new Date().getTime());
}

if (rng_pool == null) {
    rng_pool = new Array();
    rng_pptr = 0;
    var t;
    if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t) rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
    }
    while (rng_pptr < rng_psize) {
        t = Math.floor(65536 * Math.random());
        rng_pool[rng_pptr++] = t >>> 8;
        rng_pool[rng_pptr++] = t & 255;
    }
    rng_pptr = 0;
    rng_seed_time();
}

function rng_get_byte() {
    if (rng_state == null) {
        rng_seed_time();
        rng_state = prng_newstate();
        rng_state.init(rng_pool);
        for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr) rng_pool[rng_pptr] = 0;
        rng_pptr = 0;
    }
    return rng_state.next();
}

function rng_get_bytes(ba) {
    var i;
    for (i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

var dbits;

var canary = 0xdeadbeefcafe;

var j_lm = (canary & 16777215) == 15715070;

function BigInteger(a, b, c) {
    if (a != null) if ("number" == typeof a) this.fromNumber(a, b, c); else if (b == null && "string" != typeof a) this.fromString(a, 256); else this.fromString(a, b);
}

function nbi() {
    return new BigInteger(null);
}

function am1(i, x, w, j, c, n) {
    while (--n >= 0) {
        var v = x * this[i++] + w[j] + c;
        c = Math.floor(v / 67108864);
        w[j++] = v & 67108863;
    }
    return c;
}

function am2(i, x, w, j, c, n) {
    var xl = x & 32767, xh = x >> 15;
    while (--n >= 0) {
        var l = this[i] & 32767;
        var h = this[i++] >> 15;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 32767) << 15) + w[j] + (c & 1073741823);
        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
        w[j++] = l & 1073741823;
    }
    return c;
}

function am3(i, x, w, j, c, n) {
    var xl = x & 16383, xh = x >> 14;
    while (--n >= 0) {
        var l = this[i] & 16383;
        var h = this[i++] >> 14;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 16383) << 14) + w[j] + c;
        c = (l >> 28) + (m >> 14) + xh * h;
        w[j++] = l & 268435455;
    }
    return c;
}

if (j_lm && navigator.appName == "Microsoft Internet Explorer") {
    BigInteger.prototype.am = am2;
    dbits = 30;
} else if (j_lm && navigator.appName != "Netscape") {
    BigInteger.prototype.am = am1;
    dbits = 26;
} else {
    BigInteger.prototype.am = am3;
    dbits = 28;
}

BigInteger.prototype.DB = dbits;

BigInteger.prototype.DM = (1 << dbits) - 1;

BigInteger.prototype.DV = 1 << dbits;

var BI_FP = 52;

BigInteger.prototype.FV = Math.pow(2, BI_FP);

BigInteger.prototype.F1 = BI_FP - dbits;

BigInteger.prototype.F2 = 2 * dbits - BI_FP;

var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";

var BI_RC = new Array();

var rr, vv;

rr = "0".charCodeAt(0);

for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;

rr = "a".charCodeAt(0);

for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

rr = "A".charCodeAt(0);

for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) {
    return BI_RM.charAt(n);
}

function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return c == null ? -1 : c;
}

function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
}

function bnpFromInt(x) {
    this.t = 1;
    this.s = x < 0 ? -1 : 0;
    if (x > 0) this[0] = x; else if (x < -1) this[0] = x + DV; else this.t = 0;
}

function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}

function bnpFromString(s, b) {
    var k;
    if (b == 16) k = 4; else if (b == 8) k = 3; else if (b == 256) k = 8; else if (b == 2) k = 1; else if (b == 32) k = 5; else if (b == 4) k = 2; else {
        this.fromRadix(s, b);
        return;
    }
    this.t = 0;
    this.s = 0;
    var i = s.length, mi = false, sh = 0;
    while (--i >= 0) {
        var x = k == 8 ? s[i] & 255 : intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-") mi = true;
            continue;
        }
        mi = false;
        if (sh == 0) this[this.t++] = x; else if (sh + k > this.DB) {
            this[this.t - 1] |= (x & (1 << this.DB - sh) - 1) << sh;
            this[this.t++] = x >> this.DB - sh;
        } else this[this.t - 1] |= x << sh;
        sh += k;
        if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && (s[0] & 128) != 0) {
        this.s = -1;
        if (sh > 0) this[this.t - 1] |= (1 << this.DB - sh) - 1 << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
}

function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c) --this.t;
}

function bnToString(b) {
    if (this.s < 0) return "-" + this.negate().toString(b);
    var k;
    if (b == 16) k = 4; else if (b == 8) k = 3; else if (b == 2) k = 1; else if (b == 32) k = 5; else if (b == 4) k = 2; else return this.toRadix(b);
    var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
    var p = this.DB - i * this.DB % k;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) > 0) {
            m = true;
            r = int2char(d);
        }
        while (i >= 0) {
            if (p < k) {
                d = (this[i] & (1 << p) - 1) << k - p;
                d |= this[--i] >> (p += this.DB - k);
            } else {
                d = this[i] >> (p -= k) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if (d > 0) m = true;
            if (m) r += int2char(d);
        }
    }
    return m ? r : "0";
}

function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
}

function bnAbs() {
    return this.s < 0 ? this.negate() : this;
}

function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0) return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0) return this.s < 0 ? -r : r;
    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
    return 0;
}

function nbits(x) {
    var r = 1, t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) != 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) != 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}

function bnBitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM);
}

function bnpDLShiftTo(n, r) {
    var i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
}

function bnpDRShiftTo(n, r) {
    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
}

function bnpLShiftTo(n, r) {
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << cbs) - 1;
    var ds = Math.floor(n / this.DB), c = this.s << bs & this.DM, i;
    for (i = this.t - 1; i >= 0; --i) {
        r[i + ds + 1] = this[i] >> cbs | c;
        c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
}

function bnpRShiftTo(n, r) {
    r.s = this.s;
    var ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
        r.t = 0;
        return;
    }
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (var i = ds + 1; i < this.t; ++i) {
        r[i - ds - 1] |= (this[i] & bm) << cbs;
        r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
}

function bnpSubTo(a, r) {
    var i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] - a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c -= a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    } else {
        c += this.s;
        while (i < a.t) {
            c -= a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c; else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
}

function bnpMultiplyTo(a, r) {
    var x = this.abs(), y = a.abs();
    var i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

function bnpSquareTo(r) {
    var x = this.abs();
    var i = r.t = 2 * x.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
        var c = x.am(i, x[i], r, 2 * i, 0, 1);
        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
            r[i + x.t] -= x.DV;
            r[i + x.t + 1] = 1;
        }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}

function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0) return;
    var pt = this.abs();
    if (pt.t < pm.t) {
        if (q != null) q.fromInt(0);
        if (r != null) this.copyTo(r);
        return;
    }
    if (r == null) r = nbi();
    var y = nbi(), ts = this.s, ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]);
    if (nsh > 0) {
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
    } else {
        pm.copyTo(y);
        pt.copyTo(r);
    }
    var ys = y.t;
    var y0 = y[ys - 1];
    if (y0 == 0) return;
    var yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
    var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
    var i = r.t, j = i - ys, t = q == null ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
        r[r.t++] = 1;
        r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
        var qd = r[--i] == y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
            y.dlShiftTo(j, t);
            r.subTo(t, r);
            while (r[i] < --qd) r.subTo(t, r);
        }
    }
    if (q != null) {
        r.drShiftTo(ys, q);
        if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r);
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
}

function Classic(m) {
    this.m = m;
}

function cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m); else return x;
}

function cRevert(x) {
    return x;
}

function cReduce(x) {
    x.divRemTo(this.m, null, x);
}

function cMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

function cSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

Classic.prototype.convert = cConvert;

Classic.prototype.revert = cRevert;

Classic.prototype.reduce = cReduce;

Classic.prototype.mulTo = cMulTo;

Classic.prototype.sqrTo = cSqrTo;

function bnpInvDigit() {
    if (this.t < 1) return 0;
    var x = this[0];
    if ((x & 1) == 0) return 0;
    var y = x & 3;
    y = y * (2 - (x & 15) * y) & 15;
    y = y * (2 - (x & 255) * y) & 255;
    y = y * (2 - ((x & 65535) * y & 65535)) & 65535;
    y = y * (2 - x * y % this.DV) % this.DV;
    return y > 0 ? this.DV - y : -y;
}

function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 32767;
    this.mph = this.mp >> 15;
    this.um = (1 << m.DB - 15) - 1;
    this.mt2 = 2 * m.t;
}

function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
}

function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
}

function montReduce(x) {
    while (x.t <= this.mt2) x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {
        var j = x[i] & 32767;
        var u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
        j = i + this.m.t;
        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
        while (x[j] >= x.DV) {
            x[j] -= x.DV;
            x[++j]++;
        }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Montgomery.prototype.convert = montConvert;

Montgomery.prototype.revert = montRevert;

Montgomery.prototype.reduce = montReduce;

Montgomery.prototype.mulTo = montMulTo;

Montgomery.prototype.sqrTo = montSqrTo;

function bnpIsEven() {
    return (this.t > 0 ? this[0] & 1 : this.s) == 0;
}

function bnpExp(e, z) {
    if (e > 4294967295 || e < 1) return BigInteger.ONE;
    var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
        z.sqrTo(r, r2);
        if ((e & 1 << i) > 0) z.mulTo(r2, g, r); else {
            var t = r;
            r = r2;
            r2 = t;
        }
    }
    return z.revert(r);
}

function bnModPowInt(e, m) {
    var z;
    if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
    return this.exp(e, z);
}

BigInteger.prototype.copyTo = bnpCopyTo;

BigInteger.prototype.fromInt = bnpFromInt;

BigInteger.prototype.fromString = bnpFromString;

BigInteger.prototype.clamp = bnpClamp;

BigInteger.prototype.dlShiftTo = bnpDLShiftTo;

BigInteger.prototype.drShiftTo = bnpDRShiftTo;

BigInteger.prototype.lShiftTo = bnpLShiftTo;

BigInteger.prototype.rShiftTo = bnpRShiftTo;

BigInteger.prototype.subTo = bnpSubTo;

BigInteger.prototype.multiplyTo = bnpMultiplyTo;

BigInteger.prototype.squareTo = bnpSquareTo;

BigInteger.prototype.divRemTo = bnpDivRemTo;

BigInteger.prototype.invDigit = bnpInvDigit;

BigInteger.prototype.isEven = bnpIsEven;

BigInteger.prototype.exp = bnpExp;

BigInteger.prototype.toString = bnToString;

BigInteger.prototype.negate = bnNegate;

BigInteger.prototype.abs = bnAbs;

BigInteger.prototype.compareTo = bnCompareTo;

BigInteger.prototype.bitLength = bnBitLength;

BigInteger.prototype.mod = bnMod;

BigInteger.prototype.modPowInt = bnModPowInt;

BigInteger.ZERO = nbv(0);

BigInteger.ONE = nbv(1);

function bnClone() {
    var r = nbi();
    this.copyTo(r);
    return r;
}

function bnIntValue() {
    if (this.s < 0) {
        if (this.t == 1) return this[0] - this.DV; else if (this.t == 0) return -1;
    } else if (this.t == 1) return this[0]; else if (this.t == 0) return 0;
    return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0];
}

function bnByteValue() {
    return this.t == 0 ? this.s : this[0] << 24 >> 24;
}

function bnShortValue() {
    return this.t == 0 ? this.s : this[0] << 16 >> 16;
}

function bnpChunkSize(r) {
    return Math.floor(Math.LN2 * this.DB / Math.log(r));
}

function bnSigNum() {
    if (this.s < 0) return -1; else if (this.t <= 0 || this.t == 1 && this[0] <= 0) return 0; else return 1;
}

function bnpToRadix(b) {
    if (b == null) b = 10;
    if (this.signum() == 0 || b < 2 || b > 36) return "0";
    var cs = this.chunkSize(b);
    var a = Math.pow(b, cs);
    var d = nbv(a), y = nbi(), z = nbi(), r = "";
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
        r = (a + z.intValue()).toString(b).substr(1) + r;
        y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
}

function bnpFromRadix(s, b) {
    this.fromInt(0);
    if (b == null) b = 10;
    var cs = this.chunkSize(b);
    var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
    for (var i = 0; i < s.length; ++i) {
        var x = intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
            continue;
        }
        w = b * w + x;
        if (++j >= cs) {
            this.dMultiply(d);
            this.dAddOffset(w, 0);
            j = 0;
            w = 0;
        }
    }
    if (j > 0) {
        this.dMultiply(Math.pow(b, j));
        this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
}

function bnpFromNumber(a, b, c) {
    if ("number" == typeof b) {
        if (a < 2) this.fromInt(1); else {
            this.fromNumber(a, c);
            if (!this.testBit(a - 1)) this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
            if (this.isEven()) this.dAddOffset(1, 0);
            while (!this.isProbablePrime(b)) {
                this.dAddOffset(2, 0);
                if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
            }
        }
    } else {
        var x = new Array(), t = a & 7;
        x.length = (a >> 3) + 1;
        b.nextBytes(x);
        if (t > 0) x[0] &= (1 << t) - 1; else x[0] = 0;
        this.fromString(x, 256);
    }
}

function bnToByteArray() {
    var i = this.t, r = new Array();
    r[0] = this.s;
    var p = this.DB - i * this.DB % 8, d, k = 0;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p) r[k++] = d | this.s << this.DB - p;
        while (i >= 0) {
            if (p < 8) {
                d = (this[i] & (1 << p) - 1) << 8 - p;
                d |= this[--i] >> (p += this.DB - 8);
            } else {
                d = this[i] >> (p -= 8) & 255;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if ((d & 128) != 0) d |= -256;
            if (k == 0 && (this.s & 128) != (d & 128)) ++k;
            if (k > 0 || d != this.s) r[k++] = d;
        }
    }
    return r;
}

function bnEquals(a) {
    return this.compareTo(a) == 0;
}

function bnMin(a) {
    return this.compareTo(a) < 0 ? this : a;
}

function bnMax(a) {
    return this.compareTo(a) > 0 ? this : a;
}

function bnpBitwiseTo(a, op, r) {
    var i, f, m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
    if (a.t < this.t) {
        f = a.s & this.DM;
        for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
        r.t = this.t;
    } else {
        f = this.s & this.DM;
        for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
        r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
}

function op_and(x, y) {
    return x & y;
}

function bnAnd(a) {
    var r = nbi();
    this.bitwiseTo(a, op_and, r);
    return r;
}

function op_or(x, y) {
    return x | y;
}

function bnOr(a) {
    var r = nbi();
    this.bitwiseTo(a, op_or, r);
    return r;
}

function op_xor(x, y) {
    return x ^ y;
}

function bnXor(a) {
    var r = nbi();
    this.bitwiseTo(a, op_xor, r);
    return r;
}

function op_andnot(x, y) {
    return x & ~y;
}

function bnAndNot(a) {
    var r = nbi();
    this.bitwiseTo(a, op_andnot, r);
    return r;
}

function bnNot() {
    var r = nbi();
    for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
    r.t = this.t;
    r.s = ~this.s;
    return r;
}

function bnShiftLeft(n) {
    var r = nbi();
    if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
    return r;
}

function bnShiftRight(n) {
    var r = nbi();
    if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
    return r;
}

function lbit(x) {
    if (x == 0) return -1;
    var r = 0;
    if ((x & 65535) == 0) {
        x >>= 16;
        r += 16;
    }
    if ((x & 255) == 0) {
        x >>= 8;
        r += 8;
    }
    if ((x & 15) == 0) {
        x >>= 4;
        r += 4;
    }
    if ((x & 3) == 0) {
        x >>= 2;
        r += 2;
    }
    if ((x & 1) == 0) ++r;
    return r;
}

function bnGetLowestSetBit() {
    for (var i = 0; i < this.t; ++i) if (this[i] != 0) return i * this.DB + lbit(this[i]);
    if (this.s < 0) return this.t * this.DB;
    return -1;
}

function cbit(x) {
    var r = 0;
    while (x != 0) {
        x &= x - 1;
        ++r;
    }
    return r;
}

function bnBitCount() {
    var r = 0, x = this.s & this.DM;
    for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
    return r;
}

function bnTestBit(n) {
    var j = Math.floor(n / this.DB);
    if (j >= this.t) return this.s != 0;
    return (this[j] & 1 << n % this.DB) != 0;
}

function bnpChangeBit(n, op) {
    var r = BigInteger.ONE.shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
}

function bnSetBit(n) {
    return this.changeBit(n, op_or);
}

function bnClearBit(n) {
    return this.changeBit(n, op_andnot);
}

function bnFlipBit(n) {
    return this.changeBit(n, op_xor);
}

function bnpAddTo(a, r) {
    var i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] + a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c += a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    } else {
        c += this.s;
        while (i < a.t) {
            c += a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += a.s;
    }
    r.s = c < 0 ? -1 : 0;
    if (c > 0) r[i++] = c; else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
}

function bnAdd(a) {
    var r = nbi();
    this.addTo(a, r);
    return r;
}

function bnSubtract(a) {
    var r = nbi();
    this.subTo(a, r);
    return r;
}

function bnMultiply(a) {
    var r = nbi();
    this.multiplyTo(a, r);
    return r;
}

function bnSquare() {
    var r = nbi();
    this.squareTo(r);
    return r;
}

function bnDivide(a) {
    var r = nbi();
    this.divRemTo(a, r, null);
    return r;
}

function bnRemainder(a) {
    var r = nbi();
    this.divRemTo(a, null, r);
    return r;
}

function bnDivideAndRemainder(a) {
    var q = nbi(), r = nbi();
    this.divRemTo(a, q, r);
    return new Array(q, r);
}

function bnpDMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
}

function bnpDAddOffset(n, w) {
    if (n == 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] += n;
    while (this[w] >= this.DV) {
        this[w] -= this.DV;
        if (++w >= this.t) this[this.t++] = 0;
        ++this[w];
    }
}

function NullExp() {}

function nNop(x) {
    return x;
}

function nMulTo(x, y, r) {
    x.multiplyTo(y, r);
}

function nSqrTo(x, r) {
    x.squareTo(r);
}

NullExp.prototype.convert = nNop;

NullExp.prototype.revert = nNop;

NullExp.prototype.mulTo = nMulTo;

NullExp.prototype.sqrTo = nSqrTo;

function bnPow(e) {
    return this.exp(e, new NullExp());
}

function bnpMultiplyLowerTo(a, n, r) {
    var i = Math.min(this.t + a.t, n);
    r.s = 0;
    r.t = i;
    while (i > 0) r[--i] = 0;
    var j;
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
    r.clamp();
}

function bnpMultiplyUpperTo(a, n, r) {
    --n;
    var i = r.t = this.t + a.t - n;
    r.s = 0;
    while (--i >= 0) r[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i) r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
    r.clamp();
    r.drShiftTo(1, r);
}

function Barrett(m) {
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
}

function barrettConvert(x) {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m); else if (x.compareTo(this.m) < 0) return x; else {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }
}

function barrettRevert(x) {
    return x;
}

function barrettReduce(x) {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) {
        x.t = this.m.t + 1;
        x.clamp();
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

function barrettSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

function barrettMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Barrett.prototype.convert = barrettConvert;

Barrett.prototype.revert = barrettRevert;

Barrett.prototype.reduce = barrettReduce;

Barrett.prototype.mulTo = barrettMulTo;

Barrett.prototype.sqrTo = barrettSqrTo;

function bnModPow(e, m) {
    var i = e.bitLength(), k, r = nbv(1), z;
    if (i <= 0) return r; else if (i < 18) k = 1; else if (i < 48) k = 3; else if (i < 144) k = 4; else if (i < 768) k = 5; else k = 6;
    if (i < 8) z = new Classic(m); else if (m.isEven()) z = new Barrett(m); else z = new Montgomery(m);
    var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
        var g2 = nbi();
        z.sqrTo(g[1], g2);
        while (n <= km) {
            g[n] = nbi();
            z.mulTo(g2, g[n - 2], g[n]);
            n += 2;
        }
    }
    var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
    i = nbits(e[j]) - 1;
    while (j >= 0) {
        if (i >= k1) w = e[j] >> i - k1 & km; else {
            w = (e[j] & (1 << i + 1) - 1) << k1 - i;
            if (j > 0) w |= e[j - 1] >> this.DB + i - k1;
        }
        n = k;
        while ((w & 1) == 0) {
            w >>= 1;
            --n;
        }
        if ((i -= n) < 0) {
            i += this.DB;
            --j;
        }
        if (is1) {
            g[w].copyTo(r);
            is1 = false;
        } else {
            while (n > 1) {
                z.sqrTo(r, r2);
                z.sqrTo(r2, r);
                n -= 2;
            }
            if (n > 0) z.sqrTo(r, r2); else {
                t = r;
                r = r2;
                r2 = t;
            }
            z.mulTo(r2, g[w], r);
        }
        while (j >= 0 && (e[j] & 1 << i) == 0) {
            z.sqrTo(r, r2);
            t = r;
            r = r2;
            r2 = t;
            if (--i < 0) {
                i = this.DB - 1;
                --j;
            }
        }
    }
    return z.revert(r);
}

function bnGCD(a) {
    var x = this.s < 0 ? this.negate() : this.clone();
    var y = a.s < 0 ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
        var t = x;
        x = y;
        y = t;
    }
    var i = x.getLowestSetBit(), g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
        x.rShiftTo(g, x);
        y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
        if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
        if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
        if (x.compareTo(y) >= 0) {
            x.subTo(y, x);
            x.rShiftTo(1, x);
        } else {
            y.subTo(x, y);
            y.rShiftTo(1, y);
        }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
}

function bnpModInt(n) {
    if (n <= 0) return 0;
    var d = this.DV % n, r = this.s < 0 ? n - 1 : 0;
    if (this.t > 0) if (d == 0) r = this[0] % n; else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
    return r;
}

function bnModInverse(m) {
    var ac = m.isEven();
    if (this.isEven() && ac || m.signum() == 0) return BigInteger.ZERO;
    var u = m.clone(), v = this.clone();
    var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
    while (u.signum() != 0) {
        while (u.isEven()) {
            u.rShiftTo(1, u);
            if (ac) {
                if (!a.isEven() || !b.isEven()) {
                    a.addTo(this, a);
                    b.subTo(m, b);
                }
                a.rShiftTo(1, a);
            } else if (!b.isEven()) b.subTo(m, b);
            b.rShiftTo(1, b);
        }
        while (v.isEven()) {
            v.rShiftTo(1, v);
            if (ac) {
                if (!c.isEven() || !d.isEven()) {
                    c.addTo(this, c);
                    d.subTo(m, d);
                }
                c.rShiftTo(1, c);
            } else if (!d.isEven()) d.subTo(m, d);
            d.rShiftTo(1, d);
        }
        if (u.compareTo(v) >= 0) {
            u.subTo(v, u);
            if (ac) a.subTo(c, a);
            b.subTo(d, b);
        } else {
            v.subTo(u, v);
            if (ac) c.subTo(a, c);
            d.subTo(b, d);
        }
    }
    if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d); else return d;
    if (d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997 ];

var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

function bnIsProbablePrime(t) {
    var i, x = this.abs();
    if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
        for (i = 0; i < lowprimes.length; ++i) if (x[0] == lowprimes[i]) return true;
        return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < lowprimes.length) {
        var m = lowprimes[i], j = i + 1;
        while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
        m = x.modInt(m);
        while (i < j) if (m % lowprimes[i++] == 0) return false;
    }
    return x.millerRabin(t);
}

function bnpMillerRabin(t) {
    var n1 = this.subtract(BigInteger.ONE);
    var k = n1.getLowestSetBit();
    if (k <= 0) return false;
    var r = n1.shiftRight(k);
    t = t + 1 >> 1;
    if (t > lowprimes.length) t = lowprimes.length;
    var a = nbi();
    for (var i = 0; i < t; ++i) {
        a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
        var y = a.modPow(r, this);
        if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
            var j = 1;
            while (j++ < k && y.compareTo(n1) != 0) {
                y = y.modPowInt(2, this);
                if (y.compareTo(BigInteger.ONE) == 0) return false;
            }
            if (y.compareTo(n1) != 0) return false;
        }
    }
    return true;
}

BigInteger.prototype.chunkSize = bnpChunkSize;

BigInteger.prototype.toRadix = bnpToRadix;

BigInteger.prototype.fromRadix = bnpFromRadix;

BigInteger.prototype.fromNumber = bnpFromNumber;

BigInteger.prototype.bitwiseTo = bnpBitwiseTo;

BigInteger.prototype.changeBit = bnpChangeBit;

BigInteger.prototype.addTo = bnpAddTo;

BigInteger.prototype.dMultiply = bnpDMultiply;

BigInteger.prototype.dAddOffset = bnpDAddOffset;

BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;

BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;

BigInteger.prototype.modInt = bnpModInt;

BigInteger.prototype.millerRabin = bnpMillerRabin;

BigInteger.prototype.clone = bnClone;

BigInteger.prototype.intValue = bnIntValue;

BigInteger.prototype.byteValue = bnByteValue;

BigInteger.prototype.shortValue = bnShortValue;

BigInteger.prototype.signum = bnSigNum;

BigInteger.prototype.toByteArray = bnToByteArray;

BigInteger.prototype.equals = bnEquals;

BigInteger.prototype.min = bnMin;

BigInteger.prototype.max = bnMax;

BigInteger.prototype.and = bnAnd;

BigInteger.prototype.or = bnOr;

BigInteger.prototype.xor = bnXor;

BigInteger.prototype.andNot = bnAndNot;

BigInteger.prototype.not = bnNot;

BigInteger.prototype.shiftLeft = bnShiftLeft;

BigInteger.prototype.shiftRight = bnShiftRight;

BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;

BigInteger.prototype.bitCount = bnBitCount;

BigInteger.prototype.testBit = bnTestBit;

BigInteger.prototype.setBit = bnSetBit;

BigInteger.prototype.clearBit = bnClearBit;

BigInteger.prototype.flipBit = bnFlipBit;

BigInteger.prototype.add = bnAdd;

BigInteger.prototype.subtract = bnSubtract;

BigInteger.prototype.multiply = bnMultiply;

BigInteger.prototype.divide = bnDivide;

BigInteger.prototype.remainder = bnRemainder;

BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;

BigInteger.prototype.modPow = bnModPow;

BigInteger.prototype.modInverse = bnModInverse;

BigInteger.prototype.pow = bnPow;

BigInteger.prototype.gcd = bnGCD;

BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

BigInteger.prototype.square = bnSquare;

function ECFieldElementFp(q, x) {
    this.x = x;
    this.q = q;
}

function feFpEquals(other) {
    if (other == this) return true;
    return this.q.equals(other.q) && this.x.equals(other.x);
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;

ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;

ECFieldElementFp.prototype.negate = feFpNegate;

ECFieldElementFp.prototype.add = feFpAdd;

ECFieldElementFp.prototype.subtract = feFpSubtract;

ECFieldElementFp.prototype.multiply = feFpMultiply;

ECFieldElementFp.prototype.square = feFpSquare;

ECFieldElementFp.prototype.divide = feFpDivide;

function ECPointFp(curve, x, y, z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    if (z == null) {
        this.z = BigInteger.ONE;
    } else {
        this.z = z;
    }
    this.zinv = null;
}

function pointFpGetX() {
    if (this.zinv == null) {
        this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpGetY() {
    if (this.zinv == null) {
        this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpEquals(other) {
    if (other == this) return true;
    if (this.isInfinity()) return other.isInfinity();
    if (other.isInfinity()) return this.isInfinity();
    var u, v;
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if (!u.equals(BigInteger.ZERO)) return false;
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if (this.x == null && this.y == null) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if (this.isInfinity()) return b;
    if (b.isInfinity()) return this;
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);
    if (BigInteger.ZERO.equals(v)) {
        if (BigInteger.ZERO.equals(u)) {
            return this.twice();
        }
        return this.curve.getInfinity();
    }
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();
    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);
    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if (this.isInfinity()) return this;
    if (this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();
    var w = x1.square().multiply(THREE);
    if (!BigInteger.ZERO.equals(a)) {
        w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);
    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpMultiply(k) {
    if (this.isInfinity()) return this;
    if (k.signum() == 0) return this.curve.getInfinity();
    var e = k;
    var h = e.multiply(new BigInteger("3"));
    var neg = this.negate();
    var R = this;
    var i;
    for (i = h.bitLength() - 2; i > 0; --i) {
        R = R.twice();
        var hBit = h.testBit(i);
        var eBit = e.testBit(i);
        if (hBit != eBit) {
            R = R.add(hBit ? this : neg);
        }
    }
    return R;
}

function pointFpMultiplyTwo(j, x, k) {
    var i;
    if (j.bitLength() > k.bitLength()) i = j.bitLength() - 1; else i = k.bitLength() - 1;
    var R = this.curve.getInfinity();
    var both = this.add(x);
    while (i >= 0) {
        R = R.twice();
        if (j.testBit(i)) {
            if (k.testBit(i)) {
                R = R.add(both);
            } else {
                R = R.add(this);
            }
        } else {
            if (k.testBit(i)) {
                R = R.add(x);
            }
        }
        --i;
    }
    return R;
}

ECPointFp.prototype.getX = pointFpGetX;

ECPointFp.prototype.getY = pointFpGetY;

ECPointFp.prototype.equals = pointFpEquals;

ECPointFp.prototype.isInfinity = pointFpIsInfinity;

ECPointFp.prototype.negate = pointFpNegate;

ECPointFp.prototype.add = pointFpAdd;

ECPointFp.prototype.twice = pointFpTwice;

ECPointFp.prototype.multiply = pointFpMultiply;

ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

function ECCurveFp(q, a, b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if (other == this) return true;
    return this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b);
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

function curveFpDecompressPoint(yOdd, X) {
    if (this.q.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
        var ySquared = X.multiply(X.square().add(this.a)).add(this.b);
        var Y = ySquared.x.modPow(this.q.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), this.q);
        if (Y.testBit(0) !== yOdd) {
            Y = this.q.subtract(Y);
        }
        return new ECPointFp(this, X, this.fromBigInteger(Y));
    } else {
        throw new Error("point decompression only implements sqrt for q = 3 mod 4");
    }
}

function curveFpDecodePointHex(s) {
    switch (parseInt(s.substr(0, 2), 16)) {
      case 0:
        return this.infinity;

      case 2:
        return this.decompressPoint(false, this.fromBigInteger(new BigInteger(s.substr(2), 16)));

      case 3:
        return this.decompressPoint(true, this.fromBigInteger(new BigInteger(s.substr(2), 16)));

      case 4:
      case 6:
      case 7:
        var len = (s.length - 2) / 2;
        var xHex = s.substr(2, len);
        var yHex = s.substr(len + 2, len);
        return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)));

      default:
        return null;
    }
}

ECCurveFp.prototype.getQ = curveFpGetQ;

ECCurveFp.prototype.getA = curveFpGetA;

ECCurveFp.prototype.getB = curveFpGetB;

ECCurveFp.prototype.equals = curveFpEquals;

ECCurveFp.prototype.getInfinity = curveFpGetInfinity;

ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;

ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;

ECCurveFp.prototype.decompressPoint = curveFpDecompressPoint;

function X9ECParameters(curve, g, n, h) {
    this.curve = curve;
    this.g = g;
    this.n = n;
    this.h = h;
}

function x9getCurve() {
    return this.curve;
}

function x9getG() {
    return this.g;
}

function x9getN() {
    return this.n;
}

function x9getH() {
    return this.h;
}

X9ECParameters.prototype.getCurve = x9getCurve;

X9ECParameters.prototype.getG = x9getG;

X9ECParameters.prototype.getN = x9getN;

X9ECParameters.prototype.getH = x9getH;

function fromHex(s) {
    return new BigInteger(s, 16);
}

function secp128r1() {
    var p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
    var n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "161FF7528B899B2D0C28607CA52C5B86" + "CF5AC8395BAFEB13C02DA292DDED7A83");
    return new X9ECParameters(curve, G, n, h);
}

function secp160k1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    var n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB" + "938CF935318FDCED6BC28286531733C3F03C4FEE");
    return new X9ECParameters(curve, G, n, h);
}

function secp160r1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
    var b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
    var n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "4A96B5688EF573284664698968C38BB913CBFC82" + "23A628553168947D59DCC912042351377AC5FB32");
    return new X9ECParameters(curve, G, n, h);
}

function secp192k1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
    var a = BigInteger.ZERO;
    var b = fromHex("3");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D" + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
    return new X9ECParameters(curve, G, n, h);
}

function secp192r1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
    var b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012" + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
    return new X9ECParameters(curve, G, n, h);
}

function secp224r1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21" + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    return new X9ECParameters(curve, G, n, h);
}

function secp256k1() {
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    return new X9ECParameters(curve, G, n, h);
}

function secp256r1() {
    var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04" + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return new X9ECParameters(curve, G, n, h);
}

function getSECCurveByName(name) {
    if (name == "secp128r1") return secp128r1();
    if (name == "secp160k1") return secp160k1();
    if (name == "secp160r1") return secp160r1();
    if (name == "secp192k1") return secp192k1();
    if (name == "secp192r1") return secp192r1();
    if (name == "secp224r1") return secp224r1();
    if (name == "secp256k1") return secp256k1();
    if (name == "secp256r1") return secp256r1();
    return null;
}

var EventEmitter = function() {};

EventEmitter.prototype.on = function(name, callback, context) {
    if (!context) context = this;
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) this._listeners[name] = [];
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) this._unbinders[name] = [];
    var f = function(e) {
        callback.apply(context, [ e ]);
    };
    this._unbinders[name].push(callback);
    this._listeners[name].push(f);
};

EventEmitter.prototype.trigger = function(name, event) {
    if (event === undefined) event = {};
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) return;
    var i = this._listeners[name].length;
    while (i--) this._listeners[name][i](event);
};

EventEmitter.prototype.removeListener = function(name, callback) {
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) return;
    var i = this._unbinders[name].length;
    while (i--) {
        if (this._unbinders[name][i] === callback) {
            this._unbinders[name].splice(i, 1);
            this._listeners[name].splice(i, 1);
        }
    }
};

EventEmitter.augment = function(obj) {
    for (var method in EventEmitter.prototype) {
        if (!obj[method]) obj[method] = EventEmitter.prototype[method];
    }
};

(function(exports) {
    var Bitcoin = exports;
    if ("object" !== typeof module) {
        Bitcoin.EventEmitter = EventEmitter;
    }
})("object" === typeof module ? module.exports : window.Bitcoin = {});

BigInteger.valueOf = nbv;

BigInteger.prototype.toByteArrayUnsigned = function() {
    var ba = this.abs().toByteArray();
    if (ba.length) {
        if (ba[0] == 0) {
            ba = ba.slice(1);
        }
        return ba.map(function(v) {
            return v < 0 ? v + 256 : v;
        });
    } else {
        return ba;
    }
};

BigInteger.fromByteArrayUnsigned = function(ba) {
    if (!ba.length) {
        return ba.valueOf(0);
    } else if (ba[0] & 128) {
        return new BigInteger([ 0 ].concat(ba));
    } else {
        return new BigInteger(ba);
    }
};

BigInteger.prototype.toByteArraySigned = function() {
    var val = this.abs().toByteArrayUnsigned();
    var neg = this.compareTo(BigInteger.ZERO) < 0;
    if (neg) {
        if (val[0] & 128) {
            val.unshift(128);
        } else {
            val[0] |= 128;
        }
    } else {
        if (val[0] & 128) {
            val.unshift(0);
        }
    }
    return val;
};

BigInteger.fromByteArraySigned = function(ba) {
    if (ba[0] & 128) {
        ba[0] &= 127;
        return BigInteger.fromByteArrayUnsigned(ba).negate();
    } else {
        return BigInteger.fromByteArrayUnsigned(ba);
    }
};

var names = [ "log", "debug", "info", "warn", "error", "assert", "dir", "dirxml", "group", "groupEnd", "time", "timeEnd", "count", "trace", "profile", "profileEnd" ];

if ("undefined" == typeof window.console) window.console = {};

for (var i = 0; i < names.length; ++i) if ("undefined" == typeof window.console[names[i]]) window.console[names[i]] = function() {};

Bitcoin.Util = {
    isArray: Array.isArray || function(o) {
        return Object.prototype.toString.call(o) === "[object Array]";
    },
    makeFilledArray: function(len, val) {
        var array = [];
        var i = 0;
        while (i < len) {
            array[i++] = val;
        }
        return array;
    },
    numToVarInt: function(i) {
        if (i < 253) {
            return [ i ];
        } else if (i <= 1 << 16) {
            return [ 253, i >>> 8, i & 255 ];
        } else if (i <= 1 << 32) {
            return [ 254 ].concat(Crypto.util.wordsToBytes([ i ]));
        } else {
            return [ 255 ].concat(Crypto.util.wordsToBytes([ i >>> 32, i ]));
        }
    },
    valueToBigInt: function(valueBuffer) {
        if (valueBuffer instanceof BigInteger) return valueBuffer;
        return BigInteger.fromByteArrayUnsigned(valueBuffer);
    },
    formatValue: function(valueBuffer) {
        var value = this.valueToBigInt(valueBuffer).toString();
        var integerPart = value.length > 8 ? value.substr(0, value.length - 8) : "0";
        var decimalPart = value.length > 8 ? value.substr(value.length - 8) : value;
        while (decimalPart.length < 8) decimalPart = "0" + decimalPart;
        decimalPart = decimalPart.replace(/0*$/, "");
        while (decimalPart.length < 2) decimalPart += "0";
        return integerPart + "." + decimalPart;
    },
    parseValue: function(valueString) {
        var valueComp = valueString.split(".");
        var integralPart = valueComp[0];
        var fractionalPart = valueComp[1] || "0";
        while (fractionalPart.length < 8) fractionalPart += "0";
        fractionalPart = fractionalPart.replace(/^0+/g, "");
        var value = BigInteger.valueOf(parseInt(integralPart));
        value = value.multiply(BigInteger.valueOf(1e8));
        value = value.add(BigInteger.valueOf(parseInt(fractionalPart)));
        return value;
    },
    sha256ripe160: function(data) {
        return Crypto.RIPEMD160(Crypto.SHA256(data, {
            asBytes: true
        }), {
            asBytes: true
        });
    },
    dsha256: function(data) {
        return Crypto.SHA256(Crypto.SHA256(data, {
            asBytes: true
        }), {
            asBytes: true
        });
    }
};

for (var i in Crypto.util) {
    if (Crypto.util.hasOwnProperty(i)) {
        Bitcoin.Util[i] = Crypto.util[i];
    }
}

(function(Bitcoin) {
    Bitcoin.Base58 = {
        alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        validRegex: /^[1-9A-HJ-NP-Za-km-z]+$/,
        base: BigInteger.valueOf(58),
        encode: function(input) {
            var bi = BigInteger.fromByteArrayUnsigned(input);
            var chars = [];
            while (bi.compareTo(B58.base) >= 0) {
                var mod = bi.mod(B58.base);
                chars.unshift(B58.alphabet[mod.intValue()]);
                bi = bi.subtract(mod).divide(B58.base);
            }
            chars.unshift(B58.alphabet[bi.intValue()]);
            for (var i = 0; i < input.length; i++) {
                if (input[i] == 0) {
                    chars.unshift(B58.alphabet[0]);
                } else break;
            }
            return chars.join("");
        },
        decode: function(input) {
            var bi = BigInteger.valueOf(0);
            var leadingZerosNum = 0;
            for (var i = input.length - 1; i >= 0; i--) {
                var alphaIndex = B58.alphabet.indexOf(input[i]);
                if (alphaIndex < 0) {
                    throw "Invalid character";
                }
                bi = bi.add(BigInteger.valueOf(alphaIndex).multiply(B58.base.pow(input.length - 1 - i)));
                if (input[i] == "1") leadingZerosNum++; else leadingZerosNum = 0;
            }
            var bytes = bi.toByteArrayUnsigned();
            while (leadingZerosNum-- > 0) bytes.unshift(0);
            return bytes;
        }
    };
    var B58 = Bitcoin.Base58;
})("undefined" != typeof Bitcoin ? Bitcoin : module.exports);

Bitcoin.Address = function(bytes) {
    if ("string" == typeof bytes) {
        bytes = Bitcoin.Address.decodeString(bytes);
    }
    this.hash = bytes;
    this.version = Bitcoin.Address.networkVersion;
};

Bitcoin.Address.networkVersion = 0;

Bitcoin.Address.prototype.toString = function() {
    var hash = this.hash.slice(0);
    hash.unshift(this.version);
    var checksum = Bitcoin.Util.dsha256(hash);
    var bytes = hash.concat(checksum.slice(0, 4));
    return Bitcoin.Base58.encode(bytes);
};

Bitcoin.Address.prototype.getHashBase64 = function() {
    return Crypto.util.bytesToBase64(this.hash);
};

Bitcoin.Address.decodeString = function(string) {
    var bytes = Bitcoin.Base58.decode(string);
    var hash = bytes.slice(0, 21);
    var checksum = Bitcoin.Util.dsha256(hash);
    if (checksum[0] != bytes[21] || checksum[1] != bytes[22] || checksum[2] != bytes[23] || checksum[3] != bytes[24]) {
        throw "Checksum validation failed!";
    }
    var version = hash.shift();
    if (version != 0) {
        throw "Version " + version + " not supported!";
    }
    return hash;
};

function integerToBytes(i, len) {
    var bytes = i.toByteArrayUnsigned();
    if (len < bytes.length) {
        bytes = bytes.slice(bytes.length - len);
    } else while (len > bytes.length) {
        bytes.unshift(0);
    }
    return bytes;
}

ECFieldElementFp.prototype.getByteLength = function() {
    return Math.floor((this.toBigInteger().bitLength() + 7) / 8);
};

ECPointFp.prototype.getEncoded = function(compressed) {
    var x = this.getX().toBigInteger();
    var y = this.getY().toBigInteger();
    var enc = integerToBytes(x, 32);
    if (compressed) {
        if (y.isEven()) {
            enc.unshift(2);
        } else {
            enc.unshift(3);
        }
    } else {
        enc.unshift(4);
        enc = enc.concat(integerToBytes(y, 32));
    }
    return enc;
};

ECPointFp.decodeFrom = function(curve, enc) {
    var type = enc[0];
    var dataLen = enc.length - 1;
    var xBa = enc.slice(1, 1 + dataLen / 2);
    var yBa = enc.slice(1 + dataLen / 2, 1 + dataLen);
    xBa.unshift(0);
    yBa.unshift(0);
    var x = new BigInteger(xBa);
    var y = new BigInteger(yBa);
    return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

ECPointFp.prototype.add2D = function(b) {
    if (this.isInfinity()) return b;
    if (b.isInfinity()) return this;
    if (this.x.equals(b.x)) {
        if (this.y.equals(b.y)) {
            return this.twice();
        }
        return this.curve.getInfinity();
    }
    var x_x = b.x.subtract(this.x);
    var y_y = b.y.subtract(this.y);
    var gamma = y_y.divide(x_x);
    var x3 = gamma.square().subtract(this.x).subtract(b.x);
    var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
    return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.twice2D = function() {
    if (this.isInfinity()) return this;
    if (this.y.toBigInteger().signum() == 0) {
        return this.curve.getInfinity();
    }
    var TWO = this.curve.fromBigInteger(BigInteger.valueOf(2));
    var THREE = this.curve.fromBigInteger(BigInteger.valueOf(3));
    var gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));
    var x3 = gamma.square().subtract(this.x.multiply(TWO));
    var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
    return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.multiply2D = function(k) {
    if (this.isInfinity()) return this;
    if (k.signum() == 0) return this.curve.getInfinity();
    var e = k;
    var h = e.multiply(new BigInteger("3"));
    var neg = this.negate();
    var R = this;
    var i;
    for (i = h.bitLength() - 2; i > 0; --i) {
        R = R.twice();
        var hBit = h.testBit(i);
        var eBit = e.testBit(i);
        if (hBit != eBit) {
            R = R.add2D(hBit ? this : neg);
        }
    }
    return R;
};

ECPointFp.prototype.isOnCurve = function() {
    var x = this.getX().toBigInteger();
    var y = this.getY().toBigInteger();
    var a = this.curve.getA().toBigInteger();
    var b = this.curve.getB().toBigInteger();
    var n = this.curve.getQ();
    var lhs = y.multiply(y).mod(n);
    var rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(n);
    return lhs.equals(rhs);
};

ECPointFp.prototype.toString = function() {
    return "(" + this.getX().toBigInteger().toString() + "," + this.getY().toBigInteger().toString() + ")";
};

ECPointFp.prototype.validate = function() {
    var n = this.curve.getQ();
    if (this.isInfinity()) {
        throw new Error("Point is at infinity.");
    }
    var x = this.getX().toBigInteger();
    var y = this.getY().toBigInteger();
    if (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(n.subtract(BigInteger.ONE)) > 0) {
        throw new Error("x coordinate out of bounds");
    }
    if (y.compareTo(BigInteger.ONE) < 0 || y.compareTo(n.subtract(BigInteger.ONE)) > 0) {
        throw new Error("y coordinate out of bounds");
    }
    if (!this.isOnCurve()) {
        throw new Error("Point is not on the curve.");
    }
    if (this.multiply(n).isInfinity()) {
        throw new Error("Point is not a scalar multiple of G.");
    }
    return true;
};

function dmp(v) {
    if (!(v instanceof BigInteger)) v = v.toBigInteger();
    return Crypto.util.bytesToHex(v.toByteArrayUnsigned());
}

Bitcoin.ECDSA = function() {
    var ecparams = getSECCurveByName("secp256k1");
    var rng = new SecureRandom();
    var P_OVER_FOUR = null;
    function implShamirsTrick(P, k, Q, l) {
        var m = Math.max(k.bitLength(), l.bitLength());
        var Z = P.add2D(Q);
        var R = P.curve.getInfinity();
        for (var i = m - 1; i >= 0; --i) {
            R = R.twice2D();
            R.z = BigInteger.ONE;
            if (k.testBit(i)) {
                if (l.testBit(i)) {
                    R = R.add2D(Z);
                } else {
                    R = R.add2D(P);
                }
            } else {
                if (l.testBit(i)) {
                    R = R.add2D(Q);
                }
            }
        }
        return R;
    }
    var ECDSA = {
        getBigRandom: function(limit) {
            return new BigInteger(limit.bitLength(), rng).mod(limit.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        },
        sign: function(hash, priv) {
            var d = priv;
            var n = ecparams.getN();
            var e = BigInteger.fromByteArrayUnsigned(hash);
            do {
                var k = ECDSA.getBigRandom(n);
                var G = ecparams.getG();
                var Q = G.multiply(k);
                var r = Q.getX().toBigInteger().mod(n);
            } while (r.compareTo(BigInteger.ZERO) <= 0);
            var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
            return ECDSA.serializeSig(r, s);
        },
        verify: function(hash, sig, pubkey) {
            var r, s;
            if (Bitcoin.Util.isArray(sig)) {
                var obj = ECDSA.parseSig(sig);
                r = obj.r;
                s = obj.s;
            } else if ("object" === typeof sig && sig.r && sig.s) {
                r = sig.r;
                s = sig.s;
            } else {
                throw "Invalid value for signature";
            }
            var Q;
            if (pubkey instanceof ECPointFp) {
                Q = pubkey;
            } else if (Bitcoin.Util.isArray(pubkey)) {
                Q = ECPointFp.decodeFrom(ecparams.getCurve(), pubkey);
            } else {
                throw "Invalid format for pubkey value, must be byte array or ECPointFp";
            }
            var e = BigInteger.fromByteArrayUnsigned(hash);
            return ECDSA.verifyRaw(e, r, s, Q);
        },
        verifyRaw: function(e, r, s, Q) {
            var n = ecparams.getN();
            var G = ecparams.getG();
            if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0) return false;
            if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) return false;
            var c = s.modInverse(n);
            var u1 = e.multiply(c).mod(n);
            var u2 = r.multiply(c).mod(n);
            var point = G.multiply(u1).add(Q.multiply(u2));
            var v = point.getX().toBigInteger().mod(n);
            return v.equals(r);
        },
        serializeSig: function(r, s) {
            var rBa = r.toByteArraySigned();
            var sBa = s.toByteArraySigned();
            var sequence = [];
            sequence.push(2);
            sequence.push(rBa.length);
            sequence = sequence.concat(rBa);
            sequence.push(2);
            sequence.push(sBa.length);
            sequence = sequence.concat(sBa);
            sequence.unshift(sequence.length);
            sequence.unshift(48);
            return sequence;
        },
        parseSig: function(sig) {
            var cursor;
            if (sig[0] != 48) throw new Error("Signature not a valid DERSequence");
            cursor = 2;
            if (sig[cursor] != 2) throw new Error("First element in signature must be a DERInteger");
            var rBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);
            cursor += 2 + sig[cursor + 1];
            if (sig[cursor] != 2) throw new Error("Second element in signature must be a DERInteger");
            var sBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);
            cursor += 2 + sig[cursor + 1];
            var r = BigInteger.fromByteArrayUnsigned(rBa);
            var s = BigInteger.fromByteArrayUnsigned(sBa);
            return {
                r: r,
                s: s
            };
        },
        parseSigCompact: function(sig) {
            if (sig.length !== 65) {
                throw "Signature has the wrong length";
            }
            var i = sig[0] - 27;
            if (i < 0 || i > 7) {
                throw "Invalid signature type";
            }
            var n = ecparams.getN();
            var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
            var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);
            return {
                r: r,
                s: s,
                i: i
            };
        },
        recoverPubKey: function(r, s, hash, i) {
            i = i & 3;
            var isYEven = i & 1;
            var isSecondKey = i >> 1;
            var n = ecparams.getN();
            var G = ecparams.getG();
            var curve = ecparams.getCurve();
            var p = curve.getQ();
            var a = curve.getA().toBigInteger();
            var b = curve.getB().toBigInteger();
            if (!P_OVER_FOUR) {
                P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
            }
            var x = isSecondKey ? r.add(n) : r;
            var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
            var beta = alpha.modPow(P_OVER_FOUR, p);
            var xorOdd = beta.isEven() ? i % 2 : (i + 1) % 2;
            var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);
            var R = new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
            R.validate();
            var e = BigInteger.fromByteArrayUnsigned(hash);
            var eNeg = BigInteger.ZERO.subtract(e).mod(n);
            var rInv = r.modInverse(n);
            var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);
            Q.validate();
            if (!ECDSA.verifyRaw(e, r, s, Q)) {
                throw "Pubkey recovery unsuccessful";
            }
            var pubKey = new Bitcoin.ECKey();
            pubKey.pub = Q;
            return pubKey;
        },
        calcPubkeyRecoveryParam: function(address, r, s, hash) {
            for (var i = 0; i < 4; i++) {
                try {
                    var pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
                    if (pubkey.getAddress().toString() == address) {
                        return i;
                    }
                } catch (e) {}
            }
            throw "Unable to find valid recovery factor";
        }
    };
    return ECDSA;
}();

Bitcoin.ECKey = function() {
    var ECDSA = Bitcoin.ECDSA;
    var ecparams = getSECCurveByName("secp256k1");
    var rng = new SecureRandom();
    var ECKey = function(input) {
        if (!input) {
            var n = ecparams.getN();
            this.priv = ECDSA.getBigRandom(n);
        } else if (input instanceof BigInteger) {
            this.priv = input;
        } else if (Bitcoin.Util.isArray(input)) {
            this.priv = BigInteger.fromByteArrayUnsigned(input);
        } else if ("string" == typeof input) {
            var bytes = null;
            if (ECKey.isWalletImportFormat(input)) {
                bytes = ECKey.decodeWalletImportFormat(input);
            } else if (ECKey.isCompressedWalletImportFormat(input)) {
                bytes = ECKey.decodeCompressedWalletImportFormat(input);
                this.compressed = true;
            } else if (ECKey.isMiniFormat(input)) {
                bytes = Crypto.SHA256(input, {
                    asBytes: true
                });
            } else if (ECKey.isHexFormat(input)) {
                bytes = Crypto.util.hexToBytes(input);
            } else if (ECKey.isBase64Format(input)) {
                bytes = Crypto.util.base64ToBytes(input);
            }
            if (bytes == null || bytes.length != 32) {
                this.priv = null;
            } else {
                this.priv = BigInteger.fromByteArrayUnsigned(bytes);
            }
        }
        this.compressed = this.compressed == undefined ? !!ECKey.compressByDefault : this.compressed;
    };
    ECKey.privateKeyPrefix = 128;
    ECKey.compressByDefault = false;
    ECKey.prototype.setCompressed = function(v) {
        this.compressed = !!v;
        if (this.pubPoint) this.pubPoint.compressed = this.compressed;
        return this;
    };
    ECKey.prototype.getPub = function() {
        if (this.compressed) {
            if (this.pubComp) return this.pubComp;
            return this.pubComp = this.getPubPoint().getEncoded(1);
        } else {
            if (this.pubUncomp) return this.pubUncomp;
            return this.pubUncomp = this.getPubPoint().getEncoded(0);
        }
    };
    ECKey.prototype.getPubPoint = function() {
        if (!this.pubPoint) {
            this.pubPoint = ecparams.getG().multiply(this.priv);
            this.pubPoint.compressed = this.compressed;
        }
        return this.pubPoint;
    };
    ECKey.prototype.getPubKeyHex = function() {
        if (this.compressed) {
            if (this.pubKeyHexComp) return this.pubKeyHexComp;
            return this.pubKeyHexComp = Crypto.util.bytesToHex(this.getPub()).toString().toUpperCase();
        } else {
            if (this.pubKeyHexUncomp) return this.pubKeyHexUncomp;
            return this.pubKeyHexUncomp = Crypto.util.bytesToHex(this.getPub()).toString().toUpperCase();
        }
    };
    ECKey.prototype.getPubKeyHash = function() {
        if (this.compressed) {
            if (this.pubKeyHashComp) return this.pubKeyHashComp;
            return this.pubKeyHashComp = Bitcoin.Util.sha256ripe160(this.getPub());
        } else {
            if (this.pubKeyHashUncomp) return this.pubKeyHashUncomp;
            return this.pubKeyHashUncomp = Bitcoin.Util.sha256ripe160(this.getPub());
        }
    };
    ECKey.prototype.getAddress = function() {
        var hash = this.getPubKeyHash();
        var addr = new Bitcoin.Address(hash);
        return addr;
    };
    ECKey.prototype.setPub = function(pub) {
        if (Bitcoin.Util.isArray(pub)) {
            pub = Crypto.util.bytesToHex(pub).toString().toUpperCase();
        }
        var ecPoint = ecparams.getCurve().decodePointHex(pub);
        this.setCompressed(ecPoint.compressed);
        this.pubPoint = ecPoint;
        return this;
    };
    ECKey.prototype.getWalletImportFormat = function() {
        var bytes = this.getPrivateKeyByteArray();
        bytes.unshift(ECKey.privateKeyPrefix);
        if (this.compressed) bytes.push(1);
        var checksum = Bitcoin.Util.dsha256(bytes);
        bytes = bytes.concat(checksum.slice(0, 4));
        var privWif = Bitcoin.Base58.encode(bytes);
        return privWif;
    };
    ECKey.prototype.getEncryptedFormat = function(passphrase) {
        return Bitcoin.BIP38.encode(this, passphrase);
    };
    ECKey.prototype.getHexFormat = function() {
        return Crypto.util.bytesToHex(this.getPrivateKeyByteArray()).toString().toUpperCase();
    };
    ECKey.prototype.getBase64Format = function() {
        return Crypto.util.bytesToBase64(this.getPrivateKeyByteArray());
    };
    ECKey.prototype.getPrivateKeyByteArray = function() {
        var bytes = this.priv.toByteArrayUnsigned();
        while (bytes.length < 32) bytes.unshift(0);
        return bytes;
    };
    ECKey.prototype.toString = function(format) {
        format = format || "";
        if (format.toString().toLowerCase() == "base64" || format.toString().toLowerCase() == "b64") {
            return this.getBase64Format();
        } else if (format.toString().toLowerCase() == "wif") {
            return this.getWalletImportFormat();
        } else {
            return this.getHexFormat();
        }
    };
    ECKey.prototype.sign = function(hash) {
        return ECDSA.sign(hash, this.priv);
    };
    ECKey.prototype.verify = function(hash, sig) {
        return ECDSA.verify(hash, sig, this.getPub());
    };
    ECKey.decodeWalletImportFormat = function(privStr) {
        var bytes = Bitcoin.Base58.decode(privStr);
        var hash = bytes.slice(0, 33);
        var checksum = Bitcoin.Util.dsha256(hash);
        if (checksum[0] != bytes[33] || checksum[1] != bytes[34] || checksum[2] != bytes[35] || checksum[3] != bytes[36]) {
            throw "Checksum validation failed!";
        }
        var version = hash.shift();
        if (version != ECKey.privateKeyPrefix) {
            throw "Version " + version + " not supported!";
        }
        return hash;
    };
    ECKey.decodeCompressedWalletImportFormat = function(privStr) {
        var bytes = Bitcoin.Base58.decode(privStr);
        var hash = bytes.slice(0, 34);
        var checksum = Bitcoin.Util.dsha256(hash);
        if (checksum[0] != bytes[34] || checksum[1] != bytes[35] || checksum[2] != bytes[36] || checksum[3] != bytes[37]) {
            throw "Checksum validation failed!";
        }
        var version = hash.shift();
        if (version != ECKey.privateKeyPrefix) {
            throw "Version " + version + " not supported!";
        }
        hash.pop();
        return hash;
    };
    ECKey.decodeEncryptedFormat = function(base58Encrypted, passphrase) {
        return Bitcoin.BIP38.decode(base58Encrypted, passphrase);
    };
    ECKey.isHexFormat = function(key) {
        key = key.toString();
        return /^[A-Fa-f0-9]{64}$/.test(key);
    };
    ECKey.isWalletImportFormat = function(key) {
        key = key.toString();
        return ECKey.privateKeyPrefix == ECKey.privateKeyPrefix ? /^5[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$/.test(key) : /^9[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$/.test(key);
    };
    ECKey.isCompressedWalletImportFormat = function(key) {
        key = key.toString();
        return ECKey.privateKeyPrefix == ECKey.privateKeyPrefix ? /^[LK][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}$/.test(key) : /^c[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}$/.test(key);
    };
    ECKey.isBase64Format = function(key) {
        key = key.toString();
        return /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+\/]{44}$/.test(key);
    };
    ECKey.isMiniFormat = function(key) {
        key = key.toString();
        var validChars22 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{21}$/.test(key);
        var validChars26 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25}$/.test(key);
        var validChars30 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{29}$/.test(key);
        var testBytes = Crypto.SHA256(key + "?", {
            asBytes: true
        });
        return (testBytes[0] === 0 || testBytes[0] === 1) && (validChars22 || validChars26 || validChars30);
    };
    ECKey.isBIP38Format = function(string) {
        return Bitcoin.BIP38.isBIP38Format(string);
    };
    return ECKey;
}();

(function() {
    var Opcode = Bitcoin.Opcode = function(num) {
        this.code = num;
    };
    Opcode.prototype.toString = function() {
        return Opcode.reverseMap[this.code];
    };
    Opcode.map = {
        OP_0: 0,
        OP_FALSE: 0,
        OP_PUSHDATA1: 76,
        OP_PUSHDATA2: 77,
        OP_PUSHDATA4: 78,
        OP_1NEGATE: 79,
        OP_RESERVED: 80,
        OP_1: 81,
        OP_TRUE: 81,
        OP_2: 82,
        OP_3: 83,
        OP_4: 84,
        OP_5: 85,
        OP_6: 86,
        OP_7: 87,
        OP_8: 88,
        OP_9: 89,
        OP_10: 90,
        OP_11: 91,
        OP_12: 92,
        OP_13: 93,
        OP_14: 94,
        OP_15: 95,
        OP_16: 96,
        OP_NOP: 97,
        OP_VER: 98,
        OP_IF: 99,
        OP_NOTIF: 100,
        OP_VERIF: 101,
        OP_VERNOTIF: 102,
        OP_ELSE: 103,
        OP_ENDIF: 104,
        OP_VERIFY: 105,
        OP_RETURN: 106,
        OP_TOALTSTACK: 107,
        OP_FROMALTSTACK: 108,
        OP_2DROP: 109,
        OP_2DUP: 110,
        OP_3DUP: 111,
        OP_2OVER: 112,
        OP_2ROT: 113,
        OP_2SWAP: 114,
        OP_IFDUP: 115,
        OP_DEPTH: 116,
        OP_DROP: 117,
        OP_DUP: 118,
        OP_NIP: 119,
        OP_OVER: 120,
        OP_PICK: 121,
        OP_ROLL: 122,
        OP_ROT: 123,
        OP_SWAP: 124,
        OP_TUCK: 125,
        OP_CAT: 126,
        OP_SUBSTR: 127,
        OP_LEFT: 128,
        OP_RIGHT: 129,
        OP_SIZE: 130,
        OP_INVERT: 131,
        OP_AND: 132,
        OP_OR: 133,
        OP_XOR: 134,
        OP_EQUAL: 135,
        OP_EQUALVERIFY: 136,
        OP_RESERVED1: 137,
        OP_RESERVED2: 138,
        OP_1ADD: 139,
        OP_1SUB: 140,
        OP_2MUL: 141,
        OP_2DIV: 142,
        OP_NEGATE: 143,
        OP_ABS: 144,
        OP_NOT: 145,
        OP_0NOTEQUAL: 146,
        OP_ADD: 147,
        OP_SUB: 148,
        OP_MUL: 149,
        OP_DIV: 150,
        OP_MOD: 151,
        OP_LSHIFT: 152,
        OP_RSHIFT: 153,
        OP_BOOLAND: 154,
        OP_BOOLOR: 155,
        OP_NUMEQUAL: 156,
        OP_NUMEQUALVERIFY: 157,
        OP_NUMNOTEQUAL: 158,
        OP_LESSTHAN: 159,
        OP_GREATERTHAN: 160,
        OP_LESSTHANOREQUAL: 161,
        OP_GREATERTHANOREQUAL: 162,
        OP_MIN: 163,
        OP_MAX: 164,
        OP_WITHIN: 165,
        OP_RIPEMD160: 166,
        OP_SHA1: 167,
        OP_SHA256: 168,
        OP_HASH160: 169,
        OP_HASH256: 170,
        OP_CODESEPARATOR: 171,
        OP_CHECKSIG: 172,
        OP_CHECKSIGVERIFY: 173,
        OP_CHECKMULTISIG: 174,
        OP_CHECKMULTISIGVERIFY: 175,
        OP_NOP1: 176,
        OP_NOP2: 177,
        OP_NOP3: 178,
        OP_NOP4: 179,
        OP_NOP5: 180,
        OP_NOP6: 181,
        OP_NOP7: 182,
        OP_NOP8: 183,
        OP_NOP9: 184,
        OP_NOP10: 185,
        OP_PUBKEYHASH: 253,
        OP_PUBKEY: 254,
        OP_INVALIDOPCODE: 255
    };
    Opcode.reverseMap = [];
    for (var i in Opcode.map) {
        Opcode.reverseMap[Opcode.map[i]] = i;
    }
})();

(function() {
    var Opcode = Bitcoin.Opcode;
    for (var i in Opcode.map) {
        eval("var " + i + " = " + Opcode.map[i] + ";");
    }
    var Script = Bitcoin.Script = function(data) {
        if (!data) {
            this.buffer = [];
        } else if ("string" == typeof data) {
            this.buffer = Crypto.util.base64ToBytes(data);
        } else if (Bitcoin.Util.isArray(data)) {
            this.buffer = data;
        } else if (data instanceof Script) {
            this.buffer = data.buffer;
        } else {
            throw new Error("Invalid script");
        }
        this.parse();
    };
    Script.prototype.parse = function() {
        var self = this;
        this.chunks = [];
        var i = 0;
        function readChunk(n) {
            self.chunks.push(self.buffer.slice(i, i + n));
            i += n;
        }
        while (i < this.buffer.length) {
            var opcode = this.buffer[i++];
            if (opcode >= 240) {
                opcode = opcode << 8 | this.buffer[i++];
            }
            var len;
            if (opcode > 0 && opcode < OP_PUSHDATA1) {
                readChunk(opcode);
            } else if (opcode == OP_PUSHDATA1) {
                len = this.buffer[i++];
                readChunk(len);
            } else if (opcode == OP_PUSHDATA2) {
                len = this.buffer[i++] << 8 | this.buffer[i++];
                readChunk(len);
            } else if (opcode == OP_PUSHDATA4) {
                len = this.buffer[i++] << 24 | this.buffer[i++] << 16 | this.buffer[i++] << 8 | this.buffer[i++];
                readChunk(len);
            } else {
                this.chunks.push(opcode);
            }
        }
    };
    Script.prototype.getOutType = function() {
        if (this.chunks[this.chunks.length - 1] == OP_CHECKMULTISIG && this.chunks[this.chunks.length - 2] <= 3) {
            return "Multisig";
        } else if (this.chunks.length == 5 && this.chunks[0] == OP_DUP && this.chunks[1] == OP_HASH160 && this.chunks[3] == OP_EQUALVERIFY && this.chunks[4] == OP_CHECKSIG) {
            return "Address";
        } else if (this.chunks.length == 2 && this.chunks[1] == OP_CHECKSIG) {
            return "Pubkey";
        } else {
            return "Strange";
        }
    };
    Script.prototype.simpleOutHash = function() {
        switch (this.getOutType()) {
          case "Address":
            return this.chunks[2];

          case "Pubkey":
            return Bitcoin.Util.sha256ripe160(this.chunks[0]);

          default:
            throw new Error("Encountered non-standard scriptPubKey");
        }
    };
    Script.prototype.simpleOutPubKeyHash = Script.prototype.simpleOutHash;
    Script.prototype.getInType = function() {
        if (this.chunks.length == 1 && Bitcoin.Util.isArray(this.chunks[0])) {
            return "Pubkey";
        } else if (this.chunks.length == 2 && Bitcoin.Util.isArray(this.chunks[0]) && Bitcoin.Util.isArray(this.chunks[1])) {
            return "Address";
        } else {
            return "Strange";
        }
    };
    Script.prototype.simpleInPubKey = function() {
        switch (this.getInType()) {
          case "Address":
            return this.chunks[1];

          case "Pubkey":
            throw new Error("Script does not contain pubkey.");

          default:
            throw new Error("Encountered non-standard scriptSig");
        }
    };
    Script.prototype.simpleInHash = function() {
        return Bitcoin.Util.sha256ripe160(this.simpleInPubKey());
    };
    Script.prototype.simpleInPubKeyHash = Script.prototype.simpleInHash;
    Script.prototype.writeOp = function(opcode) {
        this.buffer.push(opcode);
        this.chunks.push(opcode);
    };
    Script.prototype.writeBytes = function(data) {
        if (data.length < OP_PUSHDATA1) {
            this.buffer.push(data.length);
        } else if (data.length <= 255) {
            this.buffer.push(OP_PUSHDATA1);
            this.buffer.push(data.length);
        } else if (data.length <= 65535) {
            this.buffer.push(OP_PUSHDATA2);
            this.buffer.push(data.length & 255);
            this.buffer.push(data.length >>> 8 & 255);
        } else {
            this.buffer.push(OP_PUSHDATA4);
            this.buffer.push(data.length & 255);
            this.buffer.push(data.length >>> 8 & 255);
            this.buffer.push(data.length >>> 16 & 255);
            this.buffer.push(data.length >>> 24 & 255);
        }
        this.buffer = this.buffer.concat(data);
        this.chunks.push(data);
    };
    Script.createOutputScript = function(address) {
        var script = new Script();
        script.writeOp(OP_DUP);
        script.writeOp(OP_HASH160);
        script.writeBytes(address.hash);
        script.writeOp(OP_EQUALVERIFY);
        script.writeOp(OP_CHECKSIG);
        return script;
    };
    Script.prototype.extractAddresses = function(addresses) {
        switch (this.getOutType()) {
          case "Address":
            addresses.push(new Address(this.chunks[2]));
            return 1;

          case "Pubkey":
            addresses.push(new Address(Util.sha256ripe160(this.chunks[0])));
            return 1;

          case "Multisig":
            for (var i = 1; i < this.chunks.length - 2; ++i) {
                addresses.push(new Address(Util.sha256ripe160(this.chunks[i])));
            }
            return this.chunks[0] - OP_1 + 1;

          default:
            throw new Error("Encountered non-standard scriptPubKey");
        }
    };
    Script.createMultiSigOutputScript = function(m, pubkeys) {
        var script = new Bitcoin.Script();
        script.writeOp(OP_1 + m - 1);
        for (var i = 0; i < pubkeys.length; ++i) {
            script.writeBytes(pubkeys[i]);
        }
        script.writeOp(OP_1 + pubkeys.length - 1);
        script.writeOp(OP_CHECKMULTISIG);
        return script;
    };
    Script.createInputScript = function(signature, pubKey) {
        var script = new Script();
        script.writeBytes(signature);
        script.writeBytes(pubKey);
        return script;
    };
    Script.prototype.clone = function() {
        return new Script(this.buffer);
    };
})();

(function() {
    var Script = Bitcoin.Script;
    var Transaction = Bitcoin.Transaction = function(doc) {
        this.version = 1;
        this.lock_time = 0;
        this.ins = [];
        this.outs = [];
        this.timestamp = null;
        this.block = null;
        if (doc) {
            if (doc.hash) this.hash = doc.hash;
            if (doc.version) this.version = doc.version;
            if (doc.lock_time) this.lock_time = doc.lock_time;
            if (doc.ins && doc.ins.length) {
                for (var i = 0; i < doc.ins.length; i++) {
                    this.addInput(new TransactionIn(doc.ins[i]));
                }
            }
            if (doc.outs && doc.outs.length) {
                for (var i = 0; i < doc.outs.length; i++) {
                    this.addOutput(new TransactionOut(doc.outs[i]));
                }
            }
            if (doc.timestamp) this.timestamp = doc.timestamp;
            if (doc.block) this.block = doc.block;
        }
    };
    Transaction.objectify = function(txs) {
        var objs = [];
        for (var i = 0; i < txs.length; i++) {
            objs.push(new Transaction(txs[i]));
        }
        return objs;
    };
    Transaction.prototype.addInput = function(tx, outIndex) {
        if (arguments[0] instanceof TransactionIn) {
            this.ins.push(arguments[0]);
        } else {
            this.ins.push(new TransactionIn({
                outpoint: {
                    hash: tx.hash,
                    index: outIndex
                },
                script: new Bitcoin.Script(),
                sequence: 4294967295
            }));
        }
    };
    Transaction.prototype.addOutput = function(address, value) {
        if (arguments[0] instanceof TransactionOut) {
            this.outs.push(arguments[0]);
        } else {
            if (value instanceof BigInteger) {
                value = value.toByteArrayUnsigned().reverse();
                while (value.length < 8) value.push(0);
            } else if (Bitcoin.Util.isArray(value)) {}
            this.outs.push(new TransactionOut({
                value: value,
                script: Script.createOutputScript(address)
            }));
        }
    };
    Transaction.prototype.serialize = function() {
        var buffer = [];
        buffer = buffer.concat(Crypto.util.wordsToBytes([ parseInt(this.version) ]).reverse());
        buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.ins.length));
        for (var i = 0; i < this.ins.length; i++) {
            var txin = this.ins[i];
            buffer = buffer.concat(Crypto.util.base64ToBytes(txin.outpoint.hash));
            buffer = buffer.concat(Crypto.util.wordsToBytes([ parseInt(txin.outpoint.index) ]).reverse());
            var scriptBytes = txin.script.buffer;
            buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
            buffer = buffer.concat(scriptBytes);
            buffer = buffer.concat(Crypto.util.wordsToBytes([ parseInt(txin.sequence) ]).reverse());
        }
        buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.outs.length));
        for (var i = 0; i < this.outs.length; i++) {
            var txout = this.outs[i];
            buffer = buffer.concat(txout.value);
            var scriptBytes = txout.script.buffer;
            buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
            buffer = buffer.concat(scriptBytes);
        }
        buffer = buffer.concat(Crypto.util.wordsToBytes([ parseInt(this.lock_time) ]).reverse());
        return buffer;
    };
    var OP_CODESEPARATOR = 171;
    var SIGHASH_ALL = 1;
    var SIGHASH_NONE = 2;
    var SIGHASH_SINGLE = 3;
    var SIGHASH_ANYONECANPAY = 80;
    Transaction.prototype.hashTransactionForSignature = function(connectedScript, inIndex, hashType) {
        var txTmp = this.clone();
        for (var i = 0; i < txTmp.ins.length; i++) {
            txTmp.ins[i].script = new Script();
        }
        txTmp.ins[inIndex].script = connectedScript;
        if ((hashType & 31) == SIGHASH_NONE) {
            txTmp.outs = [];
            for (var i = 0; i < txTmp.ins.length; i++) if (i != inIndex) txTmp.ins[i].sequence = 0;
        } else if ((hashType & 31) == SIGHASH_SINGLE) {}
        if (hashType & SIGHASH_ANYONECANPAY) {
            txTmp.ins = [ txTmp.ins[inIndex] ];
        }
        var buffer = txTmp.serialize();
        buffer = buffer.concat(Crypto.util.wordsToBytes([ parseInt(hashType) ]).reverse());
        var hash1 = Crypto.SHA256(buffer, {
            asBytes: true
        });
        return Crypto.SHA256(hash1, {
            asBytes: true
        });
    };
    Transaction.prototype.getHash = function() {
        var buffer = this.serialize();
        return Crypto.SHA256(Crypto.SHA256(buffer, {
            asBytes: true
        }), {
            asBytes: true
        });
    };
    Transaction.prototype.clone = function() {
        var newTx = new Transaction();
        newTx.version = this.version;
        newTx.lock_time = this.lock_time;
        for (var i = 0; i < this.ins.length; i++) {
            var txin = this.ins[i].clone();
            newTx.addInput(txin);
        }
        for (var i = 0; i < this.outs.length; i++) {
            var txout = this.outs[i].clone();
            newTx.addOutput(txout);
        }
        return newTx;
    };
    Transaction.prototype.analyze = function(wallet) {
        if (!(wallet instanceof Bitcoin.Wallet)) return null;
        var allFromMe = true, allToMe = true, firstRecvHash = null, firstMeRecvHash = null, firstSendHash = null;
        for (var i = this.outs.length - 1; i >= 0; i--) {
            var txout = this.outs[i];
            var hash = txout.script.simpleOutPubKeyHash();
            if (!wallet.hasHash(hash)) {
                allToMe = false;
            } else {
                firstMeRecvHash = hash;
            }
            firstRecvHash = hash;
        }
        for (var i = this.ins.length - 1; i >= 0; i--) {
            var txin = this.ins[i];
            firstSendHash = txin.script.simpleInPubKeyHash();
            if (!wallet.hasHash(firstSendHash)) {
                allFromMe = false;
                break;
            }
        }
        var impact = this.calcImpact(wallet);
        var analysis = {};
        analysis.impact = impact;
        if (impact.sign > 0 && impact.value.compareTo(BigInteger.ZERO) > 0) {
            analysis.type = "recv";
            analysis.addr = new Bitcoin.Address(firstMeRecvHash);
        } else if (allFromMe && allToMe) {
            analysis.type = "self";
        } else if (allFromMe) {
            analysis.type = "sent";
            analysis.addr = new Bitcoin.Address(firstRecvHash);
        } else {
            analysis.type = "other";
        }
        return analysis;
    };
    Transaction.prototype.getDescription = function(wallet) {
        var analysis = this.analyze(wallet);
        if (!analysis) return "";
        switch (analysis.type) {
          case "recv":
            return "Received with " + analysis.addr;
            break;

          case "sent":
            return "Payment to " + analysis.addr;
            break;

          case "self":
            return "Payment to yourself";
            break;

          case "other":
          default:
            return "";
        }
    };
    Transaction.prototype.getTotalOutValue = function() {
        var totalValue = BigInteger.ZERO;
        for (var j = 0; j < this.outs.length; j++) {
            var txout = this.outs[j];
            totalValue = totalValue.add(Bitcoin.Util.valueToBigInt(txout.value));
        }
        return totalValue;
    };
    Transaction.prototype.getTotalValue = Transaction.prototype.getTotalOutValue;
    Transaction.prototype.calcImpact = function(wallet) {
        if (!(wallet instanceof Bitcoin.Wallet)) return BigInteger.ZERO;
        var valueOut = BigInteger.ZERO;
        for (var j = 0; j < this.outs.length; j++) {
            var txout = this.outs[j];
            var hash = Crypto.util.bytesToBase64(txout.script.simpleOutPubKeyHash());
            if (wallet.hasHash(hash)) {
                valueOut = valueOut.add(Bitcoin.Util.valueToBigInt(txout.value));
            }
        }
        var valueIn = BigInteger.ZERO;
        for (var j = 0; j < this.ins.length; j++) {
            var txin = this.ins[j];
            var hash = Crypto.util.bytesToBase64(txin.script.simpleInPubKeyHash());
            if (wallet.hasHash(hash)) {
                var fromTx = wallet.txIndex[txin.outpoint.hash];
                if (fromTx) {
                    valueIn = valueIn.add(Bitcoin.Util.valueToBigInt(fromTx.outs[txin.outpoint.index].value));
                }
            }
        }
        if (valueOut.compareTo(valueIn) >= 0) {
            return {
                sign: 1,
                value: valueOut.subtract(valueIn)
            };
        } else {
            return {
                sign: -1,
                value: valueIn.subtract(valueOut)
            };
        }
    };
    var TransactionIn = Bitcoin.TransactionIn = function(data) {
        this.outpoint = data.outpoint;
        if (data.script instanceof Script) {
            this.script = data.script;
        } else {
            this.script = new Script(data.script);
        }
        this.sequence = data.sequence;
    };
    TransactionIn.prototype.clone = function() {
        var newTxin = new TransactionIn({
            outpoint: {
                hash: this.outpoint.hash,
                index: this.outpoint.index
            },
            script: this.script.clone(),
            sequence: this.sequence
        });
        return newTxin;
    };
    var TransactionOut = Bitcoin.TransactionOut = function(data) {
        if (data.script instanceof Script) {
            this.script = data.script;
        } else {
            this.script = new Script(data.script);
        }
        if (Bitcoin.Util.isArray(data.value)) {
            this.value = data.value;
        } else if ("string" == typeof data.value) {
            var valueHex = new BigInteger(data.value, 10).toString(16);
            while (valueHex.length < 16) valueHex = "0" + valueHex;
            this.value = Crypto.util.hexToBytes(valueHex);
        }
    };
    TransactionOut.prototype.clone = function() {
        var newTxout = new TransactionOut({
            script: this.script.clone(),
            value: this.value.slice(0)
        });
        return newTxout;
    };
})();

Bitcoin.BIP38 = function() {
    var BIP38 = function() {};
    var ecparams = getSECCurveByName("secp256k1");
    var rng = new SecureRandom();
    var scryptParams = {
        passphrase: {
            N: 16384,
            r: 8,
            p: 8
        },
        passpoint: {
            N: 1024,
            r: 1,
            p: 1
        }
    };
    var AES_opts = {
        mode: new Crypto.mode.ECB(Crypto.pad.NoPadding),
        asBytes: true
    };
    BIP38.encode = function(eckey, passphrase) {
        var privKeyBytes = eckey.getPrivateKeyByteArray();
        var address = eckey.getAddress().toString();
        var salt = Bitcoin.Util.dsha256(address).slice(0, 4);
        var derivedBytes = scrypt(passphrase, salt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 64);
        for (var i = 0; i < 32; ++i) {
            privKeyBytes[i] ^= derivedBytes[i];
        }
        var flagByte = eckey.compressed ? 224 : 192;
        var encryptedKey = [ 1, 66, flagByte ].concat(salt);
        var encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), AES_opts));
        encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0, 4));
        return Bitcoin.Base58.encode(encryptedKey);
    };
    BIP38.decode = function(base58Encrypted, passphrase) {
        var hex;
        try {
            hex = Bitcoin.Base58.decode(base58Encrypted);
        } catch (e) {
            throw new Error("Invalid BIP38-encrypted private key. Unable to decode base58.");
        }
        if (hex.length != 43) {
            throw new Error("Invalid BIP38-encrypted private key. Length of key in hex format is not 43 characters in length.");
        } else if (hex[0] != 1) {
            throw new Error("Invalid BIP38-encrypted private key. First byte is not 0x01.");
        }
        var expChecksum = hex.slice(-4);
        hex = hex.slice(0, -4);
        var checksum = Bitcoin.Util.dsha256(hex);
        if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
            throw new Error("Invalid BIP38-encrypted private key. Checksum failed.");
        }
        var isCompPoint = false;
        var isECMult = false;
        var hasLotSeq = false;
        if (hex[1] == 66) {
            if (hex[2] == 224) {
                isCompPoint = true;
            } else if (hex[2] != 192) {
                throw new Error("Invalid BIP38-encrypted private key. Second byte should be 0xc0.");
            }
        } else if (hex[1] == 67) {
            isECMult = true;
            isCompPoint = (hex[2] & 32) != 0;
            hasLotSeq = (hex[2] & 4) != 0;
            if ((hex[2] & 36) != hex[2]) {
                throw new Error("Invalid BIP38-encrypted private key. Unknown validation error.");
            }
        } else {
            throw new Error("Invalid BIP38-encrypted private key. Unknown validation error.");
        }
        var decrypted;
        var verifyHashAndReturn = function() {
            var tmpkey = new Bitcoin.ECKey(decrypted);
            tmpkey.setCompressed(isCompPoint);
            var address = tmpkey.getAddress();
            checksum = Bitcoin.Util.dsha256(address.toString());
            if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
                throw new Error("Invalid BIP38-encrypted private key. Hash could not be verified.");
            }
            return tmpkey;
        };
        if (!isECMult) {
            var addresshash = hex.slice(3, 7);
            var derivedBytes = scrypt(passphrase, addresshash, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 64);
            var k = derivedBytes.slice(32, 32 + 32);
            decrypted = Crypto.AES.decrypt(hex.slice(7, 7 + 32), k, AES_opts);
            for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
            return verifyHashAndReturn();
        } else {
            var ownerentropy = hex.slice(7, 7 + 8);
            var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
            var prefactorA = scrypt(passphrase, ownersalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);
            var passfactor;
            if (!hasLotSeq) {
                passfactor = prefactorA;
            } else {
                var prefactorB = prefactorA.concat(ownerentropy);
                passfactor = Bitcoin.Util.dsha256(prefactorB);
            }
            var kp = new Bitcoin.ECKey(passfactor);
            kp.compressed = true;
            var passpoint = kp.getPub();
            var encryptedPart2 = hex.slice(23, 23 + 16);
            var addressHashPlusOnwerEntropy = hex.slice(3, 3 + 12);
            var derived = scrypt(passpoint, addressHashPlusOnwerEntropy, scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);
            var k = derived.slice(32);
            var unencryptedPart2 = Crypto.AES.decrypt(encryptedPart2, k, AES_opts);
            for (var i = 0; i < 16; i++) {
                unencryptedPart2[i] ^= derived[i + 16];
            }
            var encryptedpart1 = hex.slice(15, 15 + 8).concat(unencryptedPart2.slice(0, 0 + 8));
            var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
            for (var i = 0; i < 16; i++) {
                unencryptedpart1[i] ^= derived[i];
            }
            var seedb = unencryptedpart1.slice(0, 0 + 16).concat(unencryptedPart2.slice(8, 8 + 8));
            var factorb = Bitcoin.Util.dsha256(seedb);
            var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ecparams.getN());
            decrypted = privateKey.toByteArrayUnsigned();
            return verifyHashAndReturn();
        }
    };
    BIP38.generateIntermediate = function(passphrase, lotNum, sequenceNum) {
        var noNumbers = lotNum == null || sequenceNum == null;
        var ownerEntropy, ownerSalt;
        if (noNumbers) {
            ownerSalt = ownerEntropy = new Array(8);
            rng.nextBytes(ownerEntropy);
        } else {
            var ownerSalt = Array(4);
            rng.nextBytes(ownerSalt);
            var lotSequence = nbv(4096 * lotNum + sequenceNum).toByteArrayUnsigned();
            var ownerEntropy = ownerSalt.concat(lotSequence);
        }
        var prefactor = scrypt(passphrase, ownerSalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);
        var passfactorBytes = noNumbers ? prefactor : Bitcoin.Util.dsha256(prefactor.concat(ownerEntropy));
        var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);
        var passpoint = ecparams.getG().multiply(passfactor).getEncoded(1);
        var magicBytes = [ 44, 233, 179, 225, 255, 57, 226, 81 ];
        if (noNumbers) magicBytes[7] = 83;
        var intermediatePreChecksum = magicBytes.concat(ownerEntropy).concat(passpoint);
        var intermediateBytes = intermediatePreChecksum.concat(Bitcoin.Util.dsha256(intermediatePreChecksum).slice(0, 4));
        var intermediate = Bitcoin.Base58.encode(intermediateBytes);
        return intermediate;
    };
    BIP38.newAddressFromIntermediate = function(intermediate, compressed) {
        var intermediateBytes = Bitcoin.Base58.decode(intermediate);
        var expectedChecksum = intermediateBytes.slice(49, 53);
        var checksum = Bitcoin.Util.dsha256(intermediateBytes.slice(0, 49)).slice(0, 4);
        if (expectedChecksum[0] != checksum[0] || expectedChecksum[1] != checksum[1] || expectedChecksum[2] != checksum[2] || expectedChecksum[3] != checksum[3]) {
            throw new Error("Invalid intermediate passphrase string");
        }
        var noNumbers = intermediateBytes[7] === 83;
        var ownerEntropy = intermediateBytes.slice(8, 8 + 8);
        var passpoint = intermediateBytes.slice(16, 16 + 33);
        var flagByte = (compressed ? 32 : 0) | (noNumbers ? 0 : 4);
        var seedB = new Array(24);
        rng.nextBytes(seedB);
        var factorB = Bitcoin.Util.dsha256(seedB);
        var ec = ecparams.getCurve();
        var generatedPoint = ec.decodePointHex(Crypto.util.bytesToHex(passpoint));
        var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(compressed);
        var generatedAddress = new Bitcoin.Address(Bitcoin.Util.sha256ripe160(generatedBytes));
        var addressHash = Bitcoin.Util.dsha256(generatedAddress.toString()).slice(0, 4);
        var derivedBytes = scrypt(passpoint, addressHash.concat(ownerEntropy), scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);
        for (var i = 0; i < 16; ++i) {
            seedB[i] ^= derivedBytes[i];
        }
        var encryptedPart1 = Crypto.AES.encrypt(seedB.slice(0, 16), derivedBytes.slice(32), AES_opts);
        var message2 = encryptedPart1.slice(8, 8 + 8).concat(seedB.slice(16, 16 + 8));
        for (var i = 0; i < 16; ++i) {
            message2[i] ^= derivedBytes[i + 16];
        }
        var encryptedSeedB = Crypto.AES.encrypt(message2, derivedBytes.slice(32), AES_opts);
        var encryptedKey = [ 1, 67, flagByte ].concat(addressHash).concat(ownerEntropy).concat(encryptedPart1.slice(0, 8)).concat(encryptedSeedB);
        encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0, 4));
        var confirmation = newAddressConfirmation(addressHash, factorB, derivedBytes, flagByte, ownerEntropy);
        return {
            address: generatedAddress,
            bip38PrivateKey: Bitcoin.Base58.encode(encryptedKey),
            confirmation: confirmation
        };
    };
    var newAddressConfirmation = function(addressHash, factorB, derivedBytes, flagByte, ownerEntropy) {
        var pointb = ecparams.getG().multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(1);
        var pointbprefix = pointb[0] ^ derivedBytes[63] & 1;
        for (var i = 0; i < 16; ++i) {
            pointb[i + 1] ^= derivedBytes[i];
        }
        var pointbx1 = Crypto.AES.encrypt(pointb.slice(1, 17), derivedBytes.slice(32), AES_opts);
        for (var i = 16; i < 32; ++i) {
            pointb[i + 1] ^= derivedBytes[i];
        }
        var pointbx2 = Crypto.AES.encrypt(pointb.slice(17, 33), derivedBytes.slice(32), AES_opts);
        var encryptedpointb = [ pointbprefix ].concat(pointbx1).concat(pointbx2);
        var confirmationPreChecksum = [ 100, 59, 246, 168, 154, flagByte ].concat(addressHash).concat(ownerEntropy).concat(encryptedpointb);
        var confirmationBytes = confirmationPreChecksum.concat(Bitcoin.Util.dsha256(confirmationPreChecksum).slice(0, 4));
        var confirmation = Bitcoin.Base58.encode(confirmationBytes);
        return confirmation;
    };
    BIP38.verifyNewAddressConfirmation = function(expectedAddressStr, confirmation, passphrase) {
        var confirmationResults = BIP38.verifyConfirmation(confirmation, passphrase);
        return confirmationResults.address == expectedAddressStr;
    };
    BIP38.verifyConfirmation = function(confirmation, passphrase) {
        var bytes = Bitcoin.Base58.decode(confirmation);
        var flagByte = bytes[5];
        var addressHash = bytes.slice(6, 10);
        var ownerEntropy = bytes.slice(10, 18);
        var encryptedpointb = bytes.slice(18, 51);
        var compressed = (flagByte & 32) == 32;
        var lotSequencePresent = (flagByte & 4) == 4;
        var ownerSalt = ownerEntropy.slice(0, lotSequencePresent ? 4 : 8);
        var prefactor = scrypt(passphrase, ownerSalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);
        var passfactorBytes = !lotSequencePresent ? prefactor : Bitcoin.Util.dsha256(prefactor.concat(ownerEntropy));
        var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);
        var passpoint = ecparams.getG().multiply(passfactor).getEncoded(1);
        var addresshashplusownerentropy = addressHash.concat(ownerEntropy);
        var derivedBytes = scrypt(passpoint, addresshashplusownerentropy, scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);
        var unencryptedpubkey = [];
        unencryptedpubkey[0] = encryptedpointb[0] ^ derivedBytes[63] & 1;
        decrypted1 = Crypto.AES.decrypt(encryptedpointb.slice(1, 17), derivedBytes.slice(32), AES_opts);
        decrypted2 = Crypto.AES.decrypt(encryptedpointb.slice(17, 33), derivedBytes.slice(32), AES_opts);
        decrypted = unencryptedpubkey.concat(decrypted1).concat(decrypted2);
        for (var x = 0; x < 32; x++) {
            decrypted[x + 1] ^= derivedBytes[x];
        }
        var ec = ecparams.getCurve();
        var generatedPoint = ec.decodePointHex(Crypto.util.bytesToHex(decrypted).toString().toUpperCase());
        var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(passfactor)).getEncoded(compressed);
        var generatedAddress = new Bitcoin.Address(Bitcoin.Util.sha256ripe160(generatedBytes)).toString();
        var generatedAddressHash = Bitcoin.Util.dsha256(generatedAddress).slice(0, 4);
        var valid = true;
        for (var i = 0; i < 4; i++) {
            if (addressHash[i] != generatedAddressHash[i]) {
                valid = false;
            }
        }
        return {
            valid: valid,
            address: generatedAddress
        };
    };
    BIP38.isBIP38Format = function(string) {
        return /^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(string);
    };
    return BIP38;
}();

Bitcoin.Wallet = function() {
    var Script = Bitcoin.Script, TransactionIn = Bitcoin.TransactionIn, TransactionOut = Bitcoin.TransactionOut;
    var Wallet = function() {
        var keys = [];
        this.addressHashes = [];
        this.txIndex = {};
        this.unspentOuts = [];
        this.addressPointer = 0;
        this.addKey = function(key, pub) {
            if (!(key instanceof Bitcoin.ECKey)) {
                key = new Bitcoin.ECKey(key);
            }
            keys.push(key);
            if (pub) {
                if ("string" === typeof pub) {
                    pub = Crypto.util.base64ToBytes(pub);
                }
                key.setPub(pub);
            }
            this.addressHashes.push(key.getAddress().getHashBase64());
        };
        this.addKeys = function(keys, pubs) {
            if ("string" === typeof keys) {
                keys = keys.split(",");
            }
            if ("string" === typeof pubs) {
                pubs = pubs.split(",");
            }
            var i;
            if (Array.isArray(pubs) && keys.length == pubs.length) {
                for (i = 0; i < keys.length; i++) {
                    this.addKey(keys[i], pubs[i]);
                }
            } else {
                for (i = 0; i < keys.length; i++) {
                    this.addKey(keys[i]);
                }
            }
        };
        this.getKeys = function() {
            var serializedWallet = [];
            for (var i = 0; i < keys.length; i++) {
                serializedWallet.push(keys[i].toString("base64"));
            }
            return serializedWallet;
        };
        this.getPubKeys = function() {
            var pubs = [];
            for (var i = 0; i < keys.length; i++) {
                pubs.push(Crypto.util.bytesToBase64(keys[i].getPub()));
            }
            return pubs;
        };
        this.clear = function() {
            keys = [];
        };
        this.getLength = function() {
            return keys.length;
        };
        this.getAllAddresses = function() {
            var addresses = [];
            for (var i = 0; i < keys.length; i++) {
                addresses.push(keys[i].getAddress());
            }
            return addresses;
        };
        this.getCurAddress = function() {
            if (keys[this.addressPointer]) {
                return keys[this.addressPointer].getAddress();
            } else {
                return null;
            }
        };
        this.getNextAddress = function() {
            this.addressPointer++;
            if (!keys[this.addressPointer]) {
                this.generateAddress();
            }
            return keys[this.addressPointer].getAddress();
        };
        this.signWithKey = function(pubKeyHash, hash) {
            pubKeyHash = Crypto.util.bytesToBase64(pubKeyHash);
            for (var i = 0; i < this.addressHashes.length; i++) {
                if (this.addressHashes[i] == pubKeyHash) {
                    return keys[i].sign(hash);
                }
            }
            throw new Error("Missing key for signature");
        };
        this.getPubKeyFromHash = function(pubKeyHash) {
            pubKeyHash = Crypto.util.bytesToBase64(pubKeyHash);
            for (var i = 0; i < this.addressHashes.length; i++) {
                if (this.addressHashes[i] == pubKeyHash) {
                    return keys[i].getPub();
                }
            }
            throw new Error("Hash unknown");
        };
    };
    Wallet.prototype.generateAddress = function() {
        this.addKey(new Bitcoin.ECKey());
    };
    Wallet.prototype.process = function(tx) {
        if (this.txIndex[tx.hash]) return;
        var j;
        var k;
        var hash;
        for (j = 0; j < tx.outs.length; j++) {
            var txout = new TransactionOut(tx.outs[j]);
            hash = Crypto.util.bytesToBase64(txout.script.simpleOutPubKeyHash());
            for (k = 0; k < this.addressHashes.length; k++) {
                if (this.addressHashes[k] === hash) {
                    this.unspentOuts.push({
                        tx: tx,
                        index: j,
                        out: txout
                    });
                    break;
                }
            }
        }
        for (j = 0; j < tx.ins.length; j++) {
            var txin = new TransactionIn(tx.ins[j]);
            var pubkey = txin.script.simpleInPubKey();
            hash = Crypto.util.bytesToBase64(Bitcoin.Util.sha256ripe160(pubkey));
            for (k = 0; k < this.addressHashes.length; k++) {
                if (this.addressHashes[k] === hash) {
                    for (var l = 0; l < this.unspentOuts.length; l++) {
                        if (txin.outpoint.hash == this.unspentOuts[l].tx.hash && txin.outpoint.index == this.unspentOuts[l].index) {
                            this.unspentOuts.splice(l, 1);
                        }
                    }
                    break;
                }
            }
        }
        this.txIndex[tx.hash] = tx;
    };
    Wallet.prototype.getBalance = function() {
        var balance = BigInteger.valueOf(0);
        for (var i = 0; i < this.unspentOuts.length; i++) {
            var txout = this.unspentOuts[i].out;
            balance = balance.add(Bitcoin.Util.valueToBigInt(txout.value));
        }
        return balance;
    };
    Wallet.prototype.createSend = function(address, sendValue, feeValue) {
        var selectedOuts = [];
        var txValue = sendValue.add(feeValue);
        var availableValue = BigInteger.ZERO;
        var i;
        for (i = 0; i < this.unspentOuts.length; i++) {
            selectedOuts.push(this.unspentOuts[i]);
            availableValue = availableValue.add(Bitcoin.Util.valueToBigInt(this.unspentOuts[i].out.value));
            if (availableValue.compareTo(txValue) >= 0) break;
        }
        if (availableValue.compareTo(txValue) < 0) {
            throw new Error("Insufficient funds.");
        }
        var changeValue = availableValue.subtract(txValue);
        var sendTx = new Bitcoin.Transaction();
        for (i = 0; i < selectedOuts.length; i++) {
            sendTx.addInput(selectedOuts[i].tx, selectedOuts[i].index);
        }
        sendTx.addOutput(address, sendValue);
        if (changeValue.compareTo(BigInteger.ZERO) > 0) {
            sendTx.addOutput(this.getNextAddress(), changeValue);
        }
        var hashType = 1;
        for (i = 0; i < sendTx.ins.length; i++) {
            var hash = sendTx.hashTransactionForSignature(selectedOuts[i].out.script, i, hashType);
            var pubKeyHash = selectedOuts[i].out.script.simpleOutPubKeyHash();
            var signature = this.signWithKey(pubKeyHash, hash);
            signature.push(parseInt(hashType, 10));
            sendTx.ins[i].script = Script.createInputScript(signature, this.getPubKeyFromHash(pubKeyHash));
        }
        return sendTx;
    };
    Wallet.prototype.clearTransactions = function() {
        this.txIndex = {};
        this.unspentOuts = [];
    };
    Wallet.prototype.hasHash = function(hash) {
        if (Bitcoin.Util.isArray(hash)) hash = Crypto.util.bytesToBase64(hash);
        for (var k = 0; k < this.addressHashes.length; k++) {
            if (this.addressHashes[k] === hash) return true;
        }
        return false;
    };
    return Wallet;
}();

var TransactionDatabase = function() {
    this.txs = [];
    this.txIndex = {};
};

EventEmitter.augment(TransactionDatabase.prototype);

TransactionDatabase.prototype.addTransaction = function(tx) {
    this.addTransactionNoUpdate(tx);
    $(this).trigger("update");
};

TransactionDatabase.prototype.addTransactionNoUpdate = function(tx) {
    if (this.txIndex[tx.hash]) {
        return;
    }
    this.txs.push(new Bitcoin.Transaction(tx));
    this.txIndex[tx.hash] = tx;
};

TransactionDatabase.prototype.removeTransaction = function(hash) {
    this.removeTransactionNoUpdate(hash);
    $(this).trigger("update");
};

TransactionDatabase.prototype.removeTransactionNoUpdate = function(hash) {
    var tx = this.txIndex[hash];
    if (!tx) {
        return;
    }
    for (var i = 0, l = this.txs.length; i < l; i++) {
        if (this.txs[i].hash == hash) {
            this.txs.splice(i, 1);
            break;
        }
    }
    delete this.txIndex[hash];
};

TransactionDatabase.prototype.loadTransactions = function(txs) {
    for (var i = 0; i < txs.length; i++) {
        this.addTransactionNoUpdate(txs[i]);
    }
    $(this).trigger("update");
};

TransactionDatabase.prototype.getTransactions = function() {
    return this.txs;
};

TransactionDatabase.prototype.clear = function() {
    this.txs = [];
    this.txIndex = {};
    $(this).trigger("update");
};