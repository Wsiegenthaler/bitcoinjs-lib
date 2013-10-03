Bitcoin.BIP38 = (function () {

  var BIP38 = function() {};

  var ecparams = getSECCurveByName("secp256k1");
  var rng = new SecureRandom();
  var AES_opts = {mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true};


  /**
   * Default parameters for scrypt key derivation
   *  -> N: cpu cost
   *  -> r: memory cost
   *  -> p: parallelization cost
   */
  BIP38.scryptParams = { N: 16384, r: 8, p: 8 };



  /**
   * Private key encoded per BIP-38 (password encrypted, checksum,  base58)
   * @author scintill
   */
  BIP38.encode = function (eckey, passphrase) {
    var privKeyBytes = eckey.getPrivateKeyByteArray();
    var address = eckey.getAddress().toString();
  
    // compute sha256(sha256(address)) and take first 4 bytes
    var salt = Bitcoin.Util.dsha256(address).slice(0, 4);
  
    // derive key using scrypt
    var derivedBytes = scrypt(passphrase, salt, BIP38.scryptParams.N, BIP38.scryptParams.r, BIP38.scryptParams.p, 64);
    for(var i = 0; i < 32; ++i) {
      privKeyBytes[i] ^= derivedBytes[i];
    }
  
    // 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
    var flagByte = eckey.compressed ? 0xe0 : 0xc0;
    var encryptedKey = [ 0x01, 0x42, flagByte ].concat(salt);

    var encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), AES_opts));
  
    encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0,4));

    return Bitcoin.Base58.encode(encryptedKey);
  }

  /**
   * Parse a wallet import format private key contained in a string.
   * @author scintill
   */
  BIP38.decode = function (base58Encrypted, passphrase) {
    var hex;
    try {
      hex = Bitcoin.Base58.decode(base58Encrypted);
    } catch (e) {
      throw new Error("Invalid BIP38-encrypted private key. Unable to decode base58.");
    }
  
    if (hex.length != 43) {
      throw new Error("Invalid BIP38-encrypted private key. Length of key in hex format is not 43 characters in length.");
    } else if (hex[0] != 0x01) {
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
    if (hex[1] == 0x42) {
      if (hex[2] == 0xe0) {
        isCompPoint = true;
      } else if (hex[2] != 0xc0) {
        throw new Error("Invalid BIP38-encrypted private key. Second byte should be 0xc0.");
      }
    } else if (hex[1] == 0x43) {
      isECMult = true;
      isCompPoint = (hex[2] & 0x20) != 0;
      hasLotSeq = (hex[2] & 0x04) != 0;
      if ((hex[2] & 0x24) != hex[2]) {
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
      var derivedBytes = scrypt(passphrase, addresshash, BIP38.scryptParams.N, BIP38.scryptParams.r, BIP38.scryptParams.p, 64);
      var k = derivedBytes.slice(32, 32+32);
      decrypted = Crypto.AES.decrypt(hex.slice(7, 7+32), k, AES_opts);
      for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
      return verifyHashAndReturn();
    } else {
      var ownerentropy = hex.slice(7, 7+8);
      var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
      var prefactorA = scrypt(passphrase, ownersalt, BIP38.scryptParams.N, BIP38.scryptParams.r, BIP38.scryptParams.p, 32);
      var passfactor;
      if (!hasLotSeq) {
        passfactor = prefactorA;
      } else {
        var prefactorB = prefactorA.concat(ownerentropy);
        passfactor = Bitcoin.Util.dsha256(prefactorB);
      }
      var kp = new Bitcoin.ECKey(passfactor);
      var passpoint = kp.getPubCompressed();
  
      var encryptedPart2 = hex.slice(23, 23+16);
  
      var addressHashPlusOnwerEntropy = hex.slice(3, 3+12);
      var derived = scrypt(passpoint, addressHashPlusOnwerEntropy, 1024, 1, 1, 64);
      var k = derived.slice(32);
  
      var unencryptedPart2 = Crypto.AES.decrypt(encryptedPart2, k, AES_opts);
      for (var i = 0; i < 16; i++) { unencryptedPart2[i] ^= derived[i+16]; }
  
      var encryptedpart1 = hex.slice(15, 15+8).concat(unencryptedPart2.slice(0, 0+8));
      var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
      for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }
  
      var seedb = unencryptedpart1.slice(0, 0+16).concat(unencryptedPart2.slice(8, 8+8));
  
      var factorb = Bitcoin.Util.dsha256(seedb);
  
      var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ecparams.getN());
  
      decrypted = privateKey.toByteArrayUnsigned();
      return verifyHashAndReturn();
    }
  }

  /**
   * Detects keys encrypted according to BIP-38 (58 base58 characters starting with 6P)
   */
  BIP38.isBIP38Format = function (string) {
    return (/^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(string));
  };


  return BIP38;

})();

