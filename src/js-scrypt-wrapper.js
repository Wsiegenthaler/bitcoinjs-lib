

var MAX_VALUE = 2147483647;
var SCRYPT_ALLOC = Math.pow(2, 25); //default 2^25=32mb

var scrypt_module = scrypt_module_factory(SCRYPT_ALLOC);

/*
 * N = Cpu cost
 * r = Memory cost
 * p = parallelization cost
 *
 */
function scrypt(passwd, salt, N, r, p, dkLen) {
  if (N == 0 || (N & (N - 1)) != 0) throw Error("N must be > 0 and a power of 2");

  if (N > MAX_VALUE / 128 / r) throw Error("Parameter N is too large");
  if (r > MAX_VALUE / 128 / p) throw Error("Parameter r is too large");

  // Handle strings
  if (passwd.constructor == String) passwd = scrypt_module.encode_utf8(passwd);
  if (salt.constructor == String) salt = scrypt_module.encode_utf8(salt);

  // Convert to Uint8Arrays
  passwd = new Uint8Array(passwd);
  salt = new Uint8Array(salt);
   
  // Execute scrypt 
  var result = scrypt_module.crypto_scrypt(passwd, salt, N, r, p, dkLen);
  var resultBytes = [];
  for (var i=0; i<result.length; i++) {
    resultBytes[i] = result[i];
  }

  return resultBytes;
}
