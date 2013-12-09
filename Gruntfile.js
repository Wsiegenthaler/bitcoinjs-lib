module.exports = function(grunt) {

  // load all grunt tasks
  require('matchdep').filterDev('grunt-*').forEach(grunt.loadNpmTasks);

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    uglify: {
      options: {
        beautify: true, compress: false, indent_level: 2, comments: true,
        //beautify: false, compress: true,
        mangle: false,
        banner:
          "/**\n" +
          " * BitcoinJS-lib v<%= pkg.version %>-default\n" +
          " * Copyright (c) 2011 BitcoinJS Project\n" +
          " * \n" +
          " * This program is free software; you can redistribute it and/or modify\n" +
          " * it under the terms of the MIT license.\n" +
          " */\n\n"
      },
      my_target: {
        files: {
          'build/bitcoinjs-exit-min.js': [
            'src/exit/client.js'
          ],
          'build/bitcoinjs-min.js': [
            'src/crypto-js/src/Crypto.js',
            'src/crypto-js/src/CryptoMath.js',
            'src/crypto-js/src/BlockModes.js',
            'src/crypto-js/src/SHA256.js',
            'src/crypto-js/src/SHA1.js',
            'src/crypto-js/src/MD5.js',
            'src/crypto-js/src/AES.js',
            'src/crypto-js/src/PBKDF2.js',
            'src/crypto-js/src/HMAC.js',

            'src/crypto-js-etc/ripemd160.js',

            // node-scrypt-js (native javascript implementation)
            //'src/node-scrypt-js/scrypt.js',

            // js-scrypt (llvm to javascript via emscripten)
            'src/js-scrypt/browser/scrypt.js',
            'src/js-scrypt-wrapper.js',

            'src/jsbn/prng4.js',
            'src/jsbn/rng.js',
            'src/jsbn/jsbn.js',
            'src/jsbn/jsbn2.js',
            'src/jsbn/ec.js',
            'src/jsbn/sec.js',

            'src/events/eventemitter.js',
            'src/bitcoin.js',
            'src/util.js',
            'src/base58.js',

            'src/address.js',
            'src/ecdsa.js',
            'src/eckey.js',
            'src/opcode.js',
            'src/script.js',
            'src/transaction.js',
            'src/bip38.js',

            'src/wallet.js',
            'src/txdb.js'
          ]
        }
      }
    }
  });
  grunt.registerTask('default', ['uglify']);
}
