#!/usr/bin/env node

const crypto = require('crypto');
const argv = require('yargs').argv;
const resizedIV = Buffer.allocUnsafe(16);
const Settings = Object.freeze({
  SECRET_KEY: '1b206e81598abdafd5d203421ac2da4b', // Replace with your secret key
  DEFAULT_HASH: 'sha256',
  DEFAULT_ALGORITHM: 'aes256',
  ENCODING_DECODED: 'utf-8',
  ENCODING_ENCODED: 'hex',
});

if (argv.e && argv.key || argv.encrypt && argv.key) {
  console.log(encrypt(argv._, argv.key, argv.hash && argv.hash, argv.algorithm && argv.algorithm));
} else if (argv.d && argv.key || argv.decrypt && argv.key) {
  console.log(decrypt(argv._, argv.key, argv.hash && argv.hash, argv.algorithm && argv.algorithm));
} else if (argv.hashes) {
  console.dir(getHashes(), { 'maxArrayLength': null });
} else if (argv.ciphers) {
  console.dir(getCiphers(), { 'maxArrayLength': null });
}

function init(hash) {
  const iv = crypto
    .createHash(hash)
    .update(Settings.SECRET_KEY)
    .digest();

  iv.copy(resizedIV);
}

function encrypt(
  input,
  key,
  hash = Settings.DEFAULT_HASH,
  algorithm = Settings.DEFAULT_ALGORITHM,
  inputEncoding = Settings.ENCODING_DECODED,
  outputEncoding = Settings.ENCODING_ENCODED
) {
  init(hash);

  const cipher = crypto.createCipheriv(
    algorithm,
    getKey(hash, key),
    resizedIV
  );

  return getMessage(cipher, input, inputEncoding, outputEncoding);
}

function decrypt(
  input,
  key,
  hash = Settings.DEFAULT_HASH,
  algorithm = Settings.DEFAULT_ALGORITHM,
  inputEncoding = Settings.ENCODING_ENCODED,
  outputEncoding = Settings.ENCODING_DECODED
) {
  init(hash);

  const decipher = crypto.createDecipheriv(
    algorithm,
    getKey(hash, key),
    resizedIV
  );

  return getMessage(decipher, input, inputEncoding, outputEncoding);
}

function getKey(hash, key) {
  return crypto
    .createHash(hash)
    .update(key)
    .digest();
}

function getMessage(cipherOrDeciper, input, inputEncoding, outputEncoding) {
  const message = [];

  input.forEach((phrase) => {
    message.push(cipherOrDeciper.update(phrase, inputEncoding, outputEncoding));
  });

  message.push(cipherOrDeciper.final(outputEncoding));
  return message.join('');
}

function getHashes() {
  return crypto.getHashes();
}

function getCiphers() {
  return crypto.getCiphers();
}