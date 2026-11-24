'use strict';

const crypto = require('node:crypto');

const ciphers = {
  16: 'aes-128-cbc',
  32: 'aes-256-cbc'
};

const tagLengths = new Set([8, 16]);

// CBC-MAC fixes the IV to all zeros; a caller-chosen IV would let messages be
// forged. See the Security Considerations section of the README.
const iv = Buffer.alloc(16, 0);

/**
  Pick the AES-CBC variant matching the key size.

  @param key, the key that will be used for the MAC operation.

  @return the Node cipher name for that key length.
*/
function cipherFor (key) {
  const cipher = ciphers[key.length];
  if (!cipher) {
    throw new TypeError(`Unsupported key length ${key.length}`);
  }
  return cipher;
}

/**
  Compute an AES-CBC-MAC tag, as used by COSE AES-MAC (RFC 9052 section 3.2).

  The message is zero-padded to a whole number of AES blocks, encrypted in CBC
  mode under an all-zero IV, and the tag is the leading bytes of the last
  ciphertext block.

  @param key, the key to authenticate with, 16 bytes (AES-128) or 32 (AES-256)
  @param msg, the message to authenticate, at least one byte
  @param len, the tag length in bytes, 8 (64 bits) or 16 (128 bits)

  @return a Buffer holding the tag, len bytes long.
*/
function create (key, msg, len) {
  if (!Buffer.isBuffer(key)) {
    throw new TypeError('Key must be of type Buffer');
  }
  if (!Buffer.isBuffer(msg)) {
    throw new TypeError('Msg must be of type Buffer');
  }
  if (!tagLengths.has(len)) {
    throw new TypeError('Len must be 8 or 16');
  }
  // An empty message has no final block to take the tag from. Earlier releases
  // returned a zero-length Buffer here, which a tag comparison would accept as
  // valid against anything.
  if (msg.length === 0) {
    throw new RangeError('Msg must not be empty');
  }

  const cipher = crypto.createCipheriv(cipherFor(key), key, iv);
  // The padding below is part of the MAC construction, so Node must not add
  // PKCS#7 padding of its own on final().
  cipher.setAutoPadding(false);

  const padLen = (msg.length % 16 === 0) ? 0 : 16 - (msg.length % 16);
  const paddedMsg = Buffer.concat([msg, Buffer.alloc(padLen)]);
  const enc = Buffer.concat([cipher.update(paddedMsg), cipher.final()]);

  return enc.subarray(enc.length - 16, enc.length - 16 + len);
}

module.exports = { create };
