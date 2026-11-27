'use strict';

const crypto = require('node:crypto');

// A Map rather than an object literal: `ciphers[key.length]` on a plain object
// walks the prototype chain, so polluting Object.prototype with a numeric key
// would smuggle a cipher name past the key length check below.
const ciphers = new Map([
  [16, 'aes-128-cbc'],
  [32, 'aes-256-cbc']
]);

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
  const cipher = ciphers.get(key.length);
  if (!cipher) {
    throw new TypeError(`Unsupported key length ${key.length}`);
  }
  return cipher;
}

/**
  Compute an AES-CBC-MAC tag, as used by COSE AES-MAC (RFC 9053 section 3.2).

  The message is zero-padded to a whole number of AES blocks, encrypted in CBC
  mode under an all-zero IV, and the tag is the leading bytes of the last
  ciphertext block.

  Zero padding is not injective, so messages differing only in trailing zero
  bytes within the final block get the same tag. See the Security
  Considerations section of the README.

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

  // Buffer.alloc is zero-filled and gets an ArrayBuffer of its own, so the
  // padding comes for free and this copy of the plaintext stays out of Node's
  // shared 8 KB pool, which is where Buffer.concat would have put it.
  const padLen = (msg.length % 16 === 0) ? 0 : 16 - (msg.length % 16);
  const padded = Buffer.alloc(msg.length + padLen);
  padded.set(msg);

  const enc = Buffer.concat([cipher.update(padded), cipher.final()]);

  // Copy the tag out rather than returning a view onto enc. A Buffer view
  // shares its parent's memory, so a truncated tag would keep the discarded
  // bytes of the full MAC reachable through tag.buffer. Buffer.alloc gives the
  // copy an ArrayBuffer of its own; Buffer.from would copy it into Node's
  // shared 8 KB pool instead, leaving tag.buffer a window onto whatever else
  // happens to sit there.
  const tagStart = enc.length - 16;
  const tag = Buffer.alloc(len);
  enc.copy(tag, 0, tagStart, tagStart + len);

  // Best effort only: a garbage-collected VM makes no promise about copies it
  // moved, but clearing the plaintext and the untruncated MAC costs nothing.
  padded.fill(0);
  enc.fill(0);

  return tag;
}

/**
  Verify an AES-CBC-MAC tag in constant time.

  len is the tag length the algorithm in use calls for, and a tag of any other
  length fails verification. Deriving the length from the tag instead would let
  an attacker swap a 128 bit tag for its own 64 bit prefix and have it accepted,
  turning a 2^128 forgery into a 2^64 one.

  key, msg and len are the caller's own, so a bad one throws as it does in
  create. The tag arrives from whoever is being authenticated, so a tag of the
  wrong length is a failed verification rather than an error.

  @param key, the key to authenticate with, 16 bytes (AES-128) or 32 (AES-256)
  @param msg, the message the tag is supposed to authenticate
  @param tag, the tag to check
  @param len, the tag length the algorithm requires, 8 or 16

  @return true if tag is the len byte AES-CBC-MAC of msg under key.
*/
function verify (key, msg, tag, len) {
  if (!Buffer.isBuffer(tag)) {
    throw new TypeError('Tag must be of type Buffer');
  }
  if (!tagLengths.has(len)) {
    throw new TypeError('Len must be 8 or 16');
  }
  // create() would reject key, msg and len below, so this runs before any
  // length-dependent work; it is not a secret-dependent branch.
  if (tag.length !== len) {
    return false;
  }

  const expected = create(key, msg, len);
  try {
    return crypto.timingSafeEqual(tag, expected);
  } finally {
    expected.fill(0);
  }
}

module.exports = { create, verify };
