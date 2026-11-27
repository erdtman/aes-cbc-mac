'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const aesCbcMac = require('../');

const key128 = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');
const key256 = Buffer.from('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188', 'hex');

// Test vectors from the COSE examples, https://github.com/cose-wg/Examples.
test('AES-MAC-128/64', () => {
  const msg = Buffer.from('84634D414343A1010E4054546869732069732074686520636F6E74656E742E', 'hex');
  const tag = aesCbcMac.create(key128, msg, 8);
  assert.equal(tag.toString('hex').toUpperCase(), 'C1CA820E6E247089');
});

test('AES-MAC-128/128', () => {
  const msg = Buffer.from('84634D414344A10118194054546869732069732074686520636F6E74656E742E', 'hex');
  const tag = aesCbcMac.create(key128, msg, 16);
  assert.equal(tag.toString('hex').toUpperCase(), 'B242D2A935FEB4D66FF8334AC95BF72B');
});

test('AES-MAC-256/64', () => {
  const msg = Buffer.from('84634D414343A1010F4054546869732069732074686520636F6E74656E742E', 'hex');
  const tag = aesCbcMac.create(key256, msg, 8);
  assert.equal(tag.toString('hex').toUpperCase(), '9E1226BA1F81B848');
});

test('AES-MAC-256/128', () => {
  const msg = Buffer.from('84634D414344A101181A4054546869732069732074686520636F6E74656E742E', 'hex');
  const tag = aesCbcMac.create(key256, msg, 16);
  assert.equal(tag.toString('hex').toUpperCase(), 'DB9C7598A0751C5FF3366B6205BD2AA9');
});

test('the tag is the requested length, and the 64 bit tag is a prefix of the 128 bit one', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const short = aesCbcMac.create(key128, msg, 8);
  const long = aesCbcMac.create(key128, msg, 16);
  assert.equal(short.length, 8);
  assert.equal(long.length, 16);
  assert.deepEqual(short, long.subarray(0, 8));
});

test('the tag shares no memory with the full MAC or the buffer pool', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 8);
  // Returned as a view, tag.buffer would expose the 8 discarded bytes of the
  // 128 bit MAC, and whatever else sits nearby in Node's shared buffer pool.
  assert.equal(tag.byteOffset, 0);
  assert.equal(tag.buffer.byteLength, tag.length);
});

test('the same key and message always give the same tag', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  assert.deepEqual(aesCbcMac.create(key128, msg, 16), aesCbcMac.create(key128, msg, 16));
});

test('the key and message are left untouched', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const msgCopy = Buffer.from(msg);
  const keyCopy = Buffer.from(key128);
  aesCbcMac.create(key128, msg, 16);
  assert.deepEqual(msg, msgCopy);
  assert.deepEqual(key128, keyCopy);
});

test('an unsupported key length is rejected', () => {
  const msg = Buffer.from('84', 'hex');
  for (const length of [0, 8, 18, 24, 33]) {
    assert.throws(
      () => aesCbcMac.create(Buffer.alloc(length), msg, 16),
      { name: 'TypeError', message: `Unsupported key length ${length}` }
    );
  }
});

test('a key that is not a Buffer is rejected', () => {
  const msg = Buffer.from('84', 'hex');
  for (const key of ['asdad', 1234, null, undefined, new Uint8Array(16)]) {
    assert.throws(
      () => aesCbcMac.create(key, msg, 16),
      { name: 'TypeError', message: 'Key must be of type Buffer' }
    );
  }
});

test('a message that is not a Buffer is rejected', () => {
  for (const msg of ['asdf', 1234, null, undefined, new Uint8Array(16)]) {
    assert.throws(
      () => aesCbcMac.create(key128, msg, 16),
      { name: 'TypeError', message: 'Msg must be of type Buffer' }
    );
  }
});

test('an unsupported tag length is rejected', () => {
  const msg = Buffer.from('84', 'hex');
  for (const len of [0, 4, 12, 17, 128, '8', 8.5, undefined]) {
    assert.throws(
      () => aesCbcMac.create(key128, msg, len),
      { name: 'TypeError', message: 'Len must be 8 or 16' }
    );
  }
});

test('an empty message is rejected rather than returning an empty tag', () => {
  assert.throws(
    () => aesCbcMac.create(key128, Buffer.alloc(0), 8),
    { name: 'RangeError', message: 'Msg must not be empty' }
  );
});

// An independent cross-check of the CBC chaining. AES-ECB is a different Node
// code path, and the caller writes the zero padding out by hand, so this shares
// no logic with lib/index.js: it is not the hand-rolled reference MAC that used
// to live here and mirrored the implementation.
function cbcMacReference (key, paddedMsg) {
  assert.equal(paddedMsg.length % 16, 0, 'the reference takes an already padded message');
  assert.notEqual(paddedMsg.length, 0, 'the reference needs at least one block');
  let prev = Buffer.alloc(16);
  for (let i = 0; i < paddedMsg.length; i += 16) {
    const block = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) {
      block[j] = paddedMsg[i + j] ^ prev[j];
    }
    const ecb = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
    ecb.setAutoPadding(false);
    prev = Buffer.concat([ecb.update(block), ecb.final()]);
  }
  return prev;
}

test('a single block tag is plain AES-ECB of that block', () => {
  const msg = crypto.randomBytes(16);
  const ecb = crypto.createCipheriv('aes-128-ecb', key128, null);
  ecb.setAutoPadding(false);
  const expected = Buffer.concat([ecb.update(msg), ecb.final()]);
  assert.deepEqual(aesCbcMac.create(key128, msg, 16), expected);
});

test('multi-block tags match a CBC chain built from AES-ECB', () => {
  for (const key of [key128, key256]) {
    for (const blocks of [1, 2, 3, 17]) {
      const msg = crypto.randomBytes(blocks * 16);
      const expected = cbcMacReference(key, msg);
      assert.deepEqual(aesCbcMac.create(key, msg, 16), expected);
      assert.deepEqual(aesCbcMac.create(key, msg, 8), expected.subarray(0, 8));
    }
  }
});

test('messages either side of a block boundary are zero-padded to the next one', () => {
  // The pad lengths are written out rather than computed, so the test does not
  // repeat the implementation's arithmetic.
  for (const [msgLen, padLen] of [[1, 15], [15, 1], [16, 0], [17, 15], [31, 1], [32, 0], [33, 15]]) {
    const msg = crypto.randomBytes(msgLen);
    const padded = Buffer.concat([msg, Buffer.alloc(padLen)]);
    assert.equal(padded.length % 16, 0, `msg ${msgLen} + pad ${padLen} is block aligned`);
    const tag = aesCbcMac.create(key128, msg, 16);
    assert.equal(tag.length, 16);
    assert.deepEqual(tag, cbcMacReference(key128, padded), `msg of ${msgLen} bytes`);
  }
});

test('trailing zeros inside the final block are not distinguished', () => {
  // Zero padding is not injective. This is a documented limitation of the
  // construction, pinned here so it stays a known property rather than turning
  // into a surprise. See the Security Considerations section of the README.
  const tagOf = (...bytes) => aesCbcMac.create(key128, Buffer.from(bytes), 16);
  assert.deepEqual(tagOf(1), tagOf(1, 0));
  assert.deepEqual(tagOf(1), tagOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
  // The ambiguity stops at the block boundary: one more zero is a new block.
  assert.notDeepEqual(tagOf(1), tagOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
});

test('a key or message that is a view into a larger buffer is read at its offset', () => {
  const msg = crypto.randomBytes(20);
  const expected = aesCbcMac.create(key128, msg, 16);

  const keyHost = crypto.randomBytes(40);
  keyHost.set(key128, 7);
  assert.deepEqual(aesCbcMac.create(keyHost.subarray(7, 23), msg, 16), expected);

  const msgHost = crypto.randomBytes(40);
  msgHost.set(msg, 11);
  assert.deepEqual(aesCbcMac.create(key128, msgHost.subarray(11, 31), 16), expected);
});

test('the tag shares no memory with the full MAC at either tag length', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  for (const len of [8, 16]) {
    const tag = aesCbcMac.create(key128, msg, len);
    assert.equal(tag.byteOffset, 0, `len ${len}`);
    assert.equal(tag.buffer.byteLength, tag.length, `len ${len}`);
  }
});

test('a multi-megabyte message is handled', () => {
  const msg = crypto.randomBytes(4 * 1024 * 1024 + 7);
  const tag = aesCbcMac.create(key256, msg, 16);
  assert.equal(tag.length, 16);
  assert.deepEqual(tag, aesCbcMac.create(key256, msg, 16));
});

test('verify accepts the tag create produced', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  for (const key of [key128, key256]) {
    for (const len of [8, 16]) {
      assert.equal(aesCbcMac.verify(key, msg, aesCbcMac.create(key, msg, len), len), true);
    }
  }
});

test('verify rejects a tampered tag, message and key', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 16);

  const badTag = Buffer.from(tag);
  badTag[15] ^= 1;
  assert.equal(aesCbcMac.verify(key128, msg, badTag, 16), false);

  const badMsg = Buffer.from(msg);
  badMsg[0] ^= 1;
  assert.equal(aesCbcMac.verify(key128, badMsg, tag, 16), false);

  const badKey = Buffer.from(key128);
  badKey[0] ^= 1;
  assert.equal(aesCbcMac.verify(badKey, msg, tag, 16), false);
});

test('verify will not accept a truncated tag in place of the length the algorithm requires', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 16);
  // The 64 bit tag is a prefix of the 128 bit one, so deriving the expected
  // length from the tag would let this downgrade a 2^128 forgery to 2^64.
  assert.equal(aesCbcMac.verify(key128, msg, tag.subarray(0, 8), 16), false);
  assert.equal(aesCbcMac.verify(key128, msg, Buffer.alloc(0), 16), false);
  assert.equal(aesCbcMac.verify(key128, msg, Buffer.concat([tag, Buffer.alloc(1)]), 16), false);
});

test('verify does not leave the tag or message modified', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 8);
  const msgCopy = Buffer.from(msg);
  const tagCopy = Buffer.from(tag);
  aesCbcMac.verify(key128, msg, tag, 8);
  assert.deepEqual(msg, msgCopy);
  assert.deepEqual(tag, tagCopy);
});

test('verify rejects a tag that is not a Buffer, and an unsupported len', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 8);
  for (const bad of ['asdf', 1234, null, undefined, new Uint8Array(8)]) {
    assert.throws(
      () => aesCbcMac.verify(key128, msg, bad, 8),
      { name: 'TypeError', message: 'Tag must be of type Buffer' }
    );
  }
  for (const len of [0, 4, 12, 17, '8', 8.5, undefined]) {
    assert.throws(
      () => aesCbcMac.verify(key128, msg, tag, len),
      { name: 'TypeError', message: 'Len must be 8 or 16' }
    );
  }
});

test('verify passes a bad key or message through to create', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const tag = aesCbcMac.create(key128, msg, 8);
  assert.throws(
    () => aesCbcMac.verify(Buffer.alloc(24), msg, tag, 8),
    { name: 'TypeError', message: 'Unsupported key length 24' }
  );
  assert.throws(
    () => aesCbcMac.verify(key128, Buffer.alloc(0), tag, 8),
    { name: 'RangeError', message: 'Msg must not be empty' }
  );
});

test('the key length allowlist cannot be bypassed by polluting Object.prototype', () => {
  // ciphers[key.length] on a plain object would find an inherited '24' here and
  // MAC under it, slipping a key length COSE does not define past the check.
  Object.prototype[24] = 'aes-192-cbc'; // eslint-disable-line no-extend-native
  try {
    assert.throws(
      () => aesCbcMac.create(Buffer.alloc(24), Buffer.from([1]), 16),
      { name: 'TypeError', message: 'Unsupported key length 24' }
    );
  } finally {
    delete Object.prototype[24];
  }
});
