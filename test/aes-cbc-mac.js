'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const aesCbcMac = require('../');

const key128 = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');
const key256 = Buffer.from('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188', 'hex');

/**
  An independent CBC-MAC, built by chaining single-block ECB encryptions by
  hand, to check the library against something other than itself.
*/
function referenceMac (key, msg, len) {
  const algorithm = key.length === 16 ? 'aes-128-ecb' : 'aes-256-ecb';
  const padLen = (msg.length % 16 === 0) ? 0 : 16 - (msg.length % 16);
  const padded = Buffer.concat([msg, Buffer.alloc(padLen)]);

  let previous = Buffer.alloc(16, 0);
  for (let offset = 0; offset < padded.length; offset += 16) {
    const block = padded.subarray(offset, offset + 16);
    const input = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      input[i] = block[i] ^ previous[i];
    }
    const cipher = crypto.createCipheriv(algorithm, key, null);
    cipher.setAutoPadding(false);
    previous = Buffer.concat([cipher.update(input), cipher.final()]);
  }
  return previous.subarray(0, len);
}

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

test('matches an independent CBC-MAC for every message length up to 4 blocks', () => {
  for (const key of [key128, key256]) {
    for (let length = 1; length <= 64; length++) {
      const msg = crypto.randomBytes(length);
      assert.deepEqual(
        aesCbcMac.create(key, msg, 16),
        referenceMac(key, msg, 16),
        `mismatch for a ${length} byte message and a ${key.length} byte key`
      );
    }
  }
});

test('block aligned messages are not padded with an extra block', () => {
  // A 16 byte message is one block, so the tag must come from that block and
  // not from a block of padding appended after it.
  const msg = Buffer.alloc(16, 0x61);
  assert.deepEqual(aesCbcMac.create(key128, msg, 16), referenceMac(key128, msg, 16));
  assert.notDeepEqual(
    aesCbcMac.create(key128, msg, 16),
    aesCbcMac.create(key128, Buffer.concat([msg, Buffer.alloc(16)]), 16)
  );
});

test('the tag is the requested length, and the 64 bit tag is a prefix of the 128 bit one', () => {
  const msg = Buffer.from('546865206D657373616765', 'hex');
  const short = aesCbcMac.create(key128, msg, 8);
  const long = aesCbcMac.create(key128, msg, 16);
  assert.equal(short.length, 8);
  assert.equal(long.length, 16);
  assert.deepEqual(short, long.subarray(0, 8));
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
