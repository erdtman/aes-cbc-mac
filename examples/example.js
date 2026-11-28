'use strict';

const aesCbcMac = require('../');

const key = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');
const message = Buffer.from('Important message', 'utf8');
const tagLength = 8; // bytes, so a 64 bit tag

const tag = aesCbcMac.create(key, message, tagLength);

console.log(`tag: ${tag.toString('hex')}`);

if (aesCbcMac.verify(key, message, tag, tagLength)) {
  console.log('tag verified');
}
