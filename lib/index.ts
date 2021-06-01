const crypto = require('crypto');

const iv = new Uint8Array(16); // Initialization vector.

export function create(key: Uint8Array, msg: Uint8Array, len: 8 | 16) {
  const algorithm = `aes-${key.length * 8}-cbc`;

  const msgLen = msg.length;
  const padLen = msgLen % 16 ? 16 - (msgLen % 16) : 0;
  const paddedMsg = new Uint8Array(msg.length + padLen);
  paddedMsg.set(msg, 0);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const enc = cipher.update(paddedMsg);
  const tagStart = enc.length - 16;
  const tag = enc.slice(tagStart, tagStart + len);

  return tag;
};
