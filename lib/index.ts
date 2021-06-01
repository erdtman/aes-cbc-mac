const crypto: Crypto = require('isomorphic-webcrypto');

const iv = new Uint8Array(16); // Initialization vector.

export async function create(key: Uint8Array, msg: Uint8Array, len: 8 | 16): Promise<ArrayBuffer> {
  const padLen = msg.length % 16 ? 16 - (msg.length % 16) : 0;
  const paddedMsg = new Uint8Array(msg.length + padLen);
  paddedMsg.set(msg, 0);

  const crypto_key = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
  const enc = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, crypto_key, paddedMsg);

  const tagStart = enc.byteLength - 16 - 16;
  const tag = enc.slice(tagStart, tagStart + len);
  return tag;
};
