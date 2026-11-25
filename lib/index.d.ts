/// <reference types="node" />

/**
 * The tag lengths COSE AES-MAC defines, in bytes: 8 for a 64 bit tag, 16 for a
 * 128 bit tag.
 */
export type TagLength = 8 | 16;

/**
 * Compute an AES-CBC-MAC tag, as used by COSE AES-MAC
 * (RFC 9053 section 3.2).
 *
 * @param key 16 bytes for AES-128, or 32 bytes for AES-256.
 * @param msg The message to authenticate. Must not be empty.
 * @param len The tag length in bytes.
 *
 * @returns The tag, `len` bytes long.
 *
 * @throws {TypeError} If `key` or `msg` is not a Buffer, if the key length is
 * not 16 or 32, or if `len` is not 8 or 16.
 * @throws {RangeError} If `msg` is empty.
 */
export function create (key: Buffer, msg: Buffer, len: TagLength): Buffer;
