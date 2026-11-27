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
 * Zero padding is not injective, so messages differing only in trailing zero
 * bytes within the final block get the same tag. See the Security
 * Considerations section of the README.
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

/**
 * Verify an AES-CBC-MAC tag in constant time.
 *
 * `len` is the tag length the algorithm in use calls for, and a tag of any
 * other length fails verification. Deriving the length from `tag` instead would
 * let an attacker swap a 128 bit tag for its own 64 bit prefix and have it
 * accepted, turning a 2^128 forgery into a 2^64 one.
 *
 * `key`, `msg` and `len` are the caller's own, so a bad one throws as it does
 * in `create`. The tag arrives from whoever is being authenticated, so a tag of
 * the wrong length returns `false` rather than throwing.
 *
 * @param key 16 bytes for AES-128, or 32 bytes for AES-256.
 * @param msg The message the tag is supposed to authenticate.
 * @param tag The tag to check.
 * @param len The tag length the algorithm requires.
 *
 * @returns `true` if `tag` is the `len` byte AES-CBC-MAC of `msg` under `key`.
 *
 * @throws {TypeError} If `key`, `msg` or `tag` is not a Buffer, if the key
 * length is not 16 or 32, or if `len` is not 8 or 16.
 * @throws {RangeError} If `msg` is empty.
 */
export function verify (key: Buffer, msg: Buffer, tag: Buffer, len: TagLength): boolean;
