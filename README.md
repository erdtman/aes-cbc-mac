[![test](https://github.com/erdtman/aes-cbc-mac/actions/workflows/test.yml/badge.svg)](https://github.com/erdtman/aes-cbc-mac/actions/workflows/test.yml)

# aes-cbc-mac

AES-CBC-MAC for Node, as used by the COSE `AES-MAC` algorithms
([RFC 9053 section 3.2](https://www.rfc-editor.org/rfc/rfc9053.html#section-3.2)).

Node's `crypto` module has no CBC-MAC of its own, so this package builds one on
top of `crypto`'s AES-CBC: the message is zero-padded to a whole number of AES
blocks, encrypted in CBC mode under an all-zero IV, and the tag is the leading
bytes of the last ciphertext block.

RFC 9053 fixes the IV and the key and tag lengths, but states no padding rule of
its own; it defines AES-CBC-MAC only as "the instantiation of the CBC-MAC
construction (defined in [MAC]) using AES as the block cipher". The zero padding
above is what the [COSE example vectors](https://github.com/cose-wg/Examples)
require, and it is what the tests check against. It has a consequence worth
reading before using this for anything but COSE: see
[Zero padding is not injective](#zero-padding-is-not-injective).

No dependencies, nothing to compile.

## Installation

```
npm install aes-cbc-mac
```

Requires Node 18 or later.

TypeScript declarations ship with the package, so there is no
`@types/aes-cbc-mac` to install. They use `Buffer`, so `@types/node` needs to be
present.

## Usage

```javascript
const aesCbcMac = require('aes-cbc-mac');

const key = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');
const message = Buffer.from('Important message', 'utf8');
const tagLength = 8; // bytes, so a 64 bit tag

const tag = aesCbcMac.create(key, message, tagLength);

console.log(tag.toString('hex'));
```

## API

### `create(key, msg, len)`

| argument | type     | accepted values                                        |
| -------- | -------- | ------------------------------------------------------ |
| `key`    | `Buffer` | 16 bytes for AES-128, 32 bytes for AES-256             |
| `msg`    | `Buffer` | at least one byte                                      |
| `len`    | `number` | `8` for a 64 bit tag, `16` for a 128 bit tag           |

Returns a `Buffer` holding the tag, `len` bytes long. In TypeScript `len` is
typed as `TagLength`, which is `8 | 16`, so a `len` computed as a plain `number`
needs narrowing or a cast. The four combinations of
key and tag length are exactly the COSE `AES-MAC-128/64`, `AES-MAC-128/128`,
`AES-MAC-256/64` and `AES-MAC-256/128` algorithms. AES-192 keys are not
supported, as COSE does not define an `AES-MAC` algorithm for them.

Anything else throws: a `TypeError` for a key or message that is not a `Buffer`,
an unsupported key length or an unsupported tag length, and a `RangeError` for
an empty message.

### `verify(key, msg, tag, len)`

| argument | type     | accepted values                                        |
| -------- | -------- | ------------------------------------------------------ |
| `key`    | `Buffer` | 16 bytes for AES-128, 32 bytes for AES-256             |
| `msg`    | `Buffer` | at least one byte                                      |
| `tag`    | `Buffer` | the tag to check, any length                           |
| `len`    | `number` | the tag length the algorithm requires, `8` or `16`     |

Returns `true` if `tag` is the `len` byte AES-CBC-MAC of `msg` under `key`. The
comparison uses
[`crypto.timingSafeEqual`](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b),
so it does not leak how much of a forged tag was correct.

```javascript
if (!aesCbcMac.verify(key, message, receivedTag, 8)) {
  throw new Error('Tag mismatch');
}
```

`len` is the length the algorithm in use calls for, not the length of the tag
that arrived, and a `tag` of any other length fails verification. Taking the
length from `tag` instead would be a downgrade: the 64 bit tag is a prefix of
the 128 bit one, so an attacker could answer an `AES-MAC-128/128` challenge with
an 8 byte tag of their own and have it accepted, which is a 2^64 forgery rather
than a 2^128 one.

`key`, `msg` and `len` are the caller's own, so a bad one throws exactly as it
does in `create`. The tag comes from whoever is being authenticated, so a `tag`
of the wrong length returns `false` rather than throwing — a remote peer should
not be able to raise an exception in the verifier by sending a short tag. A
`tag` that is not a `Buffer` is still a `TypeError`.

## Security Considerations

### Zero padding is not injective

Messages that differ only in trailing zero bytes within the final block get the
same tag, because zero-padding both of them produces the same input:

```javascript
const a = aesCbcMac.create(key, Buffer.from([1]), 16);
const b = aesCbcMac.create(key, Buffer.from([1, 0]), 16);
a.equals(b); // true
```

So a caller that MACs raw bytes under a single key is forgeable: observing the
tag for `m` gives a valid tag for `m` followed by up to a block of zeros. The
COSE `MAC_structure` is a CBOR array whose encoding carries the length of every
element, which removes the ambiguity for COSE use. A caller MACing anything else
needs its own length framing, or a MAC without this property such as
[`crypto.createHmac`](https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options)
or AES-CMAC.

### From RFC 9053

Quoted from [RFC 9053 section 3.2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-3.2.1).
"The current structure" is the COSE `MAC_structure` that the caller builds and
passes in as `msg`, not anything this package constructs.

A number of attacks exist against Cipher Block Chaining Message Authentication
Code (CBC-MAC) that need to be considered.

* A single key must only be used for messages of a fixed or known length. If
  this is not the case, an attacker will be able to generate a message with a
  valid tag given two message and tag pairs. This can be addressed by using
  different keys for messages of different lengths. The current structure
  mitigates this problem, as a specific encoding structure that includes lengths
  is built and signed. (CMAC also addresses this issue.)
* In Cipher Block Chaining (CBC) mode, if the same key is used for both
  encryption and authentication operations, an attacker can produce messages
  with a valid authentication code.
* If the IV can be modified, then messages can be forged. This is addressed by
  fixing the IV to all zeros.

## Changes in 1.2.0

Tags are unchanged, and nothing that worked in 1.1.0 stops working.

* **A `verify` function.** It compares in constant time and takes the required
  tag length explicitly, so callers no longer hand-roll a `timingSafeEqual`
  against a tag whose length an attacker chose. See
  [`verify`](#verifykey-msg-tag-len).
* **Zero-padding ambiguity is documented**, under
  [Security Considerations](#zero-padding-is-not-injective). The behaviour is
  unchanged — it is a property of CBC-MAC with zero padding — but it was not
  written down before.
* **The key length check no longer reads from `Object.prototype`.** The lookup
  from key length to AES variant was a plain object, so prototype pollution
  elsewhere in the process could slip an undefined key length past it. It is a
  `Map` now.
* **The padded plaintext no longer lands in Node's shared buffer pool**, and the
  plaintext copy and the untruncated MAC are cleared before `create` returns.

## Changes in 1.1.0

Tags are unchanged — every byte this version produces matches 1.0.1 — but four
things are worth knowing when upgrading:

* **An empty message now throws a `RangeError`.** 1.0.1 returned a zero-length
  `Buffer` for it, and a zero-length tag compares equal to any other zero-length
  tag, so a verifier could be made to accept anything.
* **Argument errors are now `TypeError`s** rather than plain `Error`s, with the
  messages unchanged. `TypeError` is an `Error`, so `catch` blocks and
  `error.message` checks keep working.
* **The returned tag is a copy, not a view.** 1.0.1 returned a `Buffer` that
  shared memory with the full MAC, so for a 64 bit tag the 8 bytes truncation
  discards — and whatever else sat nearby in Node's shared buffer pool — stayed
  reachable through `tag.buffer`. The tag now has an `ArrayBuffer` of its own,
  so `tag.byteOffset` is `0` and `tag.buffer.byteLength` equals `tag.length`.
* **The dev toolchain is gone.** Tests run on Node's built-in `node:test`
  runner, and the package has no dependencies at all, runtime or dev.

## Testing

```
npm test
```

Releases are published from CI with
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers), so each
version on npm carries a signed provenance attestation tying it to the commit
and workflow that built it.
