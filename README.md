[![test](https://github.com/erdtman/aes-cbc-mac/actions/workflows/test.yml/badge.svg)](https://github.com/erdtman/aes-cbc-mac/actions/workflows/test.yml)

# aes-cbc-mac

AES-CBC-MAC for Node, as used by the COSE `AES-MAC` algorithms
([RFC 9052 section 3.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.2)).

Node's `crypto` module has no CBC-MAC of its own, so this package builds one on
top of `crypto`'s AES-CBC: the message is zero-padded to a whole number of AES
blocks, encrypted in CBC mode under an all-zero IV, and the tag is the leading
bytes of the last ciphertext block.

No dependencies, nothing to compile.

## Installation

```
npm install aes-cbc-mac
```

Requires Node 18 or later.

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

Returns a `Buffer` holding the tag, `len` bytes long. The four combinations of
key and tag length are exactly the COSE `AES-MAC-128/64`, `AES-MAC-128/128`,
`AES-MAC-256/64` and `AES-MAC-256/128` algorithms. AES-192 keys are not
supported, as COSE does not define an `AES-MAC` algorithm for them.

Anything else throws: a `TypeError` for a key or message that is not a `Buffer`,
an unsupported key length or an unsupported tag length, and a `RangeError` for
an empty message.

Verifying a tag means recomputing it and comparing. Compare with
[`crypto.timingSafeEqual`](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
rather than `Buffer.equals`, so the comparison does not leak how much of a
forged tag was correct:

```javascript
const crypto = require('node:crypto');

const expected = aesCbcMac.create(key, message, received.length);
const ok = received.length === expected.length &&
  crypto.timingSafeEqual(received, expected);
```

## Security Considerations

A number of attacks exist against Cipher Block Chaining Message Authentication
Code (CBC-MAC) that need to be considered.

* A single key must only be used for messages of a fixed and known length. If
  this is not the case, an attacker will be able to generate a message with a
  valid tag given two message and tag pairs. This can be addressed by using
  different keys for messages of different lengths. COSE mitigates this problem,
  as the structure it builds and authenticates encodes the lengths.
  (CMAC also addresses this issue.)
* In Cipher Block Chaining (CBC) mode, if the same key is used for both
  encryption and authentication operations, an attacker can produce messages
  with a valid authentication code.
* If the IV can be modified, then messages can be forged. This is addressed by
  fixing the IV to all zeros.

## Changes in 1.1.0

Tags are unchanged — every byte this version produces matches 1.0.1 — but three
things are worth knowing when upgrading:

* **An empty message now throws a `RangeError`.** 1.0.1 returned a zero-length
  `Buffer` for it, and a zero-length tag compares equal to any other zero-length
  tag, so a verifier could be made to accept anything.
* **Argument errors are now `TypeError`s** rather than plain `Error`s, with the
  messages unchanged. `TypeError` is an `Error`, so `catch` blocks and
  `error.message` checks keep working.
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
