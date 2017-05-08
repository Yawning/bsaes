### bsaes - BitSliced AES
#### Yawning Angel (yawning at schwanenlied dot me)

> The AES operations in this package are not implemented using constant-time
> algorithms. An exception is when running on systems with enabled hardware
> support for AES that makes these operations constant-time.
>
> -- https://golang.org/pkg/crypto/aes/

bsaes is a portable pure-Go constant time AES implementation based on the
excellent code from [BearSSL](https://bearssl.org/).  It does not use any
special hardware instructions even if present (and never will), use
`crypto/aes` on such platforms.

Features:

 * Constant time.

 * 32 bit and 64 bit variants, with the appropriate one selected at runtime.

 * Provides `crypto/cipher.Block`.

 * `crypto/cipher.ctrAble` support for less-slow CTR-AES mode, leveraging the
   fact that the implementation is bitsliced.

 * `crypto/cipher.gcmAble` support that returns a runtime error, because any
   platform that requires `bsaes` does not have a constant time GHASH.

 * The raw guts of the implementations provided as sub-packages, for people
   to use to implement [other things](https://git.schwanenlied.me/yawning/aez).

Benchmarks:

| Primitive           | Version | ns/op  | MB/s   |
| ------------------- | :-----: | -----: | -----: |
| ECB-AES128          | ct32    | 760    | 21.03  |
| ECB-AES256          | ct32    | 1054   | 15.18  |
| CTR-AES128 (16 KiB) | ct32    | 376825 | 43.48  |
| ECB-AES128          | ct64    | 836    | 19.12  |
| ECB-AES256          | ct64    | 1098   | 14.56  |
| CTR-AES128 (16 KiB) | ct64    | 235429 | 69.59  |

All numbers taken on an Intel i7-5600U with Turbo Boost disabled, running on
linux/amd64.
