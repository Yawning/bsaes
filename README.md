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

 * `ctrAble` support for less-slow CTR-AES mode, leveraging the fact that the
   implementation is bitsliced.

 * Compatible with `crypto/cipher` methods that take a `crypto/cipher.Block`
   that are safe to use.  The GHASH provided by `crypto/cipher` is not
   guaranteed to be constant time, so attempting to combine bsaes with it will
   result in a runtime error.

 * The raw guts of the implementations provided as sub-packages, for people
   to use to implement [other things](https://git.schwanenlied.me/yawning/aez).

Benchmarks:

| Primitive           | Version | ns/op  | MB/s   |
| ------------------- | :-----: | -----: | -----: |
| ECB-AES128          | ct32    | 911    | 17.56  |
| ECB-AES256          | ct32    | 1242   | 12.88  |
| CTR-AES128 (16 KiB) | ct32    | 468683 | 34.96  |
| ECB-AES128          | ct64    | 1028   | 15.56  |
| ECB-AES256          | ct64    | 1326   | 12.06  |
| CTR-AES128 (16 KiB) | ct64    | 294952 | 55.55  |

All numbers taken on an Intel i7-5600U with Turbo Boost disabled, running on
linux/amd64.

ps: The `bs` stand for bullshit, because the runtime library really should be
better.
