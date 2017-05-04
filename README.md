### bsaes - BitSliced AES
#### Yawning Angel (yawning at schwanenlied dot me)

> The AES operations in this package are not implemented using constant-time
> algorithms. An exception is when running on systems with enabled hardware
> support for AES that makes these operations constant-time.
>
> -- https://golang.org/pkg/crypto/aes/

This is a portable pure-Go bitsliced constant time AES implementation based on
the excellent code from [BearSSL](https://bearssl.org/).  It does not use any
special hardware instructions even if present (and never will), use
`crypto/aes` on such platforms.

It exposes the inner guts of the implementation(s) it provdes so it can be used
for [other things](https://git.schwanenlied.me/yawning/aez), however exposed
routines beyond the provided `crypto/Block` implementation will remain forever
unstable and undocumented (much to the lamentations of `go lint`).
