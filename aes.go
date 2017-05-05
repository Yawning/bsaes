// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package bsaes is a pure-Go bitsliced constant time AES implementation.
package bsaes

import (
	"crypto/cipher"
	"errors"
	"unsafe"

	"git.schwanenlied.me/yawning/bsaes.git/ct32"
	"git.schwanenlied.me/yawning/bsaes.git/ct64"
)

var pointerSize = 8

// NewCipher creates and returns a new cipher.Block.  The key argument should be
// the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, errors.New("aes: Invalid key size")
	}

	switch pointerSize {
	case 4:
		return ct32.NewCipher(key), nil
	case 8:
		return ct64.NewCipher(key), nil
	}

	// This could default to the 32 bit code, but really, what the fuck are
	// you running this on?
	panic("bsaes: unsupported pointer size")
}

func init() {
	var foo uintptr
	pointerSize = int(unsafe.Sizeof(foo))
}
