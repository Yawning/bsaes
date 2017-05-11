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

package modes

import (
	"crypto/cipher"
	"runtime"
)

func (m *BlockModesImpl) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	ecb := m.b.(bulkECBAble)
	if len(iv) != ecb.BlockSize() {
		panic("bsaes/NewCBCDecrypter: iv size does not match block size")
	}

	return newCbcDecImpl(ecb, iv)
}

type cbcDecImpl struct {
	ecb bulkECBAble
	iv  []byte
	buf []byte
	tmp []byte

	blockSize int
	stride    int
}

func (c *cbcDecImpl) Reset() {
	c.ecb.Reset()
}

func (c *cbcDecImpl) BlockSize() int {
	return c.blockSize
}

func (c *cbcDecImpl) CryptBlocks(dst, src []byte) {
	sLen := len(src)
	if sLen == 0 {
		return
	}
	n := sLen / c.blockSize

	for n >= c.stride { // Stride blocks at a time.
		copy(c.iv[c.blockSize:], src)
		copy(c.tmp, src[(c.stride-1)*c.blockSize:])

		c.ecb.BulkDecrypt(c.buf, src)
		for i, v := range c.iv {
			dst[i] = c.buf[i] ^ v
		}

		copy(c.iv, c.tmp)
		dst, src = dst[c.stride*c.blockSize:], src[c.stride*c.blockSize:]
		n -= c.stride
	}
	if n > 0 { // Process the remainder one block at a time.
		b := c.ecb.(cipher.Block)
		for n > 0 {
			copy(c.tmp, src[:c.blockSize])

			b.Decrypt(c.buf, src[:c.blockSize])
			for i, v := range c.iv[:c.blockSize] {
				dst[i] = c.buf[i] ^ v
			}

			copy(c.iv, c.tmp)
			dst, src = dst[c.blockSize:], src[c.blockSize:]
			n--
		}
	}
}

func newCbcDecImpl(ecb bulkECBAble, iv []byte) cipher.BlockMode {
	c := new(cbcDecImpl)
	c.ecb = ecb
	c.blockSize = ecb.BlockSize()
	c.stride = ecb.Stride()
	c.iv = make([]byte, c.stride*c.blockSize)
	copy(c.iv, iv)
	c.buf = make([]byte, c.stride*c.blockSize)
	c.tmp = make([]byte, c.blockSize)

	runtime.SetFinalizer(c, (*cbcDecImpl).Reset)

	return c
}
