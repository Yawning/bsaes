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

type bulkECBEncryptAble interface {
	// BlockSize returns the block size in bytes.
	BlockSize() int

	// Stride returns the number of BlockSize-ed blocks that should be passed
	// to BulkEncrypt.
	Stride() int

	// Reset clears the block cipher state such that key material no longer
	// appears in process memory.
	Reset()

	// BulkECBEncrypt encrypts the Stride blocks of plaintext src,
	// and places the resulting output in the ciphertext dst.
	BulkECBEncrypt(dst, src []byte)
}

// CTRAbleImpl is a `crypto/cipher.ctrAble` instantiation that uses
// the bitslicing provided by bsaes
type CTRAbleImpl struct {
	b cipher.Block
}

func (m *CTRAbleImpl) CTRInit(b cipher.Block) {
	m.b = b
}

func (m *CTRAbleImpl) NewCTR(iv []byte) cipher.Stream {
	ecb := m.b.(bulkECBEncryptAble)
	if len(iv) != ecb.BlockSize() {
		panic("bsaes/NewCTR: iv size does not match block size")
	}

	return newCtrImpl(ecb, iv)
}

type ctrImpl struct {
	ecb bulkECBEncryptAble
	ctr []byte
	buf []byte
	idx int

	blockSize int
	stride    int
}

func (c *ctrImpl) Reset() {
	c.ecb.Reset()
	for i := range c.buf {
		c.buf[i] = 0
	}
}

func (c *ctrImpl) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if c.idx >= len(c.buf) {
			c.generateKeyStream()
			c.idx = 0
		}

		n := len(c.buf) - c.idx
		if sLen := len(src); sLen < n {
			n = sLen
		}
		for i, v := range src[:n] {
			dst[i] = v ^ c.buf[c.idx+i]
		}

		dst, src = dst[n:], src[n:]
		c.idx += n
	}
}

func (c *ctrImpl) generateKeyStream() {
	for i := 0; i < c.stride; i++ {
		copy(c.buf[i*c.blockSize:], c.ctr)

		// Increment counter.
		for j := c.blockSize; j > 0; j-- {
			c.ctr[j-1]++
			if c.ctr[j-1] != 0 {
				break
			}
		}
	}
	c.ecb.BulkECBEncrypt(c.buf, c.buf)
}

func newCtrImpl(ecb bulkECBEncryptAble, iv []byte) cipher.Stream {
	c := new(ctrImpl)
	c.ecb = ecb
	c.blockSize = ecb.BlockSize()
	c.stride = ecb.Stride()
	c.ctr = make([]byte, c.blockSize)
	copy(c.ctr, iv)
	c.buf = make([]byte, c.stride*c.blockSize)
	c.idx = len(c.buf)

	runtime.SetFinalizer(c, (*ctrImpl).Reset)

	return c
}