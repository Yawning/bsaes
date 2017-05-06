// aes_test.go - AES tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aes_test.go, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bsaes

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"git.schwanenlied.me/yawning/bsaes.git/ct32"
	"git.schwanenlied.me/yawning/bsaes.git/ct64"
)

type Impl struct {
	name string
	ctor func([]byte) cipher.Block
}

var (
	implCt32 = &Impl{"ct32", ct32.NewCipher}
	implCt64 = &Impl{"ct64", ct64.NewCipher}

	impls = []*Impl{implCt32, implCt64}
)

// The test vectors are shamelessly stolen from NIST Special Pub. 800-38A,
// my tax dollars at work.
//
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

var ecbVectors = []struct {
	key        string
	plaintext  string
	ciphertext string
}{
	// ECB-AES128
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"6bc1bee22e409f96e93d7e117393172a",
		"3ad77bb40d7a3660a89ecaf32466ef97",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"f5d3d58503b9699de785895a96fdbaaf",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"43b1cd7f598ece23881b00e3ed030688",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"f69f2445df4f9b17ad2b417be66c3710",
		"7b0c785e27e8ad3f8223207104725dd4",
	},

	// ECB-AES192
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"6bc1bee22e409f96e93d7e117393172a",
		"bd334f1d6e45f25ff712a214571fa5cc",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"974104846d0ad3ad7734ecb3ecee4eef",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"ef7afd2270e2e60adce0ba2face6444e",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"f69f2445df4f9b17ad2b417be66c3710",
		"9a4b41ba738d6c72fb16691603c18e0e",
	},

	// ECB-AES256
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"6bc1bee22e409f96e93d7e117393172a",
		"f3eed1bdb5d2a03c064b5a7e3db181f8",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"591ccb10d410ed26dc5ba74a31362870",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"b6ed21b99ca6f4f9f153e7b1beafed1d",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"f69f2445df4f9b17ad2b417be66c3710",
		"23304b7a39f9f3ff067d8d8f9e24ecc7",
	},
}

func TestECB_SP800_38A(t *testing.T) {
	for _, impl := range impls {
		t.Logf("Testing implementation: %v\n", impl.name)
		for i, vec := range ecbVectors {
			key, err := hex.DecodeString(vec.key[:])
			if err != nil {
				t.Fatal(err)
			}
			pt, err := hex.DecodeString(vec.plaintext[:])
			if err != nil {
				t.Fatal(err)
			}
			ct, err := hex.DecodeString(vec.ciphertext[:])
			if err != nil {
				t.Fatal(err)
			}

			b := impl.ctor(key)

			var dst [16]byte
			b.Encrypt(dst[:], pt)
			assertEqual(t, i, ct, dst[:])

			b.Decrypt(dst[:], ct)
			assertEqual(t, i, pt, dst[:])
		}
	}
}

func TestGCM(t *testing.T) {
	// Ensure that attempting to use GCM mode with this via
	// `crypto/cipher.NewGCM` fails.
	var key [16]byte

	for _, impl := range impls {
		b := impl.ctor(key[:])
		g, err := cipher.NewGCM(b)
		if g != nil {
			t.Errorf("[%s]: NewGCM() returned a cipher.AEAD, expected nil", impl.name)
			t.FailNow()
		}
		if err == nil {
			t.Errorf("[%s]: NewGCM() returned no error, expected failure", impl.name)
			t.FailNow()
		}
	}
}

func assertEqual(t *testing.T, idx int, expected, actual []byte) {
	if !bytes.Equal(expected, actual) {
		for i, v := range actual {
			if expected[i] != v {
				t.Errorf("[%d] first mismatch at offset: %d (%02x != %02x)", idx, i, expected[i], v)
				break
			}
		}
		t.Errorf("expected: %s", hex.Dump(expected))
		t.Errorf("actual: %s", hex.Dump(actual))
		t.FailNow()
	}
}

var benchOutput [16]byte

func doBenchECB(b *testing.B, impl *Impl, ksz int) {
	var src, dst, check [16]byte

	key := make([]byte, ksz)
	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	blk := impl.ctor(key[:])

	b.SetParallelism(1) // We want per-core figures.
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		blk.Encrypt(dst[:], src[:])
		b.StopTimer()

		// Check forward/back because, why not.
		blk.Decrypt(check[:], dst[:])
		if !bytes.Equal(check[:], src[:]) {
			b.Fatalf("decrypt produced invalid output")
		}
		copy(src[:], dst[:])
	}
	copy(benchOutput[:], dst[:])
}

func BenchmarkECB128_ct32(b *testing.B) {
	doBenchECB(b, implCt32, 16)
}

func BenchmarkECB192_ct32(b *testing.B) {
	doBenchECB(b, implCt32, 24)
}

func BenchmarkECB256_ct32(b *testing.B) {
	doBenchECB(b, implCt32, 32)
}

func BenchmarkECB128_ct64(b *testing.B) {
	doBenchECB(b, implCt64, 16)
}

func BenchmarkECB192_ct64(b *testing.B) {
	doBenchECB(b, implCt64, 24)
}

func BenchmarkECB256_ct64(b *testing.B) {
	doBenchECB(b, implCt64, 32)
}
