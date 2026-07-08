package jose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
)

// defaultIV is the RFC 3394 §2.2.3.1 default initial value (A6A6A6A6A6A6A6A6),
// used as an integrity check on unwrap.
var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap implements the RFC 3394 AES Key Wrap algorithm. plaintext (the
// content-encryption key) must be a non-empty multiple of 8 octets. This is
// JOSE "A256KW"; it is not RFC 5649 key-wrap-with-padding, which is a different,
// non-interoperable construction.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrInvalidKeySize
	}
	if len(plaintext) < 8 || len(plaintext)%8 != 0 {
		return nil, ErrMalformed
	}

	n := len(plaintext) / 8
	a := make([]byte, 8)
	copy(a, defaultIV)
	r := make([]byte, len(plaintext))
	copy(r, plaintext)

	var b [16]byte
	for j := range 6 {
		for i := 1; i <= n; i++ {
			copy(b[:8], a)
			copy(b[8:], r[(i-1)*8:i*8])
			block.Encrypt(b[:], b[:])

			t := uint64(n*j + i) //nolint:gosec // RFC 3394 round counter; n*j+i is small and non-negative
			copy(a, b[:8])
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(a)^t)
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}

	out := make([]byte, 8+len(r))
	copy(out, a)
	copy(out[8:], r)
	return out, nil
}

// aesKeyUnwrap reverses aesKeyWrap and verifies the RFC 3394 integrity check in
// constant time. A failed check returns ErrDecrypt with no detail, so it cannot
// serve as an oracle.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrInvalidKeySize
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, ErrDecrypt
	}

	n := len(ciphertext)/8 - 1
	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([]byte, len(ciphertext)-8)
	copy(r, ciphertext[8:])

	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i) //nolint:gosec // RFC 3394 round counter; n*j+i is small and non-negative
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(a)^t)
			copy(b[:8], a)
			copy(b[8:], r[(i-1)*8:i*8])
			decryptBlock(block, b[:])
			copy(a, b[:8])
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}

	if subtle.ConstantTimeCompare(a, defaultIV) != 1 {
		return nil, ErrDecrypt
	}
	return r, nil
}

// decryptBlock decrypts a single AES block in place.
func decryptBlock(block cipher.Block, buf []byte) {
	block.Decrypt(buf, buf)
}
