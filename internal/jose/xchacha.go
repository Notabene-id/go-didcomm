package jose

import "golang.org/x/crypto/chacha20poly1305"

// decryptXC20P verifies and decrypts an XChaCha20-Poly1305 (XC20P) ciphertext
// (24-byte nonce, 128-bit tag). Every failure returns ErrDecrypt with no detail.
func decryptXC20P(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(cek)
	if err != nil || len(iv) != chacha20poly1305.NonceSizeX || len(tag) != aead.Overhead() {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// xc20pKeyUnwrap reverses the XC20PKW key wrap (draft-amringer-jose-chacha-02):
// the CEK is sealed with XChaCha20-Poly1305 under the KEK, with a per-recipient
// nonce (iv) and tag and no additional data. Every failure returns ErrDecrypt.
func xc20pKeyUnwrap(kek, wrapped, iv, tag []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil || len(iv) != chacha20poly1305.NonceSizeX || len(tag) != aead.Overhead() {
		return nil, ErrDecrypt
	}
	cek, err := aead.Open(nil, iv, append(append([]byte{}, wrapped...), tag...), nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return cek, nil
}
