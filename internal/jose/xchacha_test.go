package jose

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestDecryptXC20P(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x24}, chacha20poly1305.NonceSizeX)
	aad := []byte("protected-header")
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	out := aead.Seal(nil, nonce, plaintext, aad)
	ct, tag := out[:len(out)-aead.Overhead()], out[len(out)-aead.Overhead():]

	got, err := decryptXC20P(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("decryptXC20P: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}

	tampered := append([]byte{}, tag...)
	tampered[0] ^= 1
	if _, err := decryptXC20P(key, nonce, ct, tampered, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered tag err = %v, want ErrDecrypt", err)
	}
	if _, err := decryptXC20P(key, nonce, ct, tag, []byte("wrong-aad")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong aad err = %v, want ErrDecrypt", err)
	}
	if _, err := decryptXC20P(key, nonce[:12], ct, tag, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short nonce err = %v, want ErrDecrypt", err)
	}
}

func TestXC20PKeyUnwrap(t *testing.T) {
	kek := bytes.Repeat([]byte{0x11}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x22}, chacha20poly1305.NonceSizeX)
	cek := bytes.Repeat([]byte{0x33}, 32)

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		t.Fatal(err)
	}
	out := aead.Seal(nil, nonce, cek, nil) // XC20PKW wraps with no additional data
	wrapped, tag := out[:len(out)-aead.Overhead()], out[len(out)-aead.Overhead():]

	got, err := xc20pKeyUnwrap(kek, wrapped, nonce, tag)
	if err != nil {
		t.Fatalf("xc20pKeyUnwrap: %v", err)
	}
	if !bytes.Equal(got, cek) {
		t.Fatalf("cek mismatch")
	}

	tampered := append([]byte{}, tag...)
	tampered[0] ^= 1
	if _, err := xc20pKeyUnwrap(kek, wrapped, nonce, tampered); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered tag err = %v, want ErrDecrypt", err)
	}
}
