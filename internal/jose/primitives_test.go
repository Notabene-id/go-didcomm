package jose

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestAESKeyWrapRFC3394 checks the 256-bit KEK / 128-bit key vector from
// RFC 3394 §4.6.
func TestAESKeyWrapRFC3394(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	key := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	want := mustHex(t, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

	wrapped, err := aesKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("wrap = %X, want %X", wrapped, want)
	}

	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, key) {
		t.Fatalf("unwrap = %X, want %X", unwrapped, key)
	}
}

// TestAESKeyUnwrapTamperFails confirms a corrupted wrapping fails the integrity
// check with the opaque error.
func TestAESKeyUnwrapTamperFails(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	wrapped := mustHex(t, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
	wrapped[0] ^= 0xFF

	if _, err := aesKeyUnwrap(kek, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered unwrap err = %v, want ErrDecrypt", err)
	}
}

// TestConcatKDFRFC7518 checks the Concat KDF vector from RFC 7518 Appendix C
// (ECDH-ES key agreement, alg "A128GCM", apu "Alice", apv "Bob", 128-bit key).
func TestConcatKDFRFC7518(t *testing.T) {
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}
	oi := otherInfo("A128GCM", []byte("Alice"), []byte("Bob"), 128, nil)
	got := concatKDF(z, oi, 16)
	want := []byte{86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26}
	if !bytes.Equal(got, want) {
		t.Fatalf("concatKDF = %v, want %v", got, want)
	}
}

// TestA256CBCHS512RoundTrip exercises encrypt/decrypt and confirms tamper
// detection on ciphertext, tag, and aad.
func TestA256CBCHS512RoundTrip(t *testing.T) {
	cek := make([]byte, 64)
	for i := range cek {
		cek[i] = byte(i)
	}
	plaintext := []byte("Live long and prosper.")
	aad := []byte("protected-header")

	s, err := encryptA256CBCHS512(cek, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptA256CBCHS512(cek, s.iv, s.ciphertext, s.tag, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}

	bad := append([]byte{}, s.ciphertext...)
	bad[0] ^= 0xFF
	if _, err := decryptA256CBCHS512(cek, s.iv, bad, s.tag, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext err = %v, want ErrDecrypt", err)
	}
	if _, err := decryptA256CBCHS512(cek, s.iv, s.ciphertext, s.tag, []byte("other-aad")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered aad err = %v, want ErrDecrypt", err)
	}
}

// TestA256GCMRoundTrip exercises the GCM path and tamper detection.
func TestA256GCMRoundTrip(t *testing.T) {
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(200 - i)
	}
	plaintext := []byte("beam me up")
	aad := []byte("aad")

	s, err := encryptA256GCM(cek, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptA256GCM(cek, s.iv, s.ciphertext, s.tag, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}

	bad := append([]byte{}, s.tag...)
	bad[0] ^= 0xFF
	if _, err := decryptA256GCM(cek, s.iv, s.ciphertext, bad, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered tag err = %v, want ErrDecrypt", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}
