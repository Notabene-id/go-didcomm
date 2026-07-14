package jose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
)

// aesCBCBlockSize is the AES block size used for PKCS#7 padding in
// A256CBC-HS512.
const aesCBCBlockSize = 16

// sealed is the output of content encryption: the initialisation vector, the
// ciphertext, and the authentication tag.
type sealed struct {
	iv         []byte
	ciphertext []byte
	tag        []byte
}

// encryptContent encrypts plaintext under cek for enc, binding aad into the
// authentication tag. cek must be the size enc requires.
func encryptContent(enc ContentEncryption, cek, plaintext, aad []byte) (sealed, error) {
	switch enc {
	case EncA256CBCHS512:
		return encryptA256CBCHS512(cek, plaintext, aad)
	case EncA256GCM:
		return encryptA256GCM(cek, plaintext, aad)
	default:
		return sealed{}, ErrMalformed
	}
}

// decryptContent verifies the tag and decrypts under cek for enc. Every failure
// returns ErrDecrypt with no detail.
func decryptContent(enc ContentEncryption, cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	switch enc {
	case EncA256CBCHS512:
		return decryptA256CBCHS512(cek, iv, ciphertext, tag, aad)
	case EncA256GCM:
		return decryptA256GCM(cek, iv, ciphertext, tag, aad)
	case EncXC20P:
		return decryptXC20P(cek, iv, ciphertext, tag, aad)
	default:
		return nil, ErrDecrypt
	}
}

// encryptA256CBCHS512 implements RFC 7518 §5.2.6 (AES-256-CBC + HMAC-SHA-512,
// tag truncated to 256 bits). The 64-byte cek splits into a leading MAC key and
// a trailing encryption key.
func encryptA256CBCHS512(cek, plaintext, aad []byte) (sealed, error) {
	if len(cek) != 64 {
		return sealed{}, ErrInvalidKeySize
	}
	macKey, encKey := cek[:32], cek[32:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return sealed{}, ErrInvalidKeySize
	}
	iv := make([]byte, aesCBCBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return sealed{}, err
	}

	padded := pkcs7Pad(plaintext)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	tag := cbcHMACTag(macKey, aad, iv, ciphertext)
	return sealed{iv: iv, ciphertext: ciphertext, tag: tag}, nil
}

// decryptA256CBCHS512 verifies the HMAC in constant time BEFORE touching the
// ciphertext, so a padding oracle is unreachable.
func decryptA256CBCHS512(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(cek) != 64 || len(iv) != aesCBCBlockSize ||
		len(ciphertext) == 0 || len(ciphertext)%aesCBCBlockSize != 0 {
		return nil, ErrDecrypt
	}
	macKey, encKey := cek[:32], cek[32:]

	expected := cbcHMACTag(macKey, aad, iv, ciphertext)
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		return nil, ErrDecrypt
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)

	plaintext, ok := pkcs7Unpad(padded)
	if !ok {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// cbcHMACTag computes the RFC 7518 §5.2.2 authentication tag: the leading half
// of HMAC-SHA-512 over aad || iv || ciphertext || AL, where AL is the aad length
// in bits as a big-endian 64-bit integer.
func cbcHMACTag(macKey, aad, iv, ciphertext []byte) []byte {
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad))*8)

	mac := hmac.New(sha512.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al[:])
	return mac.Sum(nil)[:32]
}

// encryptA256GCM implements RFC 7518 §5.3 (AES-256-GCM, 96-bit IV, 128-bit tag).
func encryptA256GCM(cek, plaintext, aad []byte) (sealed, error) {
	if len(cek) != 32 {
		return sealed{}, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return sealed{}, ErrInvalidKeySize
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return sealed{}, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return sealed{}, err
	}

	out := gcm.Seal(nil, iv, plaintext, aad)
	tagOffset := len(out) - gcm.Overhead()
	return sealed{iv: iv, ciphertext: out[:tagOffset], tag: out[tagOffset:]}, nil
}

// decryptA256GCM verifies and decrypts an AES-256-GCM ciphertext.
func decryptA256GCM(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(cek) != 32 {
		return nil, ErrDecrypt
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		return nil, ErrDecrypt
	}
	plaintext, err := gcm.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// pkcs7Pad appends PKCS#7 padding to a full AES block boundary.
func pkcs7Pad(data []byte) []byte {
	pad := aesCBCBlockSize - len(data)%aesCBCBlockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes PKCS#7 padding. It reports ok=false for malformed padding;
// callers map that to the single opaque decryption error.
func pkcs7Unpad(data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data)%aesCBCBlockSize != 0 {
		return nil, false
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aesCBCBlockSize || pad > len(data) {
		return nil, false
	}
	good := 1
	for i := len(data) - pad; i < len(data); i++ {
		good &= subtle.ConstantTimeByteEq(data[i], byte(pad))
	}
	if good != 1 {
		return nil, false
	}
	return data[:len(data)-pad], true
}
