package didcomm

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestAnoncryptAndDecrypt(t *testing.T) {
	// Generate recipient key pair
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		ID:   "1",
		Type: "https://example.com/test",
		Body: json.RawMessage(`{"hello":"world"}`),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Get Bob's public encryption key
	encPubJWK, err := bobKP.EncryptionPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt for Bob
	encrypted, err := anoncrypt(payload, []jwk.Key{encPubJWK})
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted) == 0 {
		t.Fatal("encrypted message should not be empty")
	}

	// Decrypt with Bob's private key
	decrypted, err := anonDecrypt(encrypted, bobKP.EncryptionJWK)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := json.Unmarshal(decrypted, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ID != "1" {
		t.Fatalf("expected ID=1, got %s", decoded.ID)
	}
}

func TestAnoncrypt_NoRecipients(t *testing.T) {
	_, err := anoncrypt([]byte(`{}`), nil)
	if err != ErrNoRecipients {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestAnoncrypt_MultipleRecipients(t *testing.T) {
	_, bob1KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob2KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	bob1PubJWK, _ := bob1KP.EncryptionPublicJWK()
	bob2PubJWK, _ := bob2KP.EncryptionPublicJWK()

	payload := []byte(`{"id":"1","type":"test","body":{}}`)

	encrypted, err := anoncrypt(payload, []jwk.Key{bob1PubJWK, bob2PubJWK})
	if err != nil {
		t.Fatal(err)
	}

	// Both recipients should be able to decrypt
	dec1, err := anonDecrypt(encrypted, bob1KP.EncryptionJWK)
	if err != nil {
		t.Fatal("bob1 should be able to decrypt:", err)
	}
	if string(dec1) != string(payload) {
		t.Fatal("bob1 decrypted payload mismatch")
	}

	dec2, err := anonDecrypt(encrypted, bob2KP.EncryptionJWK)
	if err != nil {
		t.Fatal("bob2 should be able to decrypt:", err)
	}
	if string(dec2) != string(payload) {
		t.Fatal("bob2 decrypted payload mismatch")
	}
}

func TestAnonDecrypt_WrongKey(t *testing.T) {
	_, bob1KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob2KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	bob1PubJWK, _ := bob1KP.EncryptionPublicJWK()

	encrypted, err := anoncrypt([]byte(`{}`), []jwk.Key{bob1PubJWK})
	if err != nil {
		t.Fatal(err)
	}

	_, err = anonDecrypt(encrypted, bob2KP.EncryptionJWK)
	if err == nil {
		t.Fatal("decryption should fail with wrong key")
	}
}

func TestAnoncrypt_Headers(t *testing.T) {
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	encPubJWK, _ := bobKP.EncryptionPublicJWK()

	encrypted, err := anoncrypt([]byte(`{}`), []jwk.Key{encPubJWK})
	if err != nil {
		t.Fatal(err)
	}

	hdrs, err := parseJWEHeaders(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	typ, ok := hdrs.Type()
	if !ok || typ != "application/didcomm-encrypted+json" {
		t.Fatalf("expected DIDComm encrypted type, got %v", typ)
	}
}

func TestComputeAPV(t *testing.T) {
	k1, err := jwk.Import([]byte("key1-material-32bytes-padding!!"))
	if err != nil {
		t.Fatal(err)
	}
	_ = k1.Set(jwk.KeyIDKey, "kid-b")

	k2, err := jwk.Import([]byte("key2-material-32bytes-padding!!"))
	if err != nil {
		t.Fatal(err)
	}
	_ = k2.Set(jwk.KeyIDKey, "kid-a")

	apv1, err := computeAPV([]jwk.Key{k1, k2})
	if err != nil {
		t.Fatal(err)
	}

	// Order shouldn't matter — kids are sorted
	apv2, err := computeAPV([]jwk.Key{k2, k1})
	if err != nil {
		t.Fatal(err)
	}

	if string(apv1) != string(apv2) {
		t.Fatal("APV should be deterministic regardless of key order")
	}
}
