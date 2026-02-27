package didcomm

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestAuthcryptRoundTrip(t *testing.T) {
	// Generate Alice (sender) and Bob (recipient)
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		ID:   "msg-1",
		Type: "https://example.com/test",
		Body: json.RawMessage(`{"hello":"world"}`),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Get Bob's public encryption key
	bobEncPub, err := bobKP.EncryptionPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	// Authcrypt: sign with Alice, encrypt for Bob
	encrypted, err := authcrypt(payload, aliceKP.SigningJWK, []jwk.Key{bobEncPub})
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

	// The decrypted content is a JWS — verify it with Alice's public key
	aliceSigPub, err := aliceKP.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifySignature(decrypted, aliceSigPub)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := json.Unmarshal(verified, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "msg-1" {
		t.Fatalf("expected ID=msg-1, got %s", decoded.ID)
	}
}

func TestAuthcrypt_WrongSenderKey(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, eveKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	bobEncPub, _ := bobKP.EncryptionPublicJWK()
	encrypted, err := authcrypt([]byte(`{"id":"1","type":"t","body":{}}`), aliceKP.SigningJWK, []jwk.Key{bobEncPub})
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with Bob's key
	decrypted, err := anonDecrypt(encrypted, bobKP.EncryptionJWK)
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify with Eve's key — should fail
	eveSigPub, _ := eveKP.SigningPublicJWK()
	_, err = verifySignature(decrypted, eveSigPub)
	if err == nil {
		t.Fatal("verification should fail with wrong sender key")
	}
}

func TestAuthcrypt_WrongRecipientKey(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, eveKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	bobEncPub, _ := bobKP.EncryptionPublicJWK()
	encrypted, err := authcrypt([]byte(`{"id":"1","type":"t","body":{}}`), aliceKP.SigningJWK, []jwk.Key{bobEncPub})
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with Eve's key — should fail
	_, err = anonDecrypt(encrypted, eveKP.EncryptionJWK)
	if err == nil {
		t.Fatal("decryption should fail with wrong recipient key")
	}
}

func TestAuthcrypt_NoRecipients(t *testing.T) {
	_, aliceKP, _ := GenerateDIDKey()
	_, err := authcrypt([]byte(`{}`), aliceKP.SigningJWK, nil)
	if !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestAuthcrypt_MultipleRecipients(t *testing.T) {
	_, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob1KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	_, bob2KP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	bob1EncPub, _ := bob1KP.EncryptionPublicJWK()
	bob2EncPub, _ := bob2KP.EncryptionPublicJWK()

	payload := []byte(`{"id":"1","type":"t","body":{}}`)
	encrypted, err := authcrypt(payload, aliceKP.SigningJWK, []jwk.Key{bob1EncPub, bob2EncPub})
	if err != nil {
		t.Fatal(err)
	}

	aliceSigPub, _ := aliceKP.SigningPublicJWK()

	// Both should be able to decrypt and verify
	dec1, err := anonDecrypt(encrypted, bob1KP.EncryptionJWK)
	if err != nil {
		t.Fatal("bob1 should be able to decrypt:", err)
	}
	verified1, err := verifySignature(dec1, aliceSigPub)
	if err != nil {
		t.Fatal("bob1 should be able to verify:", err)
	}

	var msg1 Message
	if unmarshalErr := json.Unmarshal(verified1, &msg1); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if msg1.ID != "1" {
		t.Fatalf("bob1: expected ID=1, got %s", msg1.ID)
	}

	dec2, err := anonDecrypt(encrypted, bob2KP.EncryptionJWK)
	if err != nil {
		t.Fatal("bob2 should be able to decrypt:", err)
	}
	verified2, err := verifySignature(dec2, aliceSigPub)
	if err != nil {
		t.Fatal("bob2 should be able to verify:", err)
	}

	var msg2 Message
	if err := json.Unmarshal(verified2, &msg2); err != nil {
		t.Fatal(err)
	}
	if msg2.ID != "1" {
		t.Fatalf("bob2: expected ID=1, got %s", msg2.ID)
	}
}
