package didcomm

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestAuthcryptRoundTrip(t *testing.T) {
	// Generate Alice (sender) and Bob (recipient)
	aliceDoc, aliceKP, err := GenerateDIDKey()
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
		From: aliceDoc.ID,
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

	// Get Alice's public signing key for verification
	aliceSigPub, err := aliceKP.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt and verify
	decrypted, skid, err := authDecrypt(encrypted, bobKP.EncryptionJWK, aliceSigPub)
	if err != nil {
		t.Fatal(err)
	}

	// Verify skid
	aliceKID, _ := aliceKP.SigningJWK.KeyID()
	if skid != aliceKID {
		t.Fatalf("expected skid=%s, got %s", aliceKID, skid)
	}

	// Verify payload
	var decoded Message
	if err := json.Unmarshal(decrypted, &decoded); err != nil {
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

	// Try to verify with Eve's key — should fail
	eveSigPub, _ := eveKP.SigningPublicJWK()
	_, _, err = authDecrypt(encrypted, bobKP.EncryptionJWK, eveSigPub)
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
	aliceSigPub, _ := aliceKP.SigningPublicJWK()
	_, _, err = authDecrypt(encrypted, eveKP.EncryptionJWK, aliceSigPub)
	if err == nil {
		t.Fatal("decryption should fail with wrong recipient key")
	}
}

func TestAuthcrypt_NoRecipients(t *testing.T) {
	_, aliceKP, _ := GenerateDIDKey()
	_, err := authcrypt([]byte(`{}`), aliceKP.SigningJWK, nil)
	if err != ErrNoRecipients {
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
	dec1, _, err := authDecrypt(encrypted, bob1KP.EncryptionJWK, aliceSigPub)
	if err != nil {
		t.Fatal("bob1 should be able to decrypt:", err)
	}

	var msg1 Message
	if err := json.Unmarshal(dec1, &msg1); err != nil {
		t.Fatal(err)
	}
	if msg1.ID != "1" {
		t.Fatalf("bob1: expected ID=1, got %s", msg1.ID)
	}

	dec2, _, err := authDecrypt(encrypted, bob2KP.EncryptionJWK, aliceSigPub)
	if err != nil {
		t.Fatal("bob2 should be able to decrypt:", err)
	}

	var msg2 Message
	if err := json.Unmarshal(dec2, &msg2); err != nil {
		t.Fatal(err)
	}
	if msg2.ID != "1" {
		t.Fatalf("bob2: expected ID=1, got %s", msg2.ID)
	}
}
