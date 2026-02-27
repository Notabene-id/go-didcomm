package didcomm

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = kp.SigningJWK.Set(jwk.KeyIDKey, "test-key-1")

	msg := &Message{
		ID:   "1",
		Type: "https://example.com/test",
		Body: json.RawMessage(`{"hello":"world"}`),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := signMessage(payload, kp.SigningJWK)
	if err != nil {
		t.Fatal(err)
	}

	if len(signed) == 0 {
		t.Fatal("signed message should not be empty")
	}

	pubJWK, err := kp.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifySignature(signed, pubJWK)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := json.Unmarshal(verified, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ID != "1" {
		t.Fatalf("expected ID=1, got %s", decoded.ID)
	}
}

func TestSignMessage_IncludesHeaders(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = kp.SigningJWK.Set(jwk.KeyIDKey, "test-key-1")

	signed, err := signMessage([]byte(`{}`), kp.SigningJWK)
	if err != nil {
		t.Fatal(err)
	}

	hdrs, err := parseJWSHeaders(signed)
	if err != nil {
		t.Fatal(err)
	}

	alg, _ := hdrs.Algorithm()
	if alg != jwa.EdDSA() {
		t.Fatalf("expected EdDSA algorithm, got %s", alg)
	}

	kid, ok := hdrs.KeyID()
	if !ok || kid != "test-key-1" {
		t.Fatalf("expected kid=test-key-1, got %s", kid)
	}

	typ, ok := hdrs.Type()
	if !ok || typ != "application/didcomm-signed+json" {
		t.Fatalf("expected DIDComm signed type, got %s", typ)
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := signMessage([]byte(`{}`), kp1.SigningJWK)
	if err != nil {
		t.Fatal(err)
	}

	wrongPubJWK, err := kp2.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifySignature(signed, wrongPubJWK)
	if err == nil {
		t.Fatal("verification should fail with wrong key")
	}
}

func TestParseJWSHeaders(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := signMessage([]byte(`{}`), kp.SigningJWK)
	if err != nil {
		t.Fatal(err)
	}

	hdrs, err := parseJWSHeaders(signed)
	if err != nil {
		t.Fatal(err)
	}
	if hdrs == nil {
		t.Fatal("headers should not be nil")
	}
}

func TestParseJWSHeaders_InvalidJWS(t *testing.T) {
	_, err := parseJWSHeaders([]byte("not-a-jws"))
	if err == nil {
		t.Fatal("should fail on invalid JWS")
	}
}
