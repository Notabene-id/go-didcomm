package didcomm

import (
	"crypto/ed25519"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if len(kp.signingPrivate) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PrivateKeySize, len(kp.signingPrivate))
	}
	if len(kp.signingPublic) != ed25519.PublicKeySize {
		t.Fatalf("expected %d bytes, got %d", ed25519.PublicKeySize, len(kp.signingPublic))
	}
	if kp.encryptionPrivate == nil {
		t.Fatal("encryption private key should not be nil")
	}
	if kp.encryptionPublic == nil {
		t.Fatal("encryption public key should not be nil")
	}
	if kp.SigningJWK == nil {
		t.Fatal("signing JWK should not be nil")
	}
	if kp.EncryptionJWK == nil {
		t.Fatal("encryption JWK should not be nil")
	}
}

func TestGenerateKeyPair_UniqueKeys(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if kp1.signingPublic.Equal(kp2.signingPublic) {
		t.Fatal("generated keys should be unique")
	}
}

func TestKeyPair_SigningPublicJWK(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubJWK, err := kp.SigningPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	kty := pubJWK.KeyType()
	if kty.String() != "OKP" {
		t.Fatalf("expected OKP key type, got %s", kty)
	}

	// Should not contain private key material
	var raw interface{}
	if err := jwk.Export(pubJWK, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.(ed25519.PublicKey); !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", raw)
	}
}

func TestKeyPair_EncryptionPublicJWK(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubJWK, err := kp.EncryptionPublicJWK()
	if err != nil {
		t.Fatal(err)
	}

	kty := pubJWK.KeyType()
	if kty.String() != "OKP" {
		t.Fatalf("expected OKP key type, got %s", kty)
	}
}

func TestKeyPair_JWKAlgorithms(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sigAlg, ok := kp.SigningJWK.Algorithm()
	if !ok {
		t.Fatal("signing JWK should have algorithm set")
	}
	if sigAlg.String() != "EdDSA" {
		t.Fatalf("expected EdDSA algorithm, got %s", sigAlg)
	}

	encAlg, ok := kp.EncryptionJWK.Algorithm()
	if !ok {
		t.Fatal("encryption JWK should have algorithm set")
	}
	if encAlg.String() != "ECDH-ES+A256KW" {
		t.Fatalf("expected ECDH-ES+A256KW algorithm, got %s", encAlg)
	}
}
