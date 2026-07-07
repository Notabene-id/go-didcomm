package didcomm

import (
	"encoding/json"
	"testing"

	"github.com/mr-tron/base58"
)

// TestVerificationMethodBase58 confirms legacy base58 key encodings parse into
// usable public keys, matching what older DIDComm v2 nodes publish.
func TestVerificationMethodBase58(t *testing.T) {
	_, km, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	// Recover the raw Ed25519 public key from the generated did:key.
	resolved, err := (&DIDKeyResolver{}).Resolve(nil, km.DID) //nolint:staticcheck // nil ctx ok for local decode
	if err != nil {
		t.Fatal(err)
	}
	edPub, err := json.Marshal(resolved.Authentication[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var jwkParts struct {
		X string `json:"x"`
	}
	if err = json.Unmarshal(edPub, &jwkParts); err != nil {
		t.Fatal(err)
	}
	rawEd, err := b64.DecodeString(jwkParts.X)
	if err != nil {
		t.Fatal(err)
	}

	doc := `{
		"id": "did:web:legacy.example",
		"authentication": [{
			"id": "did:web:legacy.example#key-1",
			"type": "Ed25519VerificationKey2018",
			"controller": "did:web:legacy.example",
			"publicKeyBase58": "` + base58.Encode(rawEd) + `"
		}]
	}`

	var parsed DIDDocument
	if err = json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("unmarshal base58 doc: %v", err)
	}
	if parsed.Authentication[0].PublicKey == nil {
		t.Fatal("base58 public key did not parse into a JWK")
	}
	vm, err := parsed.signingKey("did:web:legacy.example#key-1")
	if err != nil {
		t.Fatalf("signing key lookup: %v", err)
	}
	if vm.PublicKey == nil {
		t.Fatal("expected non-nil signing key")
	}
}

// TestVerificationMethodMultibase confirms publicKeyMultibase (2020 key types)
// decodes via its multicodec prefix.
func TestVerificationMethodMultibase(t *testing.T) {
	doc, _, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	// A did:key fragment is exactly the multibase multicodec form we accept.
	fragment := doc.KeyAgreement[0].ID[len(doc.ID)+1:] // strip "<did>#"

	in := `{
		"id": "did:web:mb.example",
		"keyAgreement": [{
			"id": "did:web:mb.example#kex",
			"type": "X25519KeyAgreementKey2020",
			"publicKeyMultibase": "` + fragment + `"
		}]
	}`
	var parsed DIDDocument
	if err := json.Unmarshal([]byte(in), &parsed); err != nil {
		t.Fatalf("unmarshal multibase doc: %v", err)
	}
	if parsed.KeyAgreement[0].PublicKey == nil {
		t.Fatal("multibase public key did not parse")
	}
	if _, err := x25519PublicBytes(parsed.KeyAgreement[0].PublicKey); err != nil {
		t.Fatalf("multibase key not usable as X25519: %v", err)
	}
}

func TestVerificationMethodRejectsBadBase58(t *testing.T) {
	doc := `{"id":"did:web:x","authentication":[{"id":"did:web:x#k",` +
		`"type":"Ed25519VerificationKey2018","publicKeyBase58":"!!!notbase58!!!"}]}`
	var parsed DIDDocument
	if err := json.Unmarshal([]byte(doc), &parsed); err == nil {
		t.Fatal("expected error for invalid base58")
	}
}
