package didcomm

import (
	"encoding/base64"
	"testing"

	"github.com/notabene-id/go-didcomm/internal/jose"
)

// TestDIDCommAPVKnownAnswer pins the apv derivation to values computed
// independently (SHA-256 of the "."-joined, alphanumerically sorted recipient
// kids, base64url no padding). This is the algorithm every DIDComm v2 peer must
// agree on, so a change here is a wire-breaking change.
func TestDIDCommAPVKnownAnswer(t *testing.T) {
	b64 := base64.RawURLEncoding

	// Two recipients, deliberately supplied out of order to prove sorting.
	got := b64.EncodeToString(didcommAPV([]string{
		"did:example:bob#key-2", "did:example:bob#key-1",
	}))
	const wantTwo = "rvPFG3poRc4q7DEnyfAjWjMZq4jLbATHMlnSeVP3rgM"
	if got != wantTwo {
		t.Fatalf("apv(two) = %q, want %q", got, wantTwo)
	}

	gotOne := b64.EncodeToString(didcommAPV([]string{"did:example:alice#key-x25519-1"}))
	const wantOne = "zBws6db1_Df8dwa133tyRObyx1D_qqCvNbKdjMK9ZEQ"
	if gotOne != wantOne {
		t.Fatalf("apv(one) = %q, want %q", gotOne, wantOne)
	}
}

// TestValidKDFHeaders isolates the inbound binding check: apv MUST hash the
// actual recipient set (both modes), and apu MUST equal base64url(skid) for
// authcrypt. It verifies the check independently of decryption, which also
// covers these fields via the AAD.
func TestValidKDFHeaders(t *testing.T) {
	b64 := base64.RawURLEncoding
	kids := []string{"did:example:bob#k"}
	goodAPV := b64.EncodeToString(didcommAPV(kids))

	mk := func(apv, apu, skid string) *jose.ParsedJWE {
		return &jose.ParsedJWE{
			Header:     jose.Header{APV: apv, APU: apu, SKID: skid},
			Recipients: []jose.ParsedRecipient{{KID: kids[0]}},
		}
	}

	// Anoncrypt: apv required and must match; apu is ignored.
	if !validKDFHeaders(mk(goodAPV, "", ""), false) {
		t.Fatal("valid anoncrypt headers rejected")
	}
	if validKDFHeaders(mk("", "", ""), false) {
		t.Fatal("missing apv accepted")
	}
	if validKDFHeaders(mk("wrong", "", ""), false) {
		t.Fatal("wrong apv accepted")
	}

	// Authcrypt: apu must equal base64url(skid).
	skid := "did:example:alice#k"
	goodAPU := b64.EncodeToString([]byte(skid))
	if !validKDFHeaders(mk(goodAPV, goodAPU, skid), true) {
		t.Fatal("valid authcrypt headers rejected")
	}
	if validKDFHeaders(mk(goodAPV, "", skid), true) {
		t.Fatal("missing apu accepted")
	}
	if validKDFHeaders(mk(goodAPV, "wrong", skid), true) {
		t.Fatal("apu not matching skid accepted")
	}
}
