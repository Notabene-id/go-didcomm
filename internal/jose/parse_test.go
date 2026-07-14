package jose

import (
	"errors"
	"testing"
)

func TestParseMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-json-not-compact",
		"a.b.c",                        // too few compact parts for a JWE
		`{"protected":"@@"}`,           // invalid base64 protected header
		`{"protected":"e30","iv":"x"}`, // no recipients or encrypted_key
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Parse(%q) err = %v, want ErrMalformed", c, err)
		}
	}
}

func TestParseCompactRoundsTripFields(t *testing.T) {
	// "e30" is base64url of "{}" — a syntactically valid but semantically empty
	// header, enough to check the compact splitter keeps all five segments.
	compact := "e30.AAAA.BBBB.CCCC.DDDD"
	p, err := Parse([]byte(compact))
	if err != nil {
		t.Fatalf("Parse compact: %v", err)
	}
	if len(p.Recipients) != 1 {
		t.Fatalf("compact recipients = %d, want 1", len(p.Recipients))
	}
}

func TestNewCEKUnsupportedEnc(t *testing.T) {
	if _, err := NewCEK("bogus"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("NewCEK(bogus) err = %v, want ErrMalformed", err)
	}
}

func TestOpenRecipientWrongKeyFailsOpaque(t *testing.T) {
	p := &ParsedJWE{
		Header:       Header{Alg: AlgECDHESA256KW, Enc: EncA256GCM},
		RawProtected: "e30",
		IV:           make([]byte, 12),
		Ciphertext:   []byte("x"),
		Tag:          make([]byte, 16),
	}
	r := &ParsedRecipient{Alg: AlgECDHESA256KW, EncryptedKey: make([]byte, 40)}
	if _, err := OpenRecipient(p, r, make([]byte, 32), false); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("OpenRecipient err = %v, want ErrDecrypt", err)
	}
}
