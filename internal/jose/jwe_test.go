package jose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

// TestEnvelopeRoundTrip exercises the full JWE build/parse/open path for every
// supported profile and serialization, using real X25519 to produce the ECDH
// shared secrets the way the client layer will.
func TestEnvelopeRoundTrip(t *testing.T) {
	senderPriv := newX25519(t)
	recipPriv := newX25519(t)
	plaintext := []byte(`{"id":"1","type":"test","body":{}}`)

	cases := []struct {
		name      string
		alg       KeyWrapAlgorithm
		enc       ContentEncryption
		serial    Serialization
		bindTag   bool
		authcrypt bool
	}{
		{"ecdh-es anoncrypt A256CBC general", AlgECDHESA256KW, EncA256CBCHS512, GeneralJSON, false, false},
		{"ecdh-es anoncrypt A256GCM compact", AlgECDHESA256KW, EncA256GCM, Compact, false, false},
		{"1pu v3 A256GCM general", AlgECDH1PUA256KW, EncA256GCM, GeneralJSON, false, true},
		{"1pu v3 A256CBC compact", AlgECDH1PUA256KW, EncA256CBCHS512, Compact, false, true},
		{"1pu v4 A256CBC general", AlgECDH1PUA256KW, EncA256CBCHS512, GeneralJSON, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eph := newX25519(t)
			ze := ecdhShared(t, eph, recipPriv.PublicKey())
			z := ze
			senderKID := ""
			if tc.authcrypt {
				zs := ecdhShared(t, senderPriv, recipPriv.PublicKey())
				z = append(append([]byte{}, ze...), zs...)
				senderKID = "did:example:sender#key"
			}

			env, err := Encrypt(&EncryptRequest{
				Enc: tc.enc, Alg: tc.alg, Serialization: tc.serial,
				Typ: "application/didcomm-encrypted+json", SenderKID: senderKID,
				EphemeralPub: eph.PublicKey().Bytes(), BindTag: tc.bindTag,
				Plaintext:  plaintext,
				Recipients: []Recipient{{KID: "did:example:recip#key", Z: z}},
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			p, err := Parse(env)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.Header.Alg != tc.alg || p.Header.Enc != tc.enc {
				t.Fatalf("header alg/enc = %s/%s, want %s/%s", p.Header.Alg, p.Header.Enc, tc.alg, tc.enc)
			}
			if p.Recipients[0].KID != "did:example:recip#key" {
				t.Fatalf("recipient kid = %q", p.Recipients[0].KID)
			}

			// Recompute z from the recipient's perspective.
			ephPub, err := ecdh.X25519().NewPublicKey(mustDecode(t, p.Header.EPK.X))
			if err != nil {
				t.Fatalf("epk: %v", err)
			}
			openZ := ecdhShared(t, recipPriv, ephPub)
			if tc.authcrypt {
				zs := ecdhShared(t, recipPriv, senderPriv.PublicKey())
				openZ = append(append([]byte{}, openZ...), zs...)
			}

			got, err := OpenRecipient(p, p.Recipients[0].EncryptedKey, openZ, tc.bindTag)
			if err != nil {
				t.Fatalf("OpenRecipient: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}

			// Wrong z must fail closed with the opaque error.
			wrong := make([]byte, len(openZ))
			if _, err := OpenRecipient(p, p.Recipients[0].EncryptedKey, wrong, tc.bindTag); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("wrong-z err = %v, want ErrDecrypt", err)
			}
		})
	}
}

func newX25519(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen x25519: %v", err)
	}
	return k
}

func ecdhShared(t *testing.T, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) []byte {
	t.Helper()
	s, err := priv.ECDH(pub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return s
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 %q: %v", s, err)
	}
	return b
}
