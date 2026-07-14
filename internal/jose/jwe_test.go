package jose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
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

			got, err := OpenRecipient(p, &p.Recipients[0], openZ, tc.bindTag)
			if err != nil {
				t.Fatalf("OpenRecipient: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}

			// Wrong z must fail closed with the opaque error.
			wrong := make([]byte, len(openZ))
			if _, err := OpenRecipient(p, &p.Recipients[0], wrong, tc.bindTag); !errors.Is(err, ErrDecrypt) {
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

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestParsePerRecipientHeaderOverrides covers the per-recipient-header shape:
// alg/epk and the XC20PKW key-wrap iv/tag live in the per-recipient header, with
// only enc in the protected header. Parse must resolve them onto the recipient.
func TestParsePerRecipientHeaderOverrides(t *testing.T) {
	protected := b64.EncodeToString(mustJSON(t, Header{Enc: EncXC20P}))
	env := mustJSON(t, jweJSON{
		Protected: protected,
		Recipients: []recipientJSON{{
			Header: recipientHdr{
				KID: "did:example:recip#key",
				Alg: AlgECDH1PUXC20PKW,
				EPK: &EphemeralKey{Kty: keyTypeOKP, Crv: curveX25519, X: b64.EncodeToString(make([]byte, 32))},
				IV:  b64.EncodeToString(make([]byte, 24)),
				Tag: b64.EncodeToString(make([]byte, 16)),
			},
		}},
	})

	p, err := Parse(env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := p.Recipients[0]
	if r.Alg != AlgECDH1PUXC20PKW {
		t.Fatalf("alg = %q, want per-recipient override", r.Alg)
	}
	if r.EPK == nil || r.EPK.Crv != curveX25519 {
		t.Fatal("epk not resolved from per-recipient header")
	}
	if len(r.WrapIV) != 24 || len(r.WrapTag) != 16 {
		t.Fatalf("wrap iv/tag = %d/%d, want 24/16", len(r.WrapIV), len(r.WrapTag))
	}
	if r.KID != "did:example:recip#key" {
		t.Fatalf("kid = %q", r.KID)
	}
}

// TestParseProtectedHeaderInherited covers the protected-header shape: alg/epk in
// the protected header, a bare per-recipient header. Parse must inherit them, and
// an A256KW recipient carries no key-wrap iv/tag.
func TestParseProtectedHeaderInherited(t *testing.T) {
	protected := b64.EncodeToString(mustJSON(t, Header{
		Enc: EncA256GCM,
		Alg: AlgECDH1PUA256KW,
		EPK: &EphemeralKey{Kty: keyTypeOKP, Crv: curveX25519, X: b64.EncodeToString(make([]byte, 32))},
	}))
	env := mustJSON(t, jweJSON{
		Protected:  protected,
		Recipients: []recipientJSON{{Header: recipientHdr{KID: "did:example:recip#key"}}},
	})

	p, err := Parse(env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := p.Recipients[0]
	if r.Alg != AlgECDH1PUA256KW {
		t.Fatalf("alg = %q, want inherited from protected", r.Alg)
	}
	if r.EPK == nil {
		t.Fatal("epk not inherited from protected header")
	}
	if r.WrapIV != nil || r.WrapTag != nil {
		t.Fatal("A256KW recipient must carry no key-wrap iv/tag")
	}
}
