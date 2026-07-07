package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	didcomm "github.com/notabene-id/go-didcomm"
)

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`{"protected":"x","ciphertext":"y"}`, encryptedMedia},
		{`{"payload":"p","signature":"s"}`, signedMedia},
		{`{"id":"1","body":{}}`, plainMedia},
		{"a.b.c.d.e", encryptedMedia}, // compact JWE
		{"a.b.c", signedMedia},        // compact JWS
		{"garbage", plainMedia},
	}
	for _, tt := range tests {
		if got := detectContentType([]byte(tt.in)); got != tt.want {
			t.Fatalf("detectContentType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestGenerateIdentity(t *testing.T) {
	doc, km, err := generateIdentity("", "", "")
	if err != nil || doc == nil || km.DID != doc.ID {
		t.Fatalf("did:key generate: doc=%v km=%v err=%v", doc, km, err)
	}
	webDoc, _, err := generateIdentity("example.com", "alice", "https://example.com/didcomm")
	if err != nil {
		t.Fatalf("did:web generate: %v", err)
	}
	if webDoc.ID != "did:web:example.com:alice" || len(webDoc.Service) != 1 {
		t.Fatalf("did:web doc = %+v", webDoc)
	}
}

func TestReadInput(t *testing.T) {
	if got, _ := readInput(`{"inline":true}`); string(got) != `{"inline":true}` {
		t.Fatalf("inline = %q", got)
	}
	path := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(path, []byte(`{"file":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := readInput("@" + path); string(got) != `{"file":true}` {
		t.Fatalf("file = %q", got)
	}
}

// TestPackUnpackViaCLIHelpers exercises the generate -> write -> load -> pack ->
// unpack path through the command's own helper functions.
func TestPackUnpackViaCLIHelpers(t *testing.T) {
	dir := t.TempDir()
	aliceDir, bobDir := filepath.Join(dir, "alice"), filepath.Join(dir, "bob")
	alice := writeParty(t, aliceDir)
	bob := writeParty(t, bobDir)

	client, err := clientFor(filepath.Join(aliceDir, keysFile), false)
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	msg := &didcomm.Message{
		ID: "cli-1", Type: "t", From: alice.ID, To: []string{bob.ID}, Body: json.RawMessage(`{}`),
	}
	packed, err := client.Pack(context.Background(), msg, didcomm.WithProfile(didcomm.ProfileAuthcrypt1PUv3))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	bobClient, err := clientFor(filepath.Join(bobDir, keysFile), false)
	if err != nil {
		t.Fatal(err)
	}
	got, meta, err := bobClient.Unpack(context.Background(), packed)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if got.ID != "cli-1" || meta.SenderDID != alice.ID {
		t.Fatalf("round trip: id=%q sender=%q", got.ID, meta.SenderDID)
	}
}

func writeParty(t *testing.T, dir string) *didcomm.DIDDocument {
	t.Helper()
	doc, km, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	docJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIdentity(dir, docJSON, km); err != nil {
		t.Fatal(err)
	}
	return doc
}
