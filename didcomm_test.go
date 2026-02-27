package didcomm

import (
	"context"
	"encoding/json"
	"testing"
)

func setupAliceAndBob(t *testing.T) (aliceDoc *DIDDocument, aliceKP *KeyPair, bobDoc *DIDDocument, bobKP *KeyPair, client *Client) {
	t.Helper()

	resolver := NewResolver()
	secrets := NewInMemorySecretsStore()

	var err error
	aliceDoc, aliceKP, err = GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(aliceDoc)
	secrets.Store(aliceKP)

	bobDoc, bobKP, err = GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(bobDoc)
	secrets.Store(bobKP)

	client = NewClient(resolver, secrets)
	return
}

func TestClient_PackSigned_Unpack(t *testing.T) {
	aliceDoc, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	msg := &Message{
		ID:   "msg-1",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		Body: json.RawMessage(`{"hello":"world"}`),
	}

	packed, err := client.PackSigned(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.Unpack(ctx, packed)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Signed {
		t.Fatal("expected Signed=true")
	}
	if result.Encrypted {
		t.Fatal("expected Encrypted=false")
	}
	if result.Message.ID != "msg-1" {
		t.Fatalf("expected ID=msg-1, got %s", result.Message.ID)
	}
	if result.Message.Type != "https://example.com/test" {
		t.Fatalf("expected Type, got %s", result.Message.Type)
	}
}

func TestClient_PackAnoncrypt_Unpack(t *testing.T) {
	_, _, bobDoc, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	msg := &Message{
		ID:   "msg-2",
		Type: "https://example.com/test",
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"data":"secret"}`),
	}

	packed, err := client.PackAnoncrypt(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.Unpack(ctx, packed)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Encrypted {
		t.Fatal("expected Encrypted=true")
	}
	if !result.Anonymous {
		t.Fatal("expected Anonymous=true")
	}
	if result.Signed {
		t.Fatal("expected Signed=false")
	}
	if result.Message.ID != "msg-2" {
		t.Fatalf("expected ID=msg-2, got %s", result.Message.ID)
	}
}

func TestClient_PackAuthcrypt_Unpack(t *testing.T) {
	aliceDoc, _, bobDoc, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	msg := &Message{
		ID:   "msg-3",
		Type: "https://example.com/test",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"data":"authenticated"}`),
	}

	packed, err := client.PackAuthcrypt(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.Unpack(ctx, packed)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Encrypted {
		t.Fatal("expected Encrypted=true")
	}
	if result.Anonymous {
		t.Fatal("expected Anonymous=false for authcrypt")
	}
	if !result.Signed {
		t.Fatal("expected Signed=true for authcrypt")
	}
	if result.Message.ID != "msg-3" {
		t.Fatalf("expected ID=msg-3, got %s", result.Message.ID)
	}
}

func TestClient_Unpack_PlainJSON(t *testing.T) {
	_, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	plainMsg := `{"id":"msg-4","type":"https://example.com/test","body":{}}`

	result, err := client.Unpack(ctx, []byte(plainMsg))
	if err != nil {
		t.Fatal(err)
	}

	if result.Encrypted {
		t.Fatal("expected Encrypted=false")
	}
	if result.Signed {
		t.Fatal("expected Signed=false")
	}
	if result.Message.ID != "msg-4" {
		t.Fatalf("expected ID=msg-4, got %s", result.Message.ID)
	}
}

func TestClient_PackSigned_RequiresFrom(t *testing.T) {
	_, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	msg := &Message{
		ID:   "1",
		Type: "test",
		Body: json.RawMessage(`{}`),
	}

	_, err := client.PackSigned(ctx, msg)
	if err != ErrNoSender {
		t.Fatalf("expected ErrNoSender, got %v", err)
	}
}

func TestClient_PackAnoncrypt_RequiresTo(t *testing.T) {
	_, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	msg := &Message{
		ID:   "1",
		Type: "test",
		Body: json.RawMessage(`{}`),
	}

	_, err := client.PackAnoncrypt(ctx, msg)
	if err != ErrNoRecipients {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestClient_PackAuthcrypt_RequiresFromAndTo(t *testing.T) {
	aliceDoc, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	// Missing From
	msg1 := &Message{
		ID:   "1",
		Type: "test",
		To:   []string{"did:key:bob"},
		Body: json.RawMessage(`{}`),
	}
	_, err := client.PackAuthcrypt(ctx, msg1)
	if err != ErrNoSender {
		t.Fatalf("expected ErrNoSender, got %v", err)
	}

	// Missing To
	msg2 := &Message{
		ID:   "1",
		Type: "test",
		From: aliceDoc.ID,
		Body: json.RawMessage(`{}`),
	}
	_, err = client.PackAuthcrypt(ctx, msg2)
	if err != ErrNoRecipients {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestClient_Unpack_InvalidMessage(t *testing.T) {
	_, _, _, _, client := setupAliceAndBob(t)
	ctx := context.Background()

	_, err := client.Unpack(ctx, []byte("not valid at all"))
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

// Integration test: full Alice→Bob authcrypt round-trip
func TestIntegration_AuthcryptRoundTrip(t *testing.T) {
	resolver := NewResolver()
	aliceSecrets := NewInMemorySecretsStore()
	bobSecrets := NewInMemorySecretsStore()

	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(aliceDoc)
	aliceSecrets.Store(aliceKP)

	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(bobDoc)
	bobSecrets.Store(bobKP)

	aliceClient := NewClient(resolver, aliceSecrets)
	bobClient := NewClient(resolver, bobSecrets)

	ctx := context.Background()

	msg := &Message{
		ID:   "integration-1",
		Type: "https://example.com/protocols/ping/1.0/ping",
		From: aliceDoc.ID,
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"comment":"Hello Bob!"}`),
	}

	// Alice packs
	packed, err := aliceClient.PackAuthcrypt(ctx, msg)
	if err != nil {
		t.Fatal("Alice pack:", err)
	}

	// Bob unpacks
	result, err := bobClient.Unpack(ctx, packed)
	if err != nil {
		t.Fatal("Bob unpack:", err)
	}

	if !result.Encrypted {
		t.Fatal("should be encrypted")
	}
	if !result.Signed {
		t.Fatal("should be signed")
	}
	if result.Anonymous {
		t.Fatal("should not be anonymous")
	}
	if result.Message.ID != "integration-1" {
		t.Fatalf("message ID mismatch: %s", result.Message.ID)
	}
	if result.Message.From != aliceDoc.ID {
		t.Fatalf("from mismatch: %s", result.Message.From)
	}

	var body map[string]string
	if err := json.Unmarshal(result.Message.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["comment"] != "Hello Bob!" {
		t.Fatalf("body mismatch: %v", body)
	}
}

// Integration test: anoncrypt round-trip
func TestIntegration_AnoncryptRoundTrip(t *testing.T) {
	resolver := NewResolver()
	bobSecrets := NewInMemorySecretsStore()

	bobDoc, bobKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(bobDoc)
	bobSecrets.Store(bobKP)

	senderClient := NewClient(resolver, NewInMemorySecretsStore())
	bobClient := NewClient(resolver, bobSecrets)

	ctx := context.Background()

	msg := &Message{
		ID:   "anon-1",
		Type: "https://example.com/protocols/ping/1.0/ping",
		To:   []string{bobDoc.ID},
		Body: json.RawMessage(`{"anonymous":true}`),
	}

	packed, err := senderClient.PackAnoncrypt(ctx, msg)
	if err != nil {
		t.Fatal("pack:", err)
	}

	result, err := bobClient.Unpack(ctx, packed)
	if err != nil {
		t.Fatal("unpack:", err)
	}

	if !result.Encrypted {
		t.Fatal("should be encrypted")
	}
	if !result.Anonymous {
		t.Fatal("should be anonymous")
	}
	if result.Signed {
		t.Fatal("should not be signed")
	}
	if result.Message.ID != "anon-1" {
		t.Fatalf("message ID mismatch: %s", result.Message.ID)
	}
}

// Integration test: signed-only round-trip
func TestIntegration_SignedRoundTrip(t *testing.T) {
	resolver := NewResolver()
	aliceSecrets := NewInMemorySecretsStore()

	aliceDoc, aliceKP, err := GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver.Store(aliceDoc)
	aliceSecrets.Store(aliceKP)

	aliceClient := NewClient(resolver, aliceSecrets)
	verifierClient := NewClient(resolver, NewInMemorySecretsStore())

	ctx := context.Background()

	msg := &Message{
		ID:   "signed-1",
		Type: "https://example.com/protocols/ping/1.0/ping",
		From: aliceDoc.ID,
		Body: json.RawMessage(`{"signed":true}`),
	}

	packed, err := aliceClient.PackSigned(ctx, msg)
	if err != nil {
		t.Fatal("pack:", err)
	}

	result, err := verifierClient.Unpack(ctx, packed)
	if err != nil {
		t.Fatal("unpack:", err)
	}

	if result.Encrypted {
		t.Fatal("should not be encrypted")
	}
	if !result.Signed {
		t.Fatal("should be signed")
	}
	if result.Message.ID != "signed-1" {
		t.Fatalf("message ID mismatch: %s", result.Message.ID)
	}
}

func TestIsJWE(t *testing.T) {
	// Compact JWE has 5 parts (4 dots)
	if !isJWE([]byte("a.b.c.d.e")) {
		t.Fatal("should detect compact JWE")
	}
	// JSON JWE
	if !isJWE([]byte(`{"ciphertext":"abc","recipients":[]}`)) {
		t.Fatal("should detect JSON JWE")
	}
	// Not JWE
	if isJWE([]byte("a.b.c")) {
		t.Fatal("JWS should not be detected as JWE")
	}
	if isJWE([]byte(`{}`)) {
		t.Fatal("plain JSON should not be JWE")
	}
}

func TestIsJWS(t *testing.T) {
	if !isJWS([]byte("a.b.c")) {
		t.Fatal("should detect compact JWS")
	}
	if isJWS([]byte("a.b.c.d.e")) {
		t.Fatal("JWE should not be detected as JWS")
	}
}

func TestExtractDIDFromKID(t *testing.T) {
	tests := []struct {
		kid string
		did string
	}{
		{"did:key:z123#z456", "did:key:z123"},
		{"did:web:example.com:alice#key-1", "did:web:example.com:alice"},
		{"no-fragment", ""},
	}
	for _, tt := range tests {
		if got := extractDIDFromKID(tt.kid); got != tt.did {
			t.Errorf("extractDIDFromKID(%q) = %q, want %q", tt.kid, got, tt.did)
		}
	}
}
