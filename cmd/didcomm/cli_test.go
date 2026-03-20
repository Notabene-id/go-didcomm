package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	didcomm "github.com/Notabene-id/go-didcomm"
)

// buildBinary compiles the CLI binary for testing.
func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "didcomm")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %s\n%s", err, out)
	}
	return binary
}

// generateIdentity creates a DID identity and writes files to dir.
func generateIdentity(t *testing.T, dir string) *didcomm.DIDDocument {
	t.Helper()
	doc, kp, err := didcomm.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}

	docBytes, err := marshalDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := marshalKeyPair(kp)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "did-doc.json"), docBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestCLI_DIDGenerateKey(t *testing.T) {
	bin := buildBinary(t)
	dir := filepath.Join(t.TempDir(), "out")

	cmd := exec.Command(bin, "did", "generate-key", "--output-dir", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s\n%s", err, out)
	}

	// Verify files exist
	_, statErr := os.Stat(filepath.Join(dir, "did-doc.json"))
	if statErr != nil {
		t.Fatal("did-doc.json not created")
	}
	_, statErr = os.Stat(filepath.Join(dir, "keys.json"))
	if statErr != nil {
		t.Fatal("keys.json not created")
	}

	// Verify DID document is valid
	data, _ := os.ReadFile(filepath.Join(dir, "did-doc.json"))
	doc, err := unmarshalDIDDoc(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.ID, "did:key:z") {
		t.Fatalf("expected did:key, got %s", doc.ID)
	}
}

func TestCLI_DIDGenerateKey_Stdout(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "did", "generate-key")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("command failed: %s", err)
	}

	var result generateOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON output: %s", err)
	}
	if len(result.DIDDocument) == 0 {
		t.Fatal("empty didDocument")
	}
	if len(result.Keys) == 0 {
		t.Fatal("empty keys")
	}
}

func TestCLI_DIDGenerateWeb(t *testing.T) {
	bin := buildBinary(t)
	dir := filepath.Join(t.TempDir(), "out")

	cmd := exec.Command(bin, "did", "generate-web",
		"--domain", "example.com",
		"--path", "users/alice",
		"--service-endpoint", "https://example.com/didcomm",
		"--output-dir", dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s\n%s", err, out)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "did-doc.json"))
	doc, err := unmarshalDIDDoc(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.ID != "did:web:example.com:users:alice" {
		t.Fatalf("expected did:web:example.com:users:alice, got %s", doc.ID)
	}
	if len(doc.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(doc.Service))
	}
	if doc.Service[0].ServiceEndpoint != "https://example.com/didcomm" {
		t.Fatalf("wrong service endpoint: %s", doc.Service[0].ServiceEndpoint)
	}
}

func TestCLI_DIDGenerateWeb_NoDomain(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "did", "generate-web")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when no domain specified")
	}
	if !strings.Contains(string(out), "--domain is required") {
		t.Fatalf("expected domain error, got: %s", out)
	}
}

func TestCLI_DIDResolve_Key(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	// Generate a did:key identity
	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)

	// Resolve the did:key (auto-resolution, no --did-doc needed)
	cmd := exec.Command(bin, "did", "resolve", aliceDoc.ID)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("command failed: %s", err)
	}

	var resolved didcomm.DIDDocument
	if err := json.Unmarshal(out, &resolved); err != nil {
		t.Fatalf("invalid JSON output: %s", err)
	}
	if resolved.ID != aliceDoc.ID {
		t.Fatalf("expected %s, got %s", aliceDoc.ID, resolved.ID)
	}
}

func TestCLI_DIDResolve_WithDIDDoc(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	// Generate a did:web identity (can't auto-resolve without a server)
	doc, kp, err := didcomm.GenerateDIDWeb("example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	docBytes, marshalErr := marshalDIDDoc(doc)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	_ = kp

	docFile := filepath.Join(dir, "did-doc.json")
	if writeErr := os.WriteFile(docFile, docBytes, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	// Resolve using --did-doc override
	cmd := exec.Command(bin, "did", "resolve", "--did-doc", docFile, doc.ID)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("command failed: %s", err)
	}

	var resolved didcomm.DIDDocument
	if err := json.Unmarshal(out, &resolved); err != nil {
		t.Fatalf("invalid JSON output: %s", err)
	}
	if resolved.ID != doc.ID {
		t.Fatalf("expected %s, got %s", doc.ID, resolved.ID)
	}
}

func TestCLI_DIDResolve_NoDID(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "did", "resolve")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when no DID specified")
	}
	if !strings.Contains(string(out), "usage:") {
		t.Fatalf("expected usage error, got: %s", out)
	}
}

func TestCLI_PackSigned_Unpack_RoundTrip(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)

	msg := `{"id":"1","type":"https://example.com/test","from":"` + aliceDoc.ID + `","body":{"hello":"world"}}`

	// Pack signed
	packCmd := exec.Command(bin, "pack", "signed",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", filepath.Join(aliceDir, "did-doc.json"),
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack signed failed: %s", err)
	}

	// Should be JWS (3 dot-separated parts)
	if strings.Count(string(packed), ".") != 2 {
		t.Fatalf("expected JWS compact, got: %s", string(packed)[:min(100, len(packed))])
	}

	// Unpack
	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", filepath.Join(aliceDir, "did-doc.json"),
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatalf("invalid unpack output: %s", err)
	}
	if !result.Signed {
		t.Fatal("expected signed=true")
	}
	if result.Encrypted {
		t.Fatal("expected encrypted=false")
	}
}

func TestCLI_PackAnoncrypt_Unpack_RoundTrip(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	bobDir := filepath.Join(dir, "bob")
	bobDoc := generateIdentity(t, bobDir)

	msg := `{"id":"2","type":"https://example.com/test","to":["` + bobDoc.ID + `"],"body":{"secret":"data"}}`

	// Pack anoncrypt
	packCmd := exec.Command(bin, "pack", "anoncrypt",
		"--did-doc", filepath.Join(bobDir, "did-doc.json"),
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack anoncrypt failed: %s", err)
	}

	// Unpack
	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(bobDir, "keys.json"),
		"--did-doc", filepath.Join(bobDir, "did-doc.json"),
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatalf("invalid unpack output: %s", err)
	}
	if !result.Encrypted {
		t.Fatal("expected encrypted=true")
	}
	if !result.Anonymous {
		t.Fatal("expected anonymous=true")
	}
	if result.Signed {
		t.Fatal("expected signed=false")
	}
}

func TestCLI_PackAuthcrypt_Unpack_RoundTrip(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)
	bobDir := filepath.Join(dir, "bob")
	bobDoc := generateIdentity(t, bobDir)

	didDocs := filepath.Join(aliceDir, "did-doc.json") + "," + filepath.Join(bobDir, "did-doc.json")

	msg := `{"id":"3","type":"https://example.com/test","from":"` + aliceDoc.ID + `","to":["` + bobDoc.ID + `"],"body":{"text":"hi"}}`

	// Pack authcrypt
	packCmd := exec.Command(bin, "pack", "authcrypt",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", didDocs,
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack authcrypt failed: %s", err)
	}

	// Unpack with bob's keys
	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(bobDir, "keys.json"),
		"--did-doc", didDocs,
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatalf("invalid unpack output: %s", err)
	}
	if !result.Encrypted {
		t.Fatal("expected encrypted=true")
	}
	if !result.Signed {
		t.Fatal("expected signed=true")
	}
	if result.Anonymous {
		t.Fatal("expected anonymous=false")
	}

	// Verify message content
	var innerMsg didcomm.Message
	if err := json.Unmarshal(result.Message, &innerMsg); err != nil {
		t.Fatal(err)
	}
	if innerMsg.ID != "3" {
		t.Fatalf("got message ID %s", innerMsg.ID)
	}
}

func TestCLI_Send(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	bin := buildBinary(t)
	cmd := exec.Command(bin, "send",
		"--to", server.URL,
		"--message", `{"id":"1","type":"test","body":{}}`,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("send failed: %s\n%s", err, out)
	}

	if receivedContentType != "application/didcomm-plain+json" {
		t.Fatalf("expected plain content type, got %s", receivedContentType)
	}
	if string(receivedBody) != `{"id":"1","type":"test","body":{}}` {
		t.Fatalf("unexpected body: %s", receivedBody)
	}
	if !strings.Contains(string(out), `{"status":"ok"}`) {
		t.Fatalf("expected response body in output, got: %s", out)
	}
}

func TestCLI_Send_JWS_ContentType(t *testing.T) {
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a JWS-like message (3 dot-separated parts)
	bin := buildBinary(t)

	// First generate and pack a signed message
	dir := t.TempDir()
	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)

	msg := `{"id":"1","type":"test","from":"` + aliceDoc.ID + `","body":{}}`
	packCmd := exec.Command(bin, "pack", "signed",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", filepath.Join(aliceDir, "did-doc.json"),
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack failed: %s", err)
	}

	sendCmd := exec.Command(bin, "send",
		"--to", server.URL,
		"--message", string(packed),
	)
	out, err := sendCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("send failed: %s\n%s", err, out)
	}

	if receivedContentType != "application/didcomm-signed+json" {
		t.Fatalf("expected signed content type, got %s", receivedContentType)
	}
}

func TestCLI_Send_NoURL(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "send", "--message", "{}")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when no URL specified")
	}
	if !strings.Contains(string(out), "--to is required") {
		t.Fatalf("expected --to error, got: %s", out)
	}
}

func TestCLI_Help(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "help")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("help failed: %s", err)
	}
	if !strings.Contains(string(out), "didcomm") {
		t.Fatal("help output missing 'didcomm'")
	}
	if !strings.Contains(string(out), "pack") {
		t.Fatal("help output missing 'pack'")
	}
	if !strings.Contains(string(out), "unpack") {
		t.Fatal("help output missing 'unpack'")
	}
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version failed: %s", err)
	}
	if !strings.Contains(string(out), "didcomm") {
		t.Fatal("version output missing 'didcomm'")
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "foobar")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if !strings.Contains(string(out), "unknown command") {
		t.Fatalf("expected 'unknown command' error, got: %s", out)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error with no args")
	}
}

func TestCLI_PackSigned_MissingKeyFile(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "pack", "signed", "--message", "{}")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for missing key file flag")
	}
	if !strings.Contains(string(out), "--key-file is required") {
		t.Fatalf("expected key-file error, got: %s", out)
	}
}

func TestCLI_PackAnoncrypt_NoDIDDoc_AutoResolve(t *testing.T) {
	// did:key should auto-resolve without --did-doc
	bin := buildBinary(t)
	dir := t.TempDir()

	bobDir := filepath.Join(dir, "bob")
	bobDoc := generateIdentity(t, bobDir)

	msg := `{"id":"auto-1","type":"https://example.com/test","to":["` + bobDoc.ID + `"],"body":{}}`

	packCmd := exec.Command(bin, "pack", "anoncrypt", "--message", msg)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack anoncrypt without --did-doc failed: %s", err)
	}

	// Unpack with bob's keys (also no --did-doc)
	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(bobDir, "keys.json"),
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatalf("invalid unpack output: %s", err)
	}
	if !result.Encrypted {
		t.Fatal("expected encrypted=true")
	}
	if !result.Anonymous {
		t.Fatal("expected anonymous=true")
	}
}

func TestCLI_Unpack_MissingKeyFile(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "unpack", "--message", "{}")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for missing key file flag")
	}
	if !strings.Contains(string(out), "--key-file is required") {
		t.Fatalf("expected key-file error, got: %s", out)
	}
}

// TestSendFunction tests the send function directly with a mock HTTP client.
func TestSendFunction(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use the direct send function approach via CLI binary
	bin := buildBinary(t)

	// First generate and pack an authcrypt message for encrypted content type
	dir := t.TempDir()
	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)
	bobDir := filepath.Join(dir, "bob")
	bobDoc := generateIdentity(t, bobDir)

	didDocs := filepath.Join(aliceDir, "did-doc.json") + "," + filepath.Join(bobDir, "did-doc.json")
	msg := `{"id":"1","type":"test","from":"` + aliceDoc.ID + `","to":["` + bobDoc.ID + `"],"body":{}}`

	packCmd := exec.Command(bin, "pack", "authcrypt",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", didDocs,
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack failed: %s", err)
	}

	sendCmd := exec.Command(bin, "send",
		"--to", server.URL,
		"--message", string(packed),
	)
	out, err := sendCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("send failed: %s\n%s", err, out)
	}

	if receivedContentType != "application/didcomm-encrypted+json" {
		t.Fatalf("expected encrypted content type, got %s", receivedContentType)
	}
	if len(receivedBody) == 0 {
		t.Fatal("empty body received")
	}
}

// TestPackUnpack_FileInput tests reading message from a file via @path.
func TestPackUnpack_FileInput(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)

	msgFile := filepath.Join(dir, "msg.json")
	msg := `{"id":"file-test","type":"https://example.com/test","from":"` + aliceDoc.ID + `","body":{"source":"file"}}`
	os.WriteFile(msgFile, []byte(msg), 0o644)

	packCmd := exec.Command(bin, "pack", "signed",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", filepath.Join(aliceDir, "did-doc.json"),
		"--message", "@"+msgFile,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack signed with file input failed: %s", err)
	}

	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--did-doc", filepath.Join(aliceDir, "did-doc.json"),
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatal(err)
	}

	var innerMsg didcomm.Message
	if err := json.Unmarshal(result.Message, &innerMsg); err != nil {
		t.Fatal(err)
	}
	if innerMsg.ID != "file-test" {
		t.Fatalf("got message ID %s", innerMsg.ID)
	}
}

func TestCLI_PackAuthcrypt_Unpack_AutoResolve(t *testing.T) {
	// Test full round-trip without --did-doc (auto-resolves did:key)
	bin := buildBinary(t)
	dir := t.TempDir()

	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)
	bobDir := filepath.Join(dir, "bob")
	bobDoc := generateIdentity(t, bobDir)

	msg := `{"id":"auto-2","type":"https://example.com/test","from":"` + aliceDoc.ID + `","to":["` + bobDoc.ID + `"],"body":{"text":"hi"}}`

	// Pack authcrypt — no --did-doc
	packCmd := exec.Command(bin, "pack", "authcrypt",
		"--key-file", filepath.Join(aliceDir, "keys.json"),
		"--message", msg,
	)
	packed, err := packCmd.Output()
	if err != nil {
		t.Fatalf("pack authcrypt failed: %s", err)
	}

	// Unpack — no --did-doc
	unpackCmd := exec.Command(bin, "unpack",
		"--key-file", filepath.Join(bobDir, "keys.json"),
		"--message", string(packed),
	)
	unpackOut, err := unpackCmd.Output()
	if err != nil {
		t.Fatalf("unpack failed: %s", err)
	}

	var result unpackOutput
	if err := json.Unmarshal(unpackOut, &result); err != nil {
		t.Fatalf("invalid unpack output: %s", err)
	}
	if !result.Encrypted || !result.Signed {
		t.Fatal("expected encrypted+signed")
	}
	if result.Anonymous {
		t.Fatal("expected anonymous=false")
	}

	var innerMsg didcomm.Message
	if err := json.Unmarshal(result.Message, &innerMsg); err != nil {
		t.Fatal(err)
	}
	if innerMsg.ID != "auto-2" {
		t.Fatalf("got message ID %s", innerMsg.ID)
	}
}

// TestBuildClient_Integration verifies buildClient creates a working client.
func TestBuildClient_Integration(t *testing.T) {
	dir := t.TempDir()
	aliceDir := filepath.Join(dir, "alice")
	aliceDoc := generateIdentity(t, aliceDir)

	client, err := buildClient(
		filepath.Join(aliceDir, "keys.json"),
		filepath.Join(aliceDir, "did-doc.json"),
	)
	if err != nil {
		t.Fatal(err)
	}

	msg := &didcomm.Message{
		ID:   "1",
		Type: "test",
		From: aliceDoc.ID,
		Body: json.RawMessage(`{}`),
	}

	packed, err := client.PackSigned(context.Background(), msg)
	if err != nil {
		t.Fatalf("pack signed via buildClient: %s", err)
	}
	if len(packed) == 0 {
		t.Fatal("empty packed output")
	}
}
