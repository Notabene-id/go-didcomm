// Command didcomm generates DID identities and packs, unpacks, and sends
// DIDComm v2 messages from the shell. Private keys are held only by the softkey
// development store; the didcomm library never receives them directly.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	didcomm "github.com/notabene-id/go-didcomm"
	"github.com/notabene-id/go-didcomm/softkey"
)

const (
	sendTimeout    = 15 * time.Second
	maxResponse    = 1 << 20
	keysFile       = "keys.json"
	didDocFile     = "did-doc.json"
	encryptedMedia = "application/didcomm-encrypted+json"
	signedMedia    = "application/didcomm-signed+json"
	plainMedia     = "application/didcomm-plain+json"
)

// profiles maps the --profile flag to a library profile.
var profiles = map[string]didcomm.Profile{
	"signed-anoncrypt": didcomm.ProfileSignedAnoncrypt,
	"1pu-v3":           didcomm.ProfileAuthcrypt1PUv3,
	"1pu-v4":           didcomm.ProfileAuthcrypt1PUv4,
	"anoncrypt":        didcomm.ProfileAnoncrypt,
	"signed":           didcomm.ProfileSigned,
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: didcomm <generate|resolve|pack|unpack|send> [options]")
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = runGenerate(os.Args[2:])
	case "resolve":
		err = runResolve(os.Args[2:])
	case "pack":
		err = runPack(os.Args[2:])
	case "unpack":
		err = runUnpack(os.Args[2:])
	case "send":
		err = runSend(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	web := fs.String("web", "", "generate a did:web for this domain (default: did:key)")
	path := fs.String("path", "", "optional did:web path")
	service := fs.String("service", "", "optional DIDCommMessaging service endpoint")
	dir := fs.String("dir", "", "write did-doc.json and keys.json here (default: stdout, public doc only)")
	printPrivate := fs.Bool("print-private", false, "with no --dir, also print private keys to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	doc, km, err := generateIdentity(*web, *path, *service)
	if err != nil {
		return err
	}

	docJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal DID document: %w", err)
	}
	if *dir != "" {
		return writeIdentity(*dir, docJSON, km)
	}

	if !*printPrivate {
		fmt.Println(string(docJSON))
		fmt.Fprintln(os.Stderr, "(public DID document only; pass --dir to save keys or --print-private to reveal them)")
		return nil
	}
	keysJSON, err := json.MarshalIndent(km, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}
	fmt.Printf("%s\n%s\n", docJSON, keysJSON)
	return nil
}

func generateIdentity(web, path, service string) (*didcomm.DIDDocument, *didcomm.KeyMaterial, error) {
	if web == "" {
		return didcomm.GenerateDIDKey()
	}
	doc, km, err := didcomm.GenerateDIDWeb(web, path)
	if err != nil {
		return nil, nil, err
	}
	if service != "" {
		doc.Service = append(doc.Service, didcomm.Service{
			ID: doc.ID + "#didcomm", Type: "DIDCommMessaging", ServiceEndpoint: service,
		})
	}
	return doc, km, nil
}

func writeIdentity(dir string, docJSON []byte, km *didcomm.KeyMaterial) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	keysJSON, err := json.MarshalIndent(km, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, didDocFile), docJSON, 0o600); err != nil {
		return fmt.Errorf("write DID document: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, keysFile), keysJSON, 0o600); err != nil {
		return fmt.Errorf("write keys: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", filepath.Join(dir, didDocFile), filepath.Join(dir, keysFile))
	return nil
}

func runResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	loopback := fs.Bool("allow-loopback", false, "allow resolving did:web on loopback (local dev)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: didcomm resolve [--allow-loopback] <did>")
	}
	doc, err := resolver(*loopback).Resolve(context.Background(), fs.Arg(0))
	if err != nil {
		return fmt.Errorf("resolve %s: %w", fs.Arg(0), err)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal DID document: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func runPack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	keys := fs.String("keys", "", "path to keys.json (required)")
	profileName := fs.String("profile", "signed-anoncrypt", "signed-anoncrypt|1pu-v3|1pu-v4|anoncrypt|signed")
	msgFlag := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	send := fs.Bool("send", false, "resolve the recipient endpoint and POST the packed message")
	loopback := fs.Bool("allow-loopback", false, "allow did:web on loopback (local dev)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	profile, ok := profiles[*profileName]
	if !ok {
		return fmt.Errorf("unknown profile %q", *profileName)
	}
	client, err := clientFor(*keys, *loopback)
	if err != nil {
		return err
	}
	msg, err := readMessage(*msgFlag)
	if err != nil {
		return err
	}
	packed, err := client.Pack(context.Background(), msg, didcomm.WithProfile(profile))
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	if *send {
		return sendToRecipient(packed, msg.To, *loopback)
	}
	_, err = os.Stdout.Write(packed)
	return err
}

func runUnpack(args []string) error {
	fs := flag.NewFlagSet("unpack", flag.ContinueOnError)
	keys := fs.String("keys", "", "path to keys.json (required)")
	msgFlag := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	allowUnverified := fs.Bool("allow-unverified", false, "accept plain/anonymous messages (sender NOT authenticated)")
	loopback := fs.Bool("allow-loopback", false, "allow did:web on loopback (local dev)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := clientFor(*keys, *loopback)
	if err != nil {
		return err
	}
	data, err := readInput(*msgFlag)
	if err != nil {
		return err
	}

	ctx := context.Background()
	var (
		msg  *didcomm.Message
		meta *didcomm.Metadata
	)
	if *allowUnverified {
		msg, meta, err = client.UnpackUnverified(ctx, data)
	} else {
		msg, meta, err = client.Unpack(ctx, data)
	}
	if err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	out, err := json.MarshalIndent(struct {
		Message   json.RawMessage `json:"message"`
		SenderDID string          `json:"senderDid"`
		Encrypted bool            `json:"encrypted"`
	}{body, meta.SenderDID, meta.Encrypted}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	to := fs.String("to", "", "endpoint URL to POST to (required)")
	msgFlag := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	loopback := fs.Bool("allow-loopback", false, "allow POSTing to a loopback address (local dev)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return errors.New("--to is required")
	}
	data, err := readInput(*msgFlag)
	if err != nil {
		return err
	}
	return post(*to, data, *loopback)
}

// clientFor builds a client with a softkey store loaded from a keys.json file.
func clientFor(keysPath string, loopback bool) (*didcomm.Client, error) {
	if keysPath == "" {
		return nil, errors.New("--keys is required")
	}
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, fmt.Errorf("read keys: %w", err)
	}
	var km didcomm.KeyMaterial
	if err = json.Unmarshal(data, &km); err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	store, err := softkey.New(&km)
	if err != nil {
		return nil, err
	}
	return didcomm.NewClient(resolver(loopback), store), nil
}

func resolver(loopback bool) didcomm.DIDResolver {
	multi := didcomm.NewMultiResolver(map[string]didcomm.DIDResolver{
		"did:key": &didcomm.DIDKeyResolver{},
		"did:web": &didcomm.DIDWebResolver{AllowLoopback: loopback},
	}, nil)
	return multi
}

func readMessage(flagVal string) (*didcomm.Message, error) {
	data, err := readInput(flagVal)
	if err != nil {
		return nil, err
	}
	var msg didcomm.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}
	return &msg, nil
}

func readInput(flagVal string) ([]byte, error) {
	switch {
	case flagVal == "" || flagVal == "-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(flagVal, "@"):
		return os.ReadFile(flagVal[1:])
	default:
		return []byte(flagVal), nil
	}
}

func sendToRecipient(packed []byte, recipients []string, loopback bool) error {
	if len(recipients) == 0 {
		return errors.New("message has no recipients")
	}
	doc, err := resolver(loopback).Resolve(context.Background(), recipients[0])
	if err != nil {
		return fmt.Errorf("resolve %s: %w", recipients[0], err)
	}
	endpoint, err := doc.FindDIDCommEndpoint()
	if err != nil {
		return fmt.Errorf("recipient %s: %w", recipients[0], err)
	}
	return post(endpoint, packed, loopback)
}

// post sends an envelope to an http(s) endpoint. It reuses the library's
// SSRF-guarded client so a serviceEndpoint resolved from a DID document cannot
// direct the POST to a loopback, private, or metadata address.
func post(endpoint string, body []byte, allowLoopback bool) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("endpoint must be an http(s) URL: %q", endpoint)
	}
	client := didcomm.SafeHTTPClient(allowLoopback)
	client.Timeout = sendTimeout
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", detectContentType(body))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))

	fmt.Fprintf(os.Stderr, "HTTP %s\n", resp.Status)
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	return nil
}

// detectContentType returns the DIDComm media type for an envelope.
func detectContentType(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var probe struct {
			Ciphertext string `json:"ciphertext"`
			Signature  string `json:"signature"`
		}
		if json.Unmarshal(trimmed, &probe) == nil {
			if probe.Ciphertext != "" {
				return encryptedMedia
			}
			if probe.Signature != "" {
				return signedMedia
			}
		}
		return plainMedia
	}
	// Compact serialization: JWE has 4 dots, JWS has 2.
	switch bytes.Count(trimmed, []byte(".")) {
	case 4:
		return encryptedMedia
	case 2:
		return signedMedia
	default:
		return plainMedia
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
