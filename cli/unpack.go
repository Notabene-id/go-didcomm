package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// UnpackOutput is the JSON output format for the unpack command.
type UnpackOutput struct {
	Message   json.RawMessage `json:"message"`
	Encrypted bool            `json:"encrypted"`
	Signed    bool            `json:"signed"`
	Anonymous bool            `json:"anonymous"`
}

// RunUnpack unpacks and decrypts/verifies a DIDComm message.
func RunUnpack(args []string) error {
	fs := flag.NewFlagSet("unpack", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "path to JWK Set file with private keys (required)")
	didDoc := fs.String("did-doc", "", "comma-separated DID document file paths")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyFile == "" {
		return fmt.Errorf("--key-file is required")
	}

	client, err := BuildClient(*keyFile, *didDoc)
	if err != nil {
		return err
	}

	data, err := ReadMessageInput(*message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	result, err := client.Unpack(context.Background(), data)
	if err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	msgBytes, err := json.Marshal(result.Message)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	out := UnpackOutput{
		Message:   msgBytes,
		Encrypted: result.Encrypted,
		Signed:    result.Signed,
		Anonymous: result.Anonymous,
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}

	_, err = fmt.Fprintln(os.Stdout, string(outBytes))
	return err
}
