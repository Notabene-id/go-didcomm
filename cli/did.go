package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	didcomm "github.com/Notabene-id/go-didcomm"
)

// RunDID routes DID subcommands.
func RunDID(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: did <generate-key|generate-web|resolve> [options]")
	}

	switch args[0] {
	case "generate-key":
		return RunDIDGenerateKey(args[1:])
	case "generate-web":
		return RunDIDGenerateWeb(args[1:])
	case "resolve":
		return RunDIDResolve(args[1:])
	default:
		return fmt.Errorf("unknown did subcommand: %s", args[0])
	}
}

// GenerateOutput is the combined output format for generate commands.
type GenerateOutput struct {
	DIDDocument json.RawMessage `json:"didDocument"`
	Keys        json.RawMessage `json:"keys"`
}

// WriteGenerateOutput writes DID generation results to stdout or output directory.
func WriteGenerateOutput(doc *didcomm.DIDDocument, kp *didcomm.KeyPair, outputDir string) error {
	docBytes, err := MarshalDIDDoc(doc)
	if err != nil {
		return fmt.Errorf("marshal DID document: %w", err)
	}

	keyBytes, err := MarshalKeyPair(kp)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}

	if outputDir != "" {
		return WriteOutputDir(outputDir, docBytes, keyBytes)
	}

	out := GenerateOutput{
		DIDDocument: docBytes,
		Keys:        keyBytes,
	}
	result, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Println(string(result))
	return nil
}

// WriteOutputDir writes DID document and keys to files in the given directory.
func WriteOutputDir(outputDir string, docBytes, keyBytes []byte) error {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "did-doc.json"), docBytes, 0o600); err != nil {
		return fmt.Errorf("write DID document: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "keys.json"), keyBytes, 0o600); err != nil {
		return fmt.Errorf("write keys: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s/did-doc.json and %s/keys.json\n", outputDir, outputDir)
	return nil
}

// RunDIDGenerateKey generates a did:key identity.
func RunDIDGenerateKey(args []string) error {
	fs := flag.NewFlagSet("did generate-key", flag.ContinueOnError)
	outputDir := fs.String("output-dir", "", "write did-doc.json and keys.json to this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	doc, kp, err := didcomm.GenerateDIDKey()
	if err != nil {
		return fmt.Errorf("generate did:key: %w", err)
	}

	return WriteGenerateOutput(doc, kp, *outputDir)
}

// RunDIDResolve resolves a DID and prints its DID document.
func RunDIDResolve(args []string) error {
	fs := flag.NewFlagSet("did resolve", flag.ContinueOnError)
	didDocPaths := fs.String("did-doc", "", "comma-separated DID document file overrides")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: did resolve [--did-doc <files>] <did>")
	}
	did := fs.Arg(0)

	resolver, err := BuildResolverWithOverrides(*didDocPaths)
	if err != nil {
		return err
	}

	doc, err := resolver.Resolve(context.Background(), did)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", did, err)
	}

	docBytes, err := MarshalDIDDoc(doc)
	if err != nil {
		return fmt.Errorf("marshal DID document: %w", err)
	}
	fmt.Println(string(docBytes))
	return nil
}

// RunDIDGenerateWeb generates a did:web identity.
func RunDIDGenerateWeb(args []string) error {
	fs := flag.NewFlagSet("did generate-web", flag.ContinueOnError)
	domain := fs.String("domain", "", "domain for did:web (required)")
	path := fs.String("path", "", "optional path for did:web")
	serviceEndpoint := fs.String("service-endpoint", "", "optional DIDCommMessaging service endpoint URL")
	outputDir := fs.String("output-dir", "", "write did-doc.json and keys.json to this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}

	doc, kp, err := didcomm.GenerateDIDWeb(*domain, *path)
	if err != nil {
		return fmt.Errorf("generate did:web: %w", err)
	}

	if *serviceEndpoint != "" {
		doc.Service = append(doc.Service, didcomm.Service{
			ID:              doc.ID + "#didcomm",
			Type:            "DIDCommMessaging",
			ServiceEndpoint: *serviceEndpoint,
		})
	}

	return WriteGenerateOutput(doc, kp, *outputDir)
}
