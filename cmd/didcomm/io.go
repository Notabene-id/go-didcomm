package main

import (
	"github.com/Notabene-id/go-didcomm/cli"

	didcomm "github.com/Notabene-id/go-didcomm"
)

// Thin wrappers that delegate to the cli package, maintaining backward compatibility
// for tests that reference these unexported names.

func readMessageInput(flag string) ([]byte, error) {
	return cli.ReadMessageInput(flag)
}

func marshalDIDDoc(doc *didcomm.DIDDocument) ([]byte, error) {
	return cli.MarshalDIDDoc(doc)
}

func unmarshalDIDDoc(data []byte) (*didcomm.DIDDocument, error) {
	return cli.UnmarshalDIDDoc(data)
}

func marshalKeyPair(kp *didcomm.KeyPair) ([]byte, error) {
	return cli.MarshalKeyPair(kp)
}

func loadKeyFile(path string) (*didcomm.InMemorySecretsStore, error) {
	return cli.LoadKeyFile(path)
}

func loadDIDDocs(paths string) (*didcomm.InMemoryResolver, error) {
	return cli.LoadDIDDocs(paths)
}

func buildClient(keyFile, didDocPaths string) (*didcomm.Client, error) {
	return cli.BuildClient(keyFile, didDocPaths)
}

func detectContentType(data []byte) string {
	return cli.DetectContentType(data)
}

func parseMessage(data []byte) (*didcomm.Message, error) {
	return cli.ParseMessage(data)
}
