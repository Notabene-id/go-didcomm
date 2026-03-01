package main

import (
	"encoding/json"

	"github.com/Notabene-id/go-didcomm/cli"
)

func runDID(args []string) error {
	return cli.RunDID(args)
}

// generateOutput kept for test backward compatibility.
type generateOutput struct {
	DIDDocument json.RawMessage `json:"didDocument"`
	Keys        json.RawMessage `json:"keys"`
}
