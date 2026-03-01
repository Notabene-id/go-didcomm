package main

import (
	"encoding/json"

	"github.com/Notabene-id/go-didcomm/cli"
)

// unpackOutput kept for test backward compatibility.
type unpackOutput struct {
	Message   json.RawMessage `json:"message"`
	Encrypted bool            `json:"encrypted"`
	Signed    bool            `json:"signed"`
	Anonymous bool            `json:"anonymous"`
}

func runUnpack(args []string) error {
	return cli.RunUnpack(args)
}
