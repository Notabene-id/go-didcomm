package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

const usage = `didcomm - DIDComm v2 messaging CLI

Usage:
  didcomm <command> [options]

Commands:
  did generate-key                                          Generate a did:key identity
  did generate-web --domain <d> [--path <p>]                Generate a did:web identity
  did resolve <did> [--did-doc <f>]                         Resolve a DID document
  pack signed    --key-file <f> [--send] [--did-doc <f>]    Sign a message (JWS)
  pack anoncrypt [--send] [--did-doc <f>] [--message <m>]   Anonymous encrypt (JWE)
  pack authcrypt --key-file <f> [--send] [--did-doc <f>]    Sign-then-encrypt
  unpack         --key-file <f> [--did-doc <f>]             Unpack a message
  send           --to <url> [--message <m>]                 HTTP POST pre-packed message
  version                                                   Print version
  help                                                      Print this help

DID resolution is automatic for did:key and did:web. The --did-doc flag is
only needed for overriding or supplementing auto-resolved documents.

The --send flag on pack commands resolves the first recipient's DIDCommMessaging
service endpoint and POSTs the packed message to it.

Message input (--message flag):
  -           Read from stdin (default)
  @file.json  Read from file
  '{"json"}'  Inline JSON string

Examples:
  # Generate identities
  didcomm did generate-key --output-dir alice
  didcomm did generate-key --output-dir bob

  # Pack and send (auto-resolves did:key)
  ALICE=$(jq -r .id alice/did-doc.json)
  BOB=$(jq -r .id bob/did-doc.json)
  echo '{"id":"1","type":"test","from":"'$ALICE'","to":["'$BOB'"],"body":{}}' | \
    didcomm pack authcrypt --key-file alice/keys.json

  # Unpack (auto-resolves sender's DID for signature verification)
  didcomm unpack --key-file bob/keys.json --message @packed.json
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "did":
		err = runDID(os.Args[2:])
	case "pack":
		err = runPack(os.Args[2:])
	case "unpack":
		err = runUnpack(os.Args[2:])
	case "send":
		err = runSend(os.Args[2:])
	case "version":
		fmt.Println("didcomm " + version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintln(os.Stderr, "unknown command: "+os.Args[1]+"\n") //nolint:gosec // CLI stderr output, no XSS risk
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
