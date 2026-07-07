package didcomm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// did:web resolution limits.
const (
	resolveTimeout  = 10 * time.Second
	maxDIDDocBytes  = 1 << 20 // 1 MiB
	wellKnownSuffix = "/.well-known/did.json"
)

// DIDWebResolver resolves did:web DIDs over HTTPS. Because a did:web identifier
// in an inbound message is attacker-controlled, the default transport refuses to
// connect to loopback, private, link-local, or cloud-metadata addresses (checked
// at dial time, which also defeats DNS rebinding), sets a timeout, caps the
// response size, and does not follow redirects.
type DIDWebResolver struct {
	// HTTPClient overrides the default guarded client. Setting it opts out of the
	// built-in SSRF protections, so supply your own guard if you do.
	HTTPClient *http.Client
	// AllowLoopback permits connections to loopback addresses, for local
	// development against a node on 127.0.0.1.
	AllowLoopback bool
}

// Resolve fetches and parses a did:web DID document.
func (r *DIDWebResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return nil, fmt.Errorf("%w: not a did:web DID: %s", ErrDIDNotFound, did)
	}
	url, err := didWebToURL(did)
	if err != nil {
		return nil, err
	}

	client := r.HTTPClient
	if client == nil {
		client = guardedHTTPClient(r.AllowLoopback)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", did, err)
	}
	req.Header.Set("Accept", "application/did+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch DID document for %s: %w", did, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d fetching %s", ErrDIDNotFound, resp.StatusCode, did)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDIDDocBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read DID document for %s: %w", did, err)
	}
	if len(body) > maxDIDDocBytes {
		return nil, fmt.Errorf("%w: DID document for %s exceeds %d bytes", ErrDIDNotFound, did, maxDIDDocBytes)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document for %s: %w", did, err)
	}
	if doc.ID != did {
		return nil, fmt.Errorf("%w: document id %q does not match requested %q", ErrDIDNotFound, doc.ID, did)
	}
	return &doc, nil
}

// guardedHTTPClient builds an HTTP client that blocks non-public destinations at
// dial time, times out, and refuses redirects.
func guardedHTTPClient(allowLoopback bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: resolveTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address, allowLoopback)
		},
	}
	return &http.Client{
		Timeout: resolveTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   resolveTimeout,
			ResponseHeaderTimeout: resolveTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkDialAddress rejects a resolved dial target that is not a public address.
func checkDialAddress(address string, allowLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unresolved host %s", ErrBlockedAddress, host)
	}
	if ip.IsLoopback() {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback %s", ErrBlockedAddress, ip)
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%w: non-public %s", ErrBlockedAddress, ip)
	}
	return nil
}

// didWebToURL converts a did:web identifier to its HTTPS URL (did:web method
// spec §3.2).
//
//	did:web:example.com              -> https://example.com/.well-known/did.json
//	did:web:example.com:users:alice  -> https://example.com/users/alice/did.json
//	did:web:localhost%3A8080         -> https://localhost:8080/.well-known/did.json
func didWebToURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("%w: not a did:web DID: %s", ErrDIDNotFound, did)
	}
	specific := did[len("did:web:"):]
	if specific == "" {
		return "", fmt.Errorf("%w: empty did:web identifier", ErrDIDNotFound)
	}
	parts := strings.Split(specific, ":")
	domain := strings.ReplaceAll(parts[0], "%3A", ":")
	if len(parts) == 1 {
		return "https://" + domain + wellKnownSuffix, nil
	}
	return "https://" + domain + "/" + strings.Join(parts[1:], "/") + "/did.json", nil
}
