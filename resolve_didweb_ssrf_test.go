package didcomm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckDialAddress(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		allowLoopback bool
		wantErr       bool
	}{
		{"public", "93.184.216.34:443", false, false},
		{"loopback blocked", "127.0.0.1:443", false, true},
		{"loopback allowed", "127.0.0.1:443", true, false},
		{"metadata link-local", "169.254.169.254:80", false, true},
		{"private 10", "10.0.0.5:443", false, true},
		{"private 192.168", "192.168.1.1:443", false, true},
		{"ipv6 ula", "[fd00::1]:443", false, true},
		{"unspecified", "0.0.0.0:443", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDialAddress(tt.address, tt.allowLoopback)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkDialAddress(%q,%v) = %v, wantErr=%v", tt.address, tt.allowLoopback, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("err = %v, want ErrBlockedAddress", err)
			}
		})
	}
}

func TestDIDWebResolverBlocksLoopbackByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"did:web:x"}`))
	}))
	defer srv.Close()

	r := &DIDWebResolver{}
	// srv.URL is http://127.0.0.1:port; a matching did:web must be refused at dial.
	host := strings.TrimPrefix(srv.URL, "http://")
	did := "did:web:" + strings.ReplaceAll(host, ":", "%3A")
	if _, err := r.Resolve(context.Background(), did); err == nil {
		t.Fatal("expected loopback resolution to be blocked")
	}
}

func TestDIDWebResolverResolvesAndChecksID(t *testing.T) {
	var doc string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	did := "did:web:" + strings.ReplaceAll(host, ":", "%3A")

	// A custom HTTPClient bypasses the dial guard, exercising fetch/parse/id-match.
	r := &DIDWebResolver{HTTPClient: srv.Client()}

	doc = `{"id":"` + did + `"}`
	got, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != did {
		t.Fatalf("resolved id = %q, want %q", got.ID, did)
	}

	// A document whose id does not match the requested DID is rejected.
	doc = `{"id":"did:web:someone.else"}`
	if _, err := r.Resolve(context.Background(), did); !errors.Is(err, ErrDIDNotFound) {
		t.Fatalf("id mismatch err = %v, want ErrDIDNotFound", err)
	}
}
