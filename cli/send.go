package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// RunSend POSTs a pre-packed message to an endpoint URL.
func RunSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	to := fs.String("to", "", "endpoint URL to POST to (required)")
	message := fs.String("message", "-", "message input: - (stdin), @file, or inline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *to == "" {
		return fmt.Errorf("--to is required")
	}

	data, err := ReadMessageInput(*message)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}

	contentType := DetectContentType(data)

	req, err := http.NewRequest(http.MethodPost, *to, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	fmt.Fprintln(os.Stderr, "HTTP "+resp.Status) //nolint:gosec // CLI stderr output, no XSS risk
	if len(body) > 0 {
		_, _ = os.Stdout.Write(body)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	return nil
}
