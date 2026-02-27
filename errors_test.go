package didcomm

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		err  error
		name string
	}{
		{ErrKeyNotFound, "ErrKeyNotFound"},
		{ErrDIDNotFound, "ErrDIDNotFound"},
		{ErrInvalidMessage, "ErrInvalidMessage"},
		{ErrEncryptionFailed, "ErrEncryptionFailed"},
		{ErrDecryptionFailed, "ErrDecryptionFailed"},
		{ErrSigningFailed, "ErrSigningFailed"},
		{ErrVerificationFailed, "ErrVerificationFailed"},
		{ErrUnsupportedKeyType, "ErrUnsupportedKeyType"},
		{ErrNoRecipients, "ErrNoRecipients"},
		{ErrNoSender, "ErrNoSender"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}
			if tt.err.Error() == "" {
				t.Fatal("error message should not be empty")
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	wrapped := fmt.Errorf("something went wrong: %w", ErrKeyNotFound)
	if !errors.Is(wrapped, ErrKeyNotFound) {
		t.Fatal("wrapped error should match ErrKeyNotFound")
	}
}
