package didcomm

import (
	"encoding/json"
	"fmt"
	"time"
)

// Message represents a DIDComm v2 message.
type Message struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	From      string                 `json:"from,omitempty"`
	To        []string               `json:"to,omitempty"`
	CreatedAt *time.Time             `json:"created_time,omitempty"`
	ExpiresAt *time.Time             `json:"expires_time,omitempty"`
	Body      json.RawMessage        `json:"body"`
	Thid      string                 `json:"thid,omitempty"`
	Pthid     string                 `json:"pthid,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// Validate checks that the message has required fields.
func (m *Message) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidMessage)
	}
	if m.Type == "" {
		return fmt.Errorf("%w: missing type", ErrInvalidMessage)
	}
	if m.Body == nil {
		return fmt.Errorf("%w: missing body", ErrInvalidMessage)
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling that includes Extra fields.
func (m *Message) MarshalJSON() ([]byte, error) {
	// Build a map with known fields
	msg := make(map[string]interface{})
	msg["id"] = m.ID
	msg["type"] = m.Type
	if m.From != "" {
		msg["from"] = m.From
	}
	if len(m.To) > 0 {
		msg["to"] = m.To
	}
	if m.CreatedAt != nil {
		msg["created_time"] = m.CreatedAt.Unix()
	}
	if m.ExpiresAt != nil {
		msg["expires_time"] = m.ExpiresAt.Unix()
	}
	if m.Body != nil {
		msg["body"] = m.Body
	}
	if m.Thid != "" {
		msg["thid"] = m.Thid
	}
	if m.Pthid != "" {
		msg["pthid"] = m.Pthid
	}

	// Merge extra fields
	for k, v := range m.Extra {
		if _, exists := msg[k]; !exists {
			msg[k] = v
		}
	}

	return json.Marshal(msg)
}

// UnmarshalJSON implements custom JSON unmarshaling that captures extra fields.
func (m *Message) UnmarshalJSON(data []byte) error {
	// Unmarshal known fields using an alias to avoid recursion
	type Alias Message
	aux := &struct {
		CreatedAt *int64 `json:"created_time,omitempty"`
		ExpiresAt *int64 `json:"expires_time,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if aux.CreatedAt != nil {
		t := time.Unix(*aux.CreatedAt, 0).UTC()
		m.CreatedAt = &t
	}
	if aux.ExpiresAt != nil {
		t := time.Unix(*aux.ExpiresAt, 0).UTC()
		m.ExpiresAt = &t
	}

	// Capture extra fields
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	known := map[string]bool{
		"id": true, "type": true, "from": true, "to": true,
		"created_time": true, "expires_time": true, "body": true,
		"thid": true, "pthid": true,
	}

	for k, v := range raw {
		if !known[k] {
			if m.Extra == nil {
				m.Extra = make(map[string]interface{})
			}
			var val interface{}
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			m.Extra[k] = val
		}
	}

	return nil
}
