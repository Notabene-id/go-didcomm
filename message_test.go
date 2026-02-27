package didcomm

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMessage_Validate(t *testing.T) {
	tests := []struct {
		name    string
		msg     Message
		wantErr bool
	}{
		{
			name:    "valid message",
			msg:     Message{ID: "1", Type: "test", Body: json.RawMessage(`{}`)},
			wantErr: false,
		},
		{
			name:    "missing id",
			msg:     Message{Type: "test", Body: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "missing type",
			msg:     Message{ID: "1", Body: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "missing body",
			msg:     Message{ID: "1", Type: "test"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMessage_MarshalJSON(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	msg := &Message{
		ID:        "msg-1",
		Type:      "https://example.com/test",
		From:      "did:key:alice",
		To:        []string{"did:key:bob"},
		CreatedAt: &now,
		Body:      json.RawMessage(`{"hello":"world"}`),
		Extra: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	if raw["id"] != "msg-1" {
		t.Errorf("expected id=msg-1, got %v", raw["id"])
	}
	if raw["type"] != "https://example.com/test" {
		t.Errorf("expected type, got %v", raw["type"])
	}
	if raw["from"] != "did:key:alice" {
		t.Errorf("expected from, got %v", raw["from"])
	}
	if raw["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field, got %v", raw["custom_field"])
	}
	// created_time should be a unix timestamp
	if raw["created_time"] != float64(1700000000) {
		t.Errorf("expected created_time=1700000000, got %v", raw["created_time"])
	}
}

func TestMessage_MarshalJSON_OmitsEmptyOptional(t *testing.T) {
	msg := &Message{
		ID:   "1",
		Type: "test",
		Body: json.RawMessage(`{}`),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	if _, ok := raw["from"]; ok {
		t.Error("from should be omitted when empty")
	}
	if _, ok := raw["to"]; ok {
		t.Error("to should be omitted when empty")
	}
	if _, ok := raw["created_time"]; ok {
		t.Error("created_time should be omitted when nil")
	}
}

func TestMessage_UnmarshalJSON(t *testing.T) {
	input := `{
		"id": "msg-1",
		"type": "https://example.com/test",
		"from": "did:key:alice",
		"to": ["did:key:bob"],
		"created_time": 1700000000,
		"body": {"hello":"world"},
		"custom_field": "custom_value"
	}`

	var msg Message
	if err := json.Unmarshal([]byte(input), &msg); err != nil {
		t.Fatal(err)
	}

	if msg.ID != "msg-1" {
		t.Errorf("expected ID=msg-1, got %s", msg.ID)
	}
	if msg.Type != "https://example.com/test" {
		t.Errorf("expected Type, got %s", msg.Type)
	}
	if msg.From != "did:key:alice" {
		t.Errorf("expected From, got %s", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0] != "did:key:bob" {
		t.Errorf("expected To, got %v", msg.To)
	}
	if msg.CreatedAt == nil || msg.CreatedAt.Unix() != 1700000000 {
		t.Errorf("expected CreatedAt=1700000000, got %v", msg.CreatedAt)
	}
	if msg.Extra == nil || msg.Extra["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field in Extra, got %v", msg.Extra)
	}
}

func TestMessage_RoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	original := &Message{
		ID:        "msg-1",
		Type:      "https://example.com/test",
		From:      "did:key:alice",
		To:        []string{"did:key:bob"},
		CreatedAt: &now,
		Body:      json.RawMessage(`{"hello":"world"}`),
		Thid:      "thread-1",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID mismatch: %s != %s", decoded.ID, original.ID)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type mismatch")
	}
	if decoded.From != original.From {
		t.Errorf("From mismatch")
	}
	if decoded.Thid != original.Thid {
		t.Errorf("Thid mismatch")
	}
	if decoded.CreatedAt == nil || decoded.CreatedAt.Unix() != original.CreatedAt.Unix() {
		t.Errorf("CreatedAt mismatch")
	}
}
