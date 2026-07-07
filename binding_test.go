package didcomm

import "testing"

func TestBindSender(t *testing.T) {
	tests := []struct {
		name      string
		from      string
		senderDID string
		wantErr   bool
	}{
		{"match", "did:web:alice", "did:web:alice", false},
		{"mismatch", "did:web:alice", "did:web:mallory", true},
		{"empty from", "", "did:web:alice", true},
		{"empty signer", "did:web:alice", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := bindSender(&Message{From: tt.from}, tt.senderDID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bindSender(%q,%q) err=%v, wantErr=%v", tt.from, tt.senderDID, err, tt.wantErr)
			}
		})
	}
}

func TestBindRecipient(t *testing.T) {
	tests := []struct {
		name         string
		to           []string
		recipientDID string
		wantErr      bool
	}{
		{"in list", []string{"did:web:bob", "did:web:carol"}, "did:web:bob", false},
		{"not in list", []string{"did:web:carol"}, "did:web:bob", true},
		{"no addressees", nil, "did:web:bob", false},
		{"unknown recipient did", []string{"did:web:carol"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := bindRecipient(&Message{To: tt.to}, tt.recipientDID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bindRecipient err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want envClass
	}{
		{"jwe json", `{"protected":"x","ciphertext":"y","iv":"z","tag":"t"}`, classJWE},
		{"jws json", `{"payload":"p","protected":"h","signature":"s"}`, classJWS},
		{"plain json", `{"id":"1","type":"t","body":{}}`, classPlain},
		{"jwe compact", "a.b.c.d.e", classJWE},
		{"jws compact", "a.b.c", classJWS},
		{"garbage", "not json", classPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify([]byte(tt.env)); got != tt.want {
				t.Fatalf("classify(%q) = %d, want %d", tt.env, got, tt.want)
			}
		})
	}
}
