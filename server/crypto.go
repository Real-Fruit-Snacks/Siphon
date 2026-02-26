package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"os"
)

// GenerateServerKeyPair generates a new P-256 ECDH keypair.
func GenerateServerKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// SaveKeyPair PEM-encodes the private key and writes it to path.
// The PEM block holds the raw private key bytes (as returned by priv.Bytes()).
func SaveKeyPair(priv *ecdh.PrivateKey, path string) (err error) {
	block := &pem.Block{
		Type:  "ECDH PRIVATE KEY",
		Bytes: priv.Bytes(),
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return pem.Encode(f, block)
}

// LoadKeyPair reads a PEM file written by SaveKeyPair and reconstructs the
// P-256 private key.
func LoadKeyPair(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ECDH PRIVATE KEY" {
		return nil, errors.New("crypto: invalid PEM block")
	}
	return ecdh.P256().NewPrivateKey(block.Bytes)
}

// GetPublicKeyBytes returns the uncompressed public key bytes suitable for
// embedding in the implant at compile time.
func GetPublicKeyBytes(priv *ecdh.PrivateKey) []byte {
	return priv.PublicKey().Bytes()
}

// DeriveSessionKey performs ECDH with the server's static private key and the
// client's ephemeral public key, then SHA-256 hashes the shared secret to
// produce a 32-byte AES-256 session key.
func DeriveSessionKey(serverPriv *ecdh.PrivateKey, clientPubBytes []byte) ([]byte, error) {
	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(shared)
	// Zero raw ECDH shared secret to reduce memory exposure.
	for i := range shared {
		shared[i] = 0
	}
	return key[:], nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the provided 32-byte key.
// It generates a random 12-byte nonce and returns it alongside the ciphertext.
// The caller must transmit both nonce and ciphertext to the peer.
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt using the same key and nonce.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
