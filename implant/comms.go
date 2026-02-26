package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
)

// serverPublicKey is the fallback for dev builds when serverPK ldflag is not set.
// In production, serverPK (set via -ldflags) takes precedence. See transport.go InitImplant().
var serverPublicKey = []byte{}

// zeroBytes overwrites a byte slice with zeros to reduce key material exposure
// in memory. Not a guarantee (GC may copy), but raises the bar for forensics.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateEphemeralKey generates a one-time P-256 ECDH keypair for this
// session. The public key is sent to the server in Envelope.PubKey.
func GenerateEphemeralKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// DeriveSessionKey performs ECDH with the implant's ephemeral private key and
// the server's static public key, then SHA-256 hashes the shared secret to
// produce a 32-byte AES-256 session key.
func DeriveSessionKey(ephemPriv *ecdh.PrivateKey, serverPubBytes []byte) ([]byte, error) {
	serverPub, err := ecdh.P256().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := ephemPriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(shared)
	zeroBytes(shared) // scrub raw ECDH output
	return key[:], nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the provided 32-byte key.
// It generates a random 12-byte nonce and returns it alongside the ciphertext.
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
