//go:build windows

// directlan-cert creates a dedicated, short-lived CA and server certificate
// for a manual LAN test. The CA private key is discarded after signing.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"directlan/internal/identity"
)

func main() {
	address := flag.String("address", "", "LAN IP or DNS name clients will use")
	out := flag.String("out", "test-server", "output directory")
	flag.Parse()
	if *address == "" || strings.ContainsAny(*address, "/\\ :") && net.ParseIP(*address) == nil {
		log.Fatal("-address must be a single IP or DNS name")
	}
	for _, name := range []string{"ca.pem", "server.pem", "server-key.pem"} {
		if _, err := os.Stat(filepath.Join(*out, name)); err == nil {
			log.Fatal("certificate files already exist; choose a new output directory")
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			log.Fatal(e)
		}
		return n
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "DirectLAN private LAN test CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	server := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: *address}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(*address); ip != nil {
		server.IPAddresses = []net.IP{ip}
	} else {
		server.DNSNames = []string{*address}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		log.Fatal(err)
	}
	if err := identity.WritePrivateFile(filepath.Join(*out, "server-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		log.Fatal(err)
	}
	for name, der := range map[string][]byte{"ca.pem": caDER, "server.pem": serverDER} {
		if err := os.WriteFile(filepath.Join(*out, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			log.Fatal(err)
		}
	}
	fingerprint := sha256.Sum256(caDER)
	fmt.Printf("Test certificates created for %s\nCA SHA256: %s\nSend only ca.pem to the second PC. Keep server-key.pem on the server.\n", *address, hex.EncodeToString(fingerprint[:]))
}
