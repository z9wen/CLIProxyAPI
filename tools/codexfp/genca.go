package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// runGenCA writes a self-signed CA and a leaf certificate for host. The leaf is
// what the listener presents; the CA is what has to be trusted locally so the
// client accepts it. A separate CA is required rather than a self-signed leaf:
// rustls's webpki verifier rejects a trust anchor that is also the end entity.
func runGenCA(outDir, host string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "codexfp local CA", Organization: []string{"codexfp"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate leaf key: %w", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create leaf certificate: %w", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return fmt.Errorf("marshal leaf key: %w", err)
	}

	files := map[string][]byte{
		"ca.pem":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"leaf.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"leaf-key.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	}
	for name, data := range files {
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	fmt.Printf("wrote CA and leaf for %q into %s\n\n", host, outDir)
	fmt.Println("1. Trust the CA (macOS, System keychain):")
	fmt.Printf("     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n\n",
		filepath.Join(outDir, "ca.pem"))
	fmt.Println("2. Point the host at this machine (remember to remove it afterwards):")
	fmt.Printf("     echo '127.0.0.1 %s' | sudo tee -a /etc/hosts\n\n", host)
	fmt.Printf("3. Reflect the SNI/authority only if the client also needs DNS to resolve elsewhere.\n")
	return nil
}
