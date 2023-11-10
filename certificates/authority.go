package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func CreateTemplateRootCertificateAndKey(name string) (*x509.Certificate, rsa.PrivateKey, error) {
	var privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	cert := &x509.Certificate{
		SerialNumber: SerialNumber(),
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA512WithRSA}

	return cert, *privateKey, err
}

func CreateTemplateCertificateAndKey(url string) (*x509.Certificate, rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	cert := &x509.Certificate{
		SerialNumber: SerialNumber(),
		Subject: pkix.Name{
			Organization: []string{url},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert.DNSNames = append(cert.DNSNames, url)

	return cert, *privateKey, err
}

func WritePemPrivateKey(key *rsa.PrivateKey, w io.Writer) error {
	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	err = pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: bytes})
	return err
}

func WritePemCertFile(template x509.Certificate, issuer x509.Certificate, key *rsa.PrivateKey, w io.Writer) error {

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuer, &(key.PublicKey), key)
	if err != nil {
		return err
	}

	if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write certificate data: %v", err)
	}
	return err
}

func ReadPemCert(certificate []byte) (*x509.Certificate, error) {
	derBytes, rest := pem.Decode(certificate)
	if len(rest) > 0 {
		return nil, errors.New("cannot read certificate chain")
	}

	return x509.ParseCertificate(derBytes.Bytes)
}

func ReadPemKey(key []byte) (*rsa.PrivateKey, error) {
	derBytes, rest := pem.Decode(key)
	if len(rest) > 0 {
		return nil, errors.New("cannot read key and certificate chain")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(derBytes.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("did not contain rsa private key")
	}
	return rsaKey, nil
}

func CreateSigningSet(filename string, host string) {
	certName, keyName := CertSetNames(filename)

	certOut, err := os.Create(certName)
	if err != nil {
		log.Fatalf("Failed to open certificate file for writingg: %v", err)
	}
	defer certOut.Close()

	keyOut, err := os.Create(keyName)
	defer keyOut.Close()

	if err != nil {
		log.Fatalf("Failed to open key file for writing: %v", err)
	}

	cert, key, err := CreateTemplateRootCertificateAndKey(host)
	if err != nil {
		log.Fatalf("Could not generate private key and certificate: %v", err)
	}

	err2 := WritePemCertFile(*cert, *cert, &key, certOut)
	if err2 != nil {
		log.Fatalf("Could not writer certificate: %v", err)
	}

	err3 := WritePemPrivateKey(&key, keyOut)
	if err3 != nil {
		log.Fatalf("Could not writer certificate: %v", err)
	}
}

func SerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	return serialNumber
}

func CreateSignedCertificate(filename string, host string, signingSet string) {

	// 1. Create all filenames
	certName, keyName := CertSetNames(filename)
	signingCertName, signingKeyName := CertSetNames(signingSet)

	// 2. Read the PEM files for signing cert and key
	signingCertPem, err := os.ReadFile(signingCertName)
	if err != nil {
		log.Fatalf("Could not read signing certificate certFile %v", err)
	}

	signingKeyPem, err := os.ReadFile(signingKeyName)
	if err != nil {
		log.Fatalf("Could not read signing key certFile %v", err)
	}

	// 3. Parse the PEM files to create signing cert and signing key objects
	signingCert, err := ReadPemCert(signingCertPem)
	if err != nil {
		log.Fatalf("Could not parse pem certificate certFile %v", err)
	}

	signingKey, err := ReadPemKey(signingKeyPem)
	if err != nil {
		log.Fatalf("Could not parse pem key certFile %v", err)
	}

	// 4. Generate the client certificate key pair
	certTemplate, privateKey, err := CreateTemplateCertificateAndKey(host)
	if err != nil {
		log.Fatalf("Could not create cert template and key %v", err)
	}

	keyFile, err := os.Create(keyName)
	defer keyFile.Close()

	// 4. Write the private key certFile
	if err := WritePemPrivateKey(&privateKey, keyFile); err != nil {
		log.Fatalf("Could open private key certFile %v", err)
	}

	// 5. Sign the certificate and write it out
	certFile, err := os.Create(certName)
	defer certFile.Close()

	if err != nil {
		log.Fatalf("Failed to open key certFile for writing: %v", err)
	}

	if err := WritePemCertFile(*certTemplate, *signingCert, signingKey, certFile); err != nil {
		log.Fatalf("Could not create signed certificate: %v", err)
	}
}

func CertSetNames(setName string) (string, string) {
	setName = strings.TrimSuffix(setName, filepath.Ext(setName))
	certName := setName + ".pem"
	keyName := setName + "-key.pem"
	return certName, keyName
}

func main() {

	rootCmd := flag.NewFlagSet("root", flag.ExitOnError)
	host := rootCmd.String("host", "signing.example.com", "URL of signing authority")
	filename := rootCmd.String("filename", "signing-cert", "filename for the cert ")

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	signedHost := signCmd.String("host", "signed.example.com", "URL of host to created signed certificate for")
	signedFilename := signCmd.String("filename", "signed-certificate", "Name of the signed ")
	signingCert := signCmd.String("signer", "signing-cert", "Name of the signing set")

	if len(os.Args) < 2 {
		fmt.Println("Expected root or sign  command")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "root":
		rootCmd.Parse(os.Args[2:])
		CreateSigningSet(*filename, *host)

	case "sign":
		signCmd.Parse(os.Args[2:])
		CreateSignedCertificate(*signedFilename, *signedHost, *signingCert)
	}
}
