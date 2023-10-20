package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"time"
)

func CreateTemplateRootCertificateAndKey(name string) (*x509.Certificate, rsa.PrivateKey, error) {
	var privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA512WithRSA}

	return cert, *privateKey, err
}

func CreateTemplateCertificateAndKey(url string) (*x509.Certificate, rsa.PrivateKey, error) {
	var privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuer, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write certificate data: %v", err)
	}

	_, err = w.Write(derBytes)
	return err
}
