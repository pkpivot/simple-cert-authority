package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

const RootAuthority = "rootauth.example.com"

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
	return err
}

func CreateSigningSet(filename string, host string) {
	certName := filename + ".pem"
	keyName := filename + "-key.pem"

	certOut, err := os.Create(certName)
	if err != nil {
		log.Fatalf("Failed to open certificate file for writingg: %v", err)
	}

	keyOut, err := os.Create(keyName)
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

func CreateSignedCertificate(filename string, host string, signingSet string) {
	//certTemplate, privateKey, err := CreateTemplateCertificateAndKey(host)
	//if err != nil {
	//	log.Fatalf("Could not create cert template and key %v", err)
	//}
	//
	//file, err := os.Create(filename)
	//if err != nil {
	//	log.Fatalf("Failed to open key file for writing: %v", err)
	//}
	//
	//err2 := WritePemCertFile(certTemplate, signingCert, signingKey, file)
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
	filename := rootCmd.String("filename", "certificate", "fileame for the cert ")

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	signedHost := signCmd.String("host", "signed.example.com", "URL of host to created signed certificate for")
	signedFilename := signCmd.String("filename", "signed-certificate", "Name of the signed ")

	if len(os.Args) < 2 {
		fmt.Println("Expected root command")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "root":
		rootCmd.Parse(os.Args[2:])
		CreateSigningSet(*filename, *host)

	case "sign":
		rootCmd.Parse(os.Args[2:])
		CreateSignedCertificate(*signedFilename, *signedHost, "signing-certificate")
	}
}
