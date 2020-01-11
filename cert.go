package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// createSelfSignedCertificate creates a self-signed certificate from the given rsa.PrivateKey.
func createSelfSignedCertificate(privateKey *rsa.PrivateKey) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)
	template := x509.Certificate{
		SerialNumber: new(big.Int),
		Subject: pkix.Name{
			Country:            []string{"CH"},
			Organization:       []string{"None"},
			OrganizationalUnit: []string{"None"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
	}
	return x509.CreateCertificate(
		rand.Reader, &template, &template, privateKey.Public(), privateKey)
}

func savePEM(filename string, bytes *pem.Block) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, bytes)
}

func loadPEM(filename string, typ string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(bytes)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("one block expected")
	}
	if block.Type != typ {
		return nil, errors.New("wrong type")
	}
	return block.Bytes, nil
}

func initCertAndKey() (*tls.Certificate, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		certificate, err := createSelfSignedCertificate(privateKey)
		if err != nil {
			return nil, err
		}
		savePEM(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
		savePEM(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	}

	certBytes, err := loadPEM(certFile, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := loadPEM(keyFile, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}, nil
}
