package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/alexcesaro/log/stdlog"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

var crts = make(map[string]string)

// Certs - array of certificates
type Certs struct {
	Certs []Cert
}

// Cert - single certificate information
type Cert struct {
	Name         string
	SerialNumber int
	Revoked      bool
	Created      time.Time
}

// TestMe - bla bla
func TestMe(certs *Certs) {
	if len(certs.Certs) > 0 {
		fmt.Println(certs.Certs[0].Name)
		fmt.Println(certs.Certs[0].SerialNumber)
	} else {
		fmt.Println("Array empty")
	}
}

// Create - create a certificate signing request
func Create(csrName, csrUser string, basePath string) {
	logger := stdlog.GetFromFlags()
	logger.Debug("## Creating CSR ##")

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   csrUser,
			Organization: []string{"student", "admission"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)

	if err != nil {
		logger.Errorf("Create certificate request failed", err)
		return
	}

	csrOut, _ := os.OpenFile(basePath+"/csr/"+csrName+".pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrOut.Close()
	logger.Debug("written " + csrName + ".pem\n")

	privateKeyFile, err := os.OpenFile(basePath+"/private_keys/"+csrName+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(privateKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	privateKeyFile.Close()
	logger.Debug("written " + csrName + ".key\n")
}

// Sign - Sign certificate
func Sign(csrName string, caPWD string, certs *Certs, years int, basePath string) {
	logger := stdlog.GetFromFlags()

	caPublicKeyFile, err := ioutil.ReadFile(basePath + "/certificates/ca.crt")
	if err != nil {
		panic(err)
	}

	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile(basePath + "/private_keys/ca.key")
	if err != nil {
		panic(err)
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	der, err := x509.DecryptPEMBlock(pemBlock, []byte(caPWD))
	if err != nil {
		panic(err)
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		panic(err)
	}

	// load client certificate request
	clientCSRFile, err := ioutil.ReadFile(basePath + "/csr/" + csrName + ".pem")
	if err != nil {
		panic(err)
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		panic(err)
	}

	var maxSerialNum = 0
	var serialNum = 0

	// Check if this is already signed
	for i := range certs.Certs {
		if certs.Certs[i].Name == csrName {
			logger.Debug("CSR with same name is already signed.")
			return
		}
	}

	// Get largest current serialnum
	if len(certs.Certs) > 0 {
		for s := range certs.Certs {
			serialNum = int(certs.Certs[s].SerialNumber)
			if serialNum > maxSerialNum {
				maxSerialNum = serialNum
				logger.Debug("maxSerialNum", maxSerialNum)
			}
		}
	} else { // First certificate, serial will be 1
		serialNum = 0
		maxSerialNum = 0
	}

	logger.Debug("final maxSerial:", maxSerialNum+1)

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(int64(maxSerialNum + 1)),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(years, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certs.Certs = append(certs.Certs, Cert{Name: csrName, SerialNumber: maxSerialNum + 1, Revoked: false, Created: time.Now()})

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}
	// save the certificate
	clientCRTFile, err := os.Create(basePath + "/certificates/" + csrName + ".crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile.Close()
}
