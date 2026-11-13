package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

var certificateProofOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}

func NewServerCertificate(serverName string, proofKey []byte, now time.Time, lifetime time.Duration, random io.Reader) (Certificate, error) {
	if serverName == "" || len(proofKey) == 0 || lifetime <= 0 {
		return Certificate{}, errors.New("server name, proof key, and positive lifetime are required")
	}
	if random == nil {
		random = rand.Reader
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(random, serialLimit)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("marshal public key: %w", err)
	}
	notBefore := now.UTC().Add(-time.Minute).Truncate(time.Second)
	notAfter := now.UTC().Add(lifetime).Truncate(time.Second)
	proof := certificateProof(proofKey, spki, serverName, notBefore, notAfter)
	proofDER, err := asn1.Marshal(proof)
	if err != nil {
		return Certificate{}, fmt.Errorf("marshal certificate proof: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{
			Id:       certificateProofOID,
			Critical: false,
			Value:    proofDER,
		}},
	}
	der, err := x509.CreateCertificate(random, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse generated certificate: %w", err)
	}
	return Certificate{DER: der, PrivateKey: privateKey, Parsed: parsed}, nil
}

type Certificate struct {
	DER        []byte
	PrivateKey *ecdsa.PrivateKey
	Parsed     *x509.Certificate
}

func VerifyServerCertificate(cert *x509.Certificate, serverName string, proofKey []byte, now time.Time, clockSkew time.Duration) error {
	if cert == nil {
		return errors.New("missing server certificate")
	}
	if serverName == "" || len(proofKey) == 0 {
		return errors.New("server name and proof key are required")
	}
	if clockSkew < 0 {
		return errors.New("clock skew cannot be negative")
	}
	if err := cert.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("verify cover server name: %w", err)
	}
	if now.Add(clockSkew).Before(cert.NotBefore) || now.Add(-clockSkew).After(cert.NotAfter) {
		return errors.New("server certificate is outside its validity period")
	}
	var encodedProof []byte
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(certificateProofOID) {
			encodedProof = extension.Value
			break
		}
	}
	if encodedProof == nil {
		return errors.New("server certificate has no TLSNet proof")
	}
	var proof []byte
	if rest, err := asn1.Unmarshal(encodedProof, &proof); err != nil || len(rest) != 0 {
		return errors.New("server certificate has an invalid TLSNet proof")
	}
	expected := certificateProof(proofKey, cert.RawSubjectPublicKeyInfo, serverName, cert.NotBefore, cert.NotAfter)
	if !hmac.Equal(proof, expected) {
		return errors.New("server certificate TLSNet proof does not match the password")
	}
	return nil
}

func certificateProof(key, spki []byte, serverName string, notBefore, notAfter time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tlsnet/certificate-proof/v1"))
	writeLengthPrefixed(mac, spki)
	writeLengthPrefixed(mac, []byte(strings.ToLower(strings.TrimSuffix(serverName, "."))))
	var encoded [16]byte
	binary.BigEndian.PutUint64(encoded[:8], uint64(notBefore.Unix()))
	binary.BigEndian.PutUint64(encoded[8:], uint64(notAfter.Unix()))
	_, _ = mac.Write(encoded[:])
	return mac.Sum(nil)
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeLengthPrefixed(dst hashWriter, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = dst.Write(length[:])
	_, _ = dst.Write(value)
}
