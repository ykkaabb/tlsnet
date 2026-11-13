package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func testKeys(t *testing.T, password string) *Keys {
	t.Helper()
	keys, err := Derive(password, "test-network", "www.speedtest.cn", KDFParams{
		MemoryMiB:   1,
		Iterations:  1,
		Parallelism: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestDeriveIsDomainSeparatedAndStable(t *testing.T) {
	a := testKeys(t, "password of arbitrary length")
	b := testKeys(t, "password of arbitrary length")
	if a.TCPRoute != b.TCPRoute {
		t.Fatal("same inputs produced different keys")
	}
	if a.TCPRoute == a.QUICRoute || a.QUICRoute == a.Certificate {
		t.Fatal("derived keys are not domain-separated")
	}
	c := testKeys(t, "different password")
	if a.TCPRoute == c.TCPRoute {
		t.Fatal("different password produced same key")
	}
}

func TestRouteTokens(t *testing.T) {
	keys := testKeys(t, "password")
	now := time.Unix(1_800_000_000, 0)
	window := time.Minute
	tcpToken, err := NewTCPToken(keys.TCPRoute[:], now, window, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTCPToken(tcpToken[:], keys.TCPRoute[:], now.Add(window), window) {
		t.Fatal("TCP token did not survive adjacent time window")
	}
	if VerifyTCPToken(tcpToken[:], keys.TCPRoute[:], now.Add(3*window), window) {
		t.Fatal("expired TCP token was accepted")
	}
	quicToken, err := NewQUICToken(keys.QUICRoute[:], now, window, bytes.NewReader(bytes.Repeat([]byte{7}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyQUICToken(quicToken[:], keys.QUICRoute[:], now, window) {
		t.Fatal("QUIC token was rejected")
	}
	quicToken[0] ^= 1
	if VerifyQUICToken(quicToken[:], keys.QUICRoute[:], now, window) {
		t.Fatal("tampered QUIC token was accepted")
	}
}

func TestCertificateProof(t *testing.T) {
	keys := testKeys(t, "password")
	now := time.Unix(1_800_000_000, 0)
	certificate, err := NewServerCertificate("www.speedtest.cn", keys.Certificate[:], now, 6*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerCertificate(certificate.Parsed, "www.speedtest.cn", keys.Certificate[:], now, time.Minute); err != nil {
		t.Fatal(err)
	}
	wrong := testKeys(t, "wrong password")
	if err := VerifyServerCertificate(certificate.Parsed, "www.speedtest.cn", wrong.Certificate[:], now, time.Minute); err == nil {
		t.Fatal("certificate verified with wrong password")
	}
	if err := VerifyServerCertificate(certificate.Parsed, "other.example", keys.Certificate[:], now, time.Minute); err == nil {
		t.Fatal("certificate verified for wrong cover name")
	}
}
