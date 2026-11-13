package auth

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

type CertificateManager struct {
	serverName  string
	proofKey    []byte
	lifetime    time.Duration
	renewBefore time.Duration
	now         func() time.Time

	mu          sync.Mutex
	certificate *tls.Certificate
}

func NewCertificateManager(serverName string, proofKey []byte, lifetime, renewBefore time.Duration, now func() time.Time) (*CertificateManager, error) {
	if serverName == "" || len(proofKey) == 0 {
		return nil, errors.New("server name and proof key are required")
	}
	if lifetime <= 0 || renewBefore <= 0 || renewBefore >= lifetime {
		return nil, errors.New("invalid certificate rotation periods")
	}
	if now == nil {
		now = time.Now
	}
	return &CertificateManager{
		serverName: serverName, proofKey: append([]byte(nil), proofKey...),
		lifetime: lifetime, renewBefore: renewBefore, now: now,
	}, nil
}

func (m *CertificateManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.certificate != nil && m.certificate.Leaf != nil &&
		now.Before(m.certificate.Leaf.NotAfter.Add(-m.renewBefore)) {
		return m.certificate, nil
	}
	generated, err := NewServerCertificate(m.serverName, m.proofKey, now, m.lifetime, nil)
	if err != nil {
		return nil, err
	}
	m.certificate = &tls.Certificate{
		Certificate: [][]byte{generated.DER},
		PrivateKey:  generated.PrivateKey,
		Leaf:        generated.Parsed,
	}
	return m.certificate, nil
}
