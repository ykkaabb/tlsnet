package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	TCPTokenSize  = 32
	QUICTokenSize = 16
)

var (
	tcpTokenLabel  = []byte("tlsnet/tcp-route/v1")
	quicTokenLabel = []byte("tlsnet/quic-route/v1")
)

func NewTCPToken(key []byte, now time.Time, window time.Duration, random io.Reader) ([TCPTokenSize]byte, error) {
	var token [TCPTokenSize]byte
	if err := fillToken(token[:16], token[16:], key, tcpTokenLabel, now, window, random); err != nil {
		return token, err
	}
	return token, nil
}

func VerifyTCPToken(token []byte, key []byte, now time.Time, window time.Duration) bool {
	if len(token) != TCPTokenSize {
		return false
	}
	return verifyToken(token[:16], token[16:], key, tcpTokenLabel, now, window)
}

func NewQUICToken(key []byte, now time.Time, window time.Duration, random io.Reader) ([QUICTokenSize]byte, error) {
	var token [QUICTokenSize]byte
	if err := fillToken(token[:8], token[8:], key, quicTokenLabel, now, window, random); err != nil {
		return token, err
	}
	return token, nil
}

func VerifyQUICToken(token []byte, key []byte, now time.Time, window time.Duration) bool {
	if len(token) != QUICTokenSize {
		return false
	}
	return verifyToken(token[:8], token[8:], key, quicTokenLabel, now, window)
}

func fillToken(nonce, tag, key, label []byte, now time.Time, window time.Duration, random io.Reader) error {
	if len(key) == 0 || window <= 0 {
		return errors.New("token key and positive time window are required")
	}
	if random == nil {
		return errors.New("random source is required")
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return err
	}
	expected := tokenMAC(key, label, timeBucket(now, window), nonce)
	copy(tag, expected[:len(tag)])
	return nil
}

func verifyToken(nonce, tag, key, label []byte, now time.Time, window time.Duration) bool {
	if len(key) == 0 || window <= 0 {
		return false
	}
	bucket := timeBucket(now, window)
	matched := 0
	for offset := int64(-1); offset <= 1; offset++ {
		expected := tokenMAC(key, label, bucket+offset, nonce)
		matched |= subtle.ConstantTimeCompare(tag, expected[:len(tag)])
	}
	return matched == 1
}

func timeBucket(now time.Time, window time.Duration) int64 {
	return now.UnixNano() / window.Nanoseconds()
}

func tokenMAC(key, label []byte, bucket int64, nonce []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(label)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(bucket))
	_, _ = mac.Write(encoded[:])
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)
}
