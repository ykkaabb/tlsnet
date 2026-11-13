package quicreality

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
)

const (
	ProbeSize       = 1200
	probeDCIDLength = auth.QUICTokenSize
	probeSCIDLength = 8
	quicVersion1    = 1
)

func NewProbe(key []byte, now time.Time, window time.Duration, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	token, err := auth.NewQUICToken(key, now, window, random)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, ProbeSize)
	packet[0] = 0xc3
	binary.BigEndian.PutUint32(packet[1:5], quicVersion1)
	packet[5] = probeDCIDLength
	copy(packet[6:6+probeDCIDLength], token[:])
	offset := 6 + probeDCIDLength
	packet[offset] = probeSCIDLength
	offset++
	if _, err := io.ReadFull(random, packet[offset:offset+probeSCIDLength]); err != nil {
		return nil, fmt.Errorf("generate probe source connection ID: %w", err)
	}
	offset += probeSCIDLength
	packet[offset] = 0
	offset++
	remaining := ProbeSize - offset - 2
	if remaining >= 1<<14 {
		return nil, errors.New("probe payload cannot be represented by a two-byte QUIC varint")
	}
	binary.BigEndian.PutUint16(packet[offset:offset+2], uint16(remaining)|(1<<14))
	offset += 2
	if _, err := io.ReadFull(random, packet[offset:]); err != nil {
		return nil, fmt.Errorf("generate probe payload: %w", err)
	}
	return packet, nil
}

func VerifyProbe(packet, key []byte, now time.Time, window time.Duration) bool {
	dcid, ok := initialDCID(packet)
	return ok && len(dcid) == probeDCIDLength && auth.VerifyQUICToken(dcid, key, now, window)
}

func SendProbe(conn net.PacketConn, server net.Addr, key []byte, now time.Time, window time.Duration) error {
	if conn == nil || server == nil {
		return errors.New("packet connection and server address are required")
	}
	packet, err := NewProbe(key, now, window, rand.Reader)
	if err != nil {
		return err
	}
	n, err := conn.WriteTo(packet, server)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}

func initialDCID(packet []byte) ([]byte, bool) {
	if len(packet) < 7 || packet[0]&0xc0 != 0xc0 || packet[0]&0x30 != 0 {
		return nil, false
	}
	if binary.BigEndian.Uint32(packet[1:5]) != quicVersion1 {
		return nil, false
	}
	length := int(packet[5])
	if length == 0 || length > 20 || 6+length > len(packet) {
		return nil, false
	}
	return packet[6 : 6+length], true
}
