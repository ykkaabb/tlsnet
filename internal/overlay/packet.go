package overlay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type Packet struct {
	Version int
	Source  netip.Addr
	Target  netip.Addr
	Length  int
}

func ParsePacket(packet []byte) (Packet, error) {
	if len(packet) == 0 {
		return Packet{}, errors.New("empty IP packet")
	}
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return Packet{}, fmt.Errorf("unsupported IP version %d", packet[0]>>4)
	}
}

func parseIPv4(packet []byte) (Packet, error) {
	if len(packet) < 20 {
		return Packet{}, errors.New("truncated IPv4 header")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return Packet{}, errors.New("invalid IPv4 header length")
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength || totalLength > len(packet) {
		return Packet{}, errors.New("invalid IPv4 total length")
	}
	return Packet{
		Version: 4,
		Source:  netip.AddrFrom4([4]byte(packet[12:16])),
		Target:  netip.AddrFrom4([4]byte(packet[16:20])),
		Length:  totalLength,
	}, nil
}

func parseIPv6(packet []byte) (Packet, error) {
	if len(packet) < 40 {
		return Packet{}, errors.New("truncated IPv6 header")
	}
	totalLength := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if totalLength > len(packet) {
		return Packet{}, errors.New("invalid IPv6 payload length")
	}
	var source, target [16]byte
	copy(source[:], packet[8:24])
	copy(target[:], packet[24:40])
	return Packet{
		Version: 6,
		Source:  netip.AddrFrom16(source),
		Target:  netip.AddrFrom16(target),
		Length:  totalLength,
	}, nil
}
