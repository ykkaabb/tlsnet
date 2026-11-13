package tlsreality

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	defaultMaxClientHello = 64 * 1024
	tlsRecordHeaderSize   = 5
	clientHelloType       = 1
	handshakeRecordType   = 22
)

type ClientHello struct {
	Raw        []byte
	Random     [32]byte
	ServerName string
}

func PeekClientHello(conn net.Conn, maxBytes int, timeout time.Duration) (ClientHello, error) {
	if maxBytes == 0 {
		maxBytes = defaultMaxClientHello
	}
	if maxBytes < tlsRecordHeaderSize+4+34 {
		return ClientHello{}, errors.New("ClientHello limit is too small")
	}
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return ClientHello{}, err
		}
		defer conn.SetReadDeadline(time.Time{})
	}

	var raw, handshake []byte
	for {
		header := make([]byte, tlsRecordHeaderSize)
		if _, err := io.ReadFull(conn, header); err != nil {
			return ClientHello{}, fmt.Errorf("read TLS record header: %w", err)
		}
		if header[0] != handshakeRecordType {
			return ClientHello{}, fmt.Errorf("unexpected TLS record type %d before ClientHello", header[0])
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || len(raw)+tlsRecordHeaderSize+recordLength > maxBytes {
			return ClientHello{}, errors.New("ClientHello exceeds configured limit")
		}
		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return ClientHello{}, fmt.Errorf("read TLS record payload: %w", err)
		}
		raw = append(raw, header...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != clientHelloType {
			return ClientHello{}, fmt.Errorf("unexpected TLS handshake type %d", handshake[0])
		}
		messageLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if messageLength+4 > maxBytes {
			return ClientHello{}, errors.New("ClientHello handshake exceeds configured limit")
		}
		if len(handshake) < messageLength+4 {
			continue
		}
		if len(handshake) != messageLength+4 {
			return ClientHello{}, errors.New("unexpected handshake data after ClientHello")
		}
		return parseClientHello(raw, handshake[4:])
	}
}

func parseClientHello(raw, body []byte) (ClientHello, error) {
	if len(body) < 34 {
		return ClientHello{}, errors.New("truncated ClientHello")
	}
	result := ClientHello{Raw: raw}
	copy(result.Random[:], body[2:34])
	offset := 34
	if err := skipVector(body, &offset, 1); err != nil {
		return ClientHello{}, fmt.Errorf("session ID: %w", err)
	}
	if err := skipVector(body, &offset, 2); err != nil {
		return ClientHello{}, fmt.Errorf("cipher suites: %w", err)
	}
	if err := skipVector(body, &offset, 1); err != nil {
		return ClientHello{}, fmt.Errorf("compression methods: %w", err)
	}
	if offset == len(body) {
		return result, nil
	}
	extensions, err := readVector(body, &offset, 2)
	if err != nil {
		return ClientHello{}, fmt.Errorf("extensions: %w", err)
	}
	if offset != len(body) {
		return ClientHello{}, errors.New("trailing bytes in ClientHello")
	}
	for len(extensions) != 0 {
		if len(extensions) < 4 {
			return ClientHello{}, errors.New("truncated ClientHello extension")
		}
		typeID := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return ClientHello{}, errors.New("invalid ClientHello extension length")
		}
		if typeID == 0 {
			serverName, err := parseServerName(extensions[:length])
			if err != nil {
				return ClientHello{}, err
			}
			result.ServerName = serverName
		}
		extensions = extensions[length:]
	}
	return result, nil
}

func parseServerName(extension []byte) (string, error) {
	offset := 0
	list, err := readVector(extension, &offset, 2)
	if err != nil || offset != len(extension) {
		return "", errors.New("invalid SNI extension")
	}
	for len(list) != 0 {
		if len(list) < 3 {
			return "", errors.New("truncated SNI entry")
		}
		nameType := list[0]
		nameLength := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if nameLength > len(list) {
			return "", errors.New("invalid SNI entry length")
		}
		if nameType == 0 {
			return string(list[:nameLength]), nil
		}
		list = list[nameLength:]
	}
	return "", nil
}

func skipVector(data []byte, offset *int, lengthBytes int) error {
	_, err := readVector(data, offset, lengthBytes)
	return err
}

func readVector(data []byte, offset *int, lengthBytes int) ([]byte, error) {
	if *offset < 0 || lengthBytes < 1 || lengthBytes > 3 || len(data)-*offset < lengthBytes {
		return nil, io.ErrUnexpectedEOF
	}
	length := 0
	for i := 0; i < lengthBytes; i++ {
		length = length<<8 | int(data[*offset+i])
	}
	*offset += lengthBytes
	if length > len(data)-*offset {
		return nil, io.ErrUnexpectedEOF
	}
	value := data[*offset : *offset+length]
	*offset += length
	return value, nil
}
