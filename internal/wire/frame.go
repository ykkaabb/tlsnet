package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version        = 1
	HeaderSize     = 20
	MaxPayloadSize = 65535
)

var magic = [4]byte{'T', 'N', 'E', 'T'}

type Type uint8

const (
	TypeData Type = iota + 1
	TypeClientHello
	TypeServerHello
	TypeRouteUpdate
	TypePing
	TypePong
)

type Frame struct {
	Type     Type
	Flags    uint16
	Sequence uint64
	Payload  []byte
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if err := validateFrame(f); err != nil {
		return nil, err
	}
	encoded := make([]byte, HeaderSize+len(f.Payload))
	copy(encoded[:4], magic[:])
	encoded[4] = Version
	encoded[5] = byte(f.Type)
	binary.BigEndian.PutUint16(encoded[6:8], f.Flags)
	binary.BigEndian.PutUint64(encoded[8:16], f.Sequence)
	binary.BigEndian.PutUint32(encoded[16:20], uint32(len(f.Payload)))
	copy(encoded[HeaderSize:], f.Payload)
	return encoded, nil
}

func UnmarshalFrame(encoded []byte) (Frame, error) {
	if len(encoded) < HeaderSize {
		return Frame{}, io.ErrUnexpectedEOF
	}
	if err := validateHeader(encoded[:HeaderSize]); err != nil {
		return Frame{}, err
	}
	length := int(binary.BigEndian.Uint32(encoded[16:20]))
	if length > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload length %d exceeds maximum", length)
	}
	if len(encoded) != HeaderSize+length {
		return Frame{}, fmt.Errorf("frame length mismatch: header says %d, got %d", length, len(encoded)-HeaderSize)
	}
	return Frame{
		Type:     Type(encoded[5]),
		Flags:    binary.BigEndian.Uint16(encoded[6:8]),
		Sequence: binary.BigEndian.Uint64(encoded[8:16]),
		Payload:  encoded[HeaderSize:],
	}, nil
}

func WriteFrame(dst io.Writer, frame Frame) error {
	encoded, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	for len(encoded) != 0 {
		n, err := dst.Write(encoded)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[n:]
	}
	return nil
}

func ReadFrame(src io.Reader) (Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return Frame{}, err
	}
	if err := validateHeader(header); err != nil {
		return Frame{}, err
	}
	length := int(binary.BigEndian.Uint32(header[16:20]))
	if length > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload length %d exceeds maximum", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(src, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Type:     Type(header[5]),
		Flags:    binary.BigEndian.Uint16(header[6:8]),
		Sequence: binary.BigEndian.Uint64(header[8:16]),
		Payload:  payload,
	}, nil
}

func validateFrame(frame Frame) error {
	if !frame.Type.valid() {
		return fmt.Errorf("unknown frame type %d", frame.Type)
	}
	if len(frame.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload length %d exceeds maximum", len(frame.Payload))
	}
	return nil
}

func validateHeader(header []byte) error {
	if len(header) < HeaderSize {
		return io.ErrUnexpectedEOF
	}
	if string(header[:4]) != string(magic[:]) {
		return errors.New("invalid TLSNet frame magic")
	}
	if header[4] != Version {
		return fmt.Errorf("unsupported TLSNet frame version %d", header[4])
	}
	if !Type(header[5]).valid() {
		return fmt.Errorf("unknown frame type %d", header[5])
	}
	return nil
}

func (t Type) valid() bool {
	return t >= TypeData && t <= TypePong
}
