package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{Type: TypeData, Flags: 3, Sequence: 42, Payload: []byte("packet")}
	encoded, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.Sequence != want.Sequence || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	var stream bytes.Buffer
	if err := WriteFrame(&stream, want); err != nil {
		t.Fatal(err)
	}
	got, err = ReadFrame(&stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatal("stream round trip changed payload")
	}
}

func TestFrameRejectsOversizedPayloadBeforeAllocation(t *testing.T) {
	header := make([]byte, HeaderSize)
	copy(header, magic[:])
	header[4] = Version
	header[5] = byte(TypeData)
	binary.BigEndian.PutUint32(header[16:20], MaxPayloadSize+1)
	_, err := ReadFrame(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFrameRejectsTrailingBytes(t *testing.T) {
	encoded, err := (Frame{Type: TypePing}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, 0)
	if _, err := UnmarshalFrame(encoded); err == nil {
		t.Fatal("accepted trailing bytes")
	}
}
