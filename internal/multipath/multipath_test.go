package multipath

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/ykkaabb/tlsnet/internal/wire"
)

type memoryLane struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	writeErr error
	closed   bool
}

func (m *memoryLane) Read(dst []byte) (int, error) { return m.buffer.Read(dst) }
func (m *memoryLane) Write(src []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.buffer.Write(src)
}
func (m *memoryLane) Close() error { m.closed = true; return nil }

func TestSetDistributesFramesAndRemovesFailedLane(t *testing.T) {
	set := NewSet()
	failed := &memoryLane{writeErr: io.ErrClosedPipe}
	healthy := &memoryLane{}
	if err := set.Add(0, failed); err != nil {
		t.Fatal(err)
	}
	if err := set.Add(1, healthy); err != nil {
		t.Fatal(err)
	}
	if err := set.Write(wire.Frame{Type: wire.TypeData, Payload: []byte("packet")}); err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || !failed.closed {
		t.Fatal("failed lane was not removed")
	}
	frame, err := wire.ReadFrame(&healthy.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 || string(frame.Payload) != "packet" {
		t.Fatalf("unexpected frame: %+v", frame)
	}
}

func TestReordererReleasesGapAfterDeadline(t *testing.T) {
	input := make(chan wire.Frame, 4)
	output := make(chan wire.Frame, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (Reorderer{Wait: 10 * time.Millisecond}).Run(ctx, input, output)
	input <- wire.Frame{Type: wire.TypeData, Sequence: 2}
	input <- wire.Frame{Type: wire.TypeData, Sequence: 1}
	if first := <-output; first.Sequence != 1 {
		t.Fatalf("first sequence=%d", first.Sequence)
	}
	if second := <-output; second.Sequence != 2 {
		t.Fatalf("second sequence=%d", second.Sequence)
	}
	input <- wire.Frame{Type: wire.TypeData, Sequence: 4}
	select {
	case frame := <-output:
		if frame.Sequence != 4 {
			t.Fatalf("gap release sequence=%d", frame.Sequence)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("gap was not released")
	}
}

func TestSetWithoutLanes(t *testing.T) {
	err := NewSet().Write(wire.Frame{Type: wire.TypeData})
	if !errors.Is(err, ErrNoHealthyLane) {
		t.Fatalf("unexpected error: %v", err)
	}
}
