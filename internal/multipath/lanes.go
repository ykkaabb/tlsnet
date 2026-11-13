package multipath

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/ykkaabb/tlsnet/internal/wire"
)

var ErrNoHealthyLane = errors.New("no healthy transport lane")

type Lane interface {
	io.ReadWriteCloser
}

type laneState struct {
	conn Lane
	mu   sync.Mutex
}

type Set struct {
	mu       sync.RWMutex
	lanes    map[int]*laneState
	order    []int
	cursor   atomic.Uint64
	sequence atomic.Uint64
}

func NewSet() *Set {
	return &Set{lanes: make(map[int]*laneState)}
}

func (s *Set) Add(id int, conn Lane) error {
	if id < 0 || conn == nil {
		return errors.New("valid lane ID and connection are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.lanes[id]; exists {
		return errors.New("lane already exists")
	}
	s.lanes[id] = &laneState{conn: conn}
	s.order = append(s.order, id)
	return nil
}

func (s *Set) Remove(id int) {
	s.mu.Lock()
	lane := s.lanes[id]
	if lane != nil {
		delete(s.lanes, id)
		for index, current := range s.order {
			if current == id {
				s.order = append(s.order[:index], s.order[index+1:]...)
				break
			}
		}
	}
	s.mu.Unlock()
	if lane != nil {
		_ = lane.conn.Close()
	}
}

func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.lanes)
}

func (s *Set) Close() error {
	s.mu.Lock()
	lanes := s.lanes
	s.lanes = make(map[int]*laneState)
	s.order = nil
	s.mu.Unlock()
	for _, lane := range lanes {
		_ = lane.conn.Close()
	}
	return nil
}

func (s *Set) Write(frame wire.Frame) error {
	if frame.Type == wire.TypeData {
		frame.Sequence = s.sequence.Add(1)
	}
	lanes := s.snapshot()
	if len(lanes) == 0 {
		return ErrNoHealthyLane
	}
	start := int(s.cursor.Add(1)-1) % len(lanes)
	var lastErr error
	for offset := 0; offset < len(lanes); offset++ {
		selected := lanes[(start+offset)%len(lanes)]
		selected.state.mu.Lock()
		err := wire.WriteFrame(selected.state.conn, frame)
		selected.state.mu.Unlock()
		if err == nil {
			return nil
		}
		lastErr = err
		s.Remove(selected.id)
	}
	if lastErr == nil {
		lastErr = ErrNoHealthyLane
	}
	return errors.Join(ErrNoHealthyLane, lastErr)
}

type selectedLane struct {
	id    int
	state *laneState
}

func (s *Set) snapshot() []selectedLane {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]selectedLane, 0, len(s.order))
	for _, id := range s.order {
		if lane := s.lanes[id]; lane != nil {
			result = append(result, selectedLane{id: id, state: lane})
		}
	}
	return result
}
