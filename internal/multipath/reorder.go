package multipath

import (
	"container/heap"
	"context"
	"time"

	"github.com/ykkaabb/tlsnet/internal/wire"
)

type Reorderer struct {
	Wait       time.Duration
	MaxPending int
}

func (r Reorderer) Run(ctx context.Context, input <-chan wire.Frame, output chan<- wire.Frame) {
	wait := r.Wait
	if wait <= 0 {
		wait = 5 * time.Millisecond
	}
	maxPending := r.MaxPending
	if maxPending <= 0 {
		maxPending = 1024
	}
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	defer timer.Stop()

	pending := &frameHeap{}
	heap.Init(pending)
	var expected uint64 = 1
	var waiting bool
	emit := func(frame wire.Frame) bool {
		select {
		case output <- frame:
			return true
		case <-ctx.Done():
			return false
		}
	}
	drain := func() bool {
		for pending.Len() != 0 && (*pending)[0].Sequence == expected {
			frame := heap.Pop(pending).(wire.Frame)
			if !emit(frame) {
				return false
			}
			expected++
		}
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-input:
			if !ok {
				for pending.Len() != 0 {
					frame := heap.Pop(pending).(wire.Frame)
					if frame.Sequence >= expected && !emit(frame) {
						return
					}
				}
				return
			}
			if frame.Sequence < expected {
				continue
			}
			if frame.Sequence == expected {
				if !emit(frame) {
					return
				}
				expected++
				if !drain() {
					return
				}
			} else {
				heap.Push(pending, frame)
			}
			if pending.Len() > maxPending {
				frame := heap.Pop(pending).(wire.Frame)
				if frame.Sequence >= expected {
					expected = frame.Sequence + 1
					if !emit(frame) || !drain() {
						return
					}
				}
			}
			if pending.Len() != 0 && !waiting {
				timer.Reset(wait)
				waiting = true
			}
			if pending.Len() == 0 && waiting {
				stopTimer(timer)
				waiting = false
			}
		case <-timer.C:
			waiting = false
			if pending.Len() != 0 {
				frame := heap.Pop(pending).(wire.Frame)
				if frame.Sequence >= expected {
					expected = frame.Sequence + 1
					if !emit(frame) || !drain() {
						return
					}
				}
			}
			if pending.Len() != 0 {
				timer.Reset(wait)
				waiting = true
			}
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

type frameHeap []wire.Frame

func (h frameHeap) Len() int           { return len(h) }
func (h frameHeap) Less(i, j int) bool { return h[i].Sequence < h[j].Sequence }
func (h frameHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *frameHeap) Push(value any)    { *h = append(*h, value.(wire.Frame)) }
func (h *frameHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
