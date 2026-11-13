package app

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// trafficStats keeps hot-path accounting lock free. Window counters are swapped
// by the reporter while totals remain monotonic for post-incident correlation.
type trafficStats struct {
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64

	totalTxBytes atomic.Uint64
	totalRxBytes atomic.Uint64
}

func (s *trafficStats) sent(size int) {
	s.txPackets.Add(1)
	s.txBytes.Add(uint64(size))
	s.totalTxBytes.Add(uint64(size))
}

func (s *trafficStats) received(size int) {
	s.rxPackets.Add(1)
	s.rxBytes.Add(uint64(size))
	s.totalRxBytes.Add(uint64(size))
}

func (s *trafficStats) drop() { s.dropped.Add(1) }
func (s *trafficStats) fail() { s.errors.Add(1) }

func reportTraffic(ctx context.Context, logger *slog.Logger, interval time.Duration, scope string, s *trafficStats) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			elapsed := now.Sub(last).Seconds()
			last = now
			txPackets := s.txPackets.Swap(0)
			txBytes := s.txBytes.Swap(0)
			rxPackets := s.rxPackets.Swap(0)
			rxBytes := s.rxBytes.Swap(0)
			logger.Info("traffic stats",
				"scope", scope,
				"window", interval,
				"tx_packets", txPackets,
				"tx_mbps", float64(txBytes)*8/elapsed/1_000_000,
				"rx_packets", rxPackets,
				"rx_mbps", float64(rxBytes)*8/elapsed/1_000_000,
				"dropped", s.dropped.Swap(0),
				"errors", s.errors.Swap(0),
				"tx_total_bytes", s.totalTxBytes.Load(),
				"rx_total_bytes", s.totalRxBytes.Load(),
			)
		}
	}
}
