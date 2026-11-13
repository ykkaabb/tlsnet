package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	laneQueueDepth   = 8
	maxLanes         = 16
	frameHeaderSize  = 12
	maxReorderFrames = 256
)

var (
	laneMagic = []byte("LANE0005")
	laneOK    = []byte("LN05")
)

type laneMeta struct {
	Group [16]byte
	Index uint16
	Count uint16
}

func laneMetaBytes(meta laneMeta) []byte {
	b := make([]byte, 20)
	copy(b[:16], meta.Group[:])
	binary.BigEndian.PutUint16(b[16:18], meta.Index)
	binary.BigEndian.PutUint16(b[18:20], meta.Count)
	return b
}

func laneAuthTag(key, role, meta []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("TlsTun v0.5 lane "))
	_, _ = h.Write(role)
	_, _ = h.Write(meta)
	return h.Sum(nil)
}

func clientJoinLane(conn net.Conn, key []byte, meta laneMeta) error {
	metadata := laneMetaBytes(meta)
	request := make([]byte, 0, len(laneMagic)+len(metadata)+sha256.Size)
	request = append(request, laneMagic...)
	request = append(request, metadata...)
	request = append(request, laneAuthTag(key, []byte("client"), metadata)...)
	if err := writeAll(conn, request); err != nil {
		return err
	}
	response := make([]byte, len(laneOK)+sha256.Size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	expected := append(append([]byte{}, laneOK...), laneAuthTag(key, []byte("server"), metadata)...)
	if !hmac.Equal(response, expected) {
		return errors.New("lane authentication failed")
	}
	return nil
}

func serverJoinLane(conn net.Conn, key []byte) (laneMeta, error) {
	var meta laneMeta
	request := make([]byte, len(laneMagic)+20+sha256.Size)
	if _, err := io.ReadFull(conn, request); err != nil {
		return meta, err
	}
	if !hmac.Equal(request[:len(laneMagic)], laneMagic) {
		return meta, errors.New("client does not support parallel TLS lanes")
	}
	metadata := request[len(laneMagic) : len(laneMagic)+20]
	if !hmac.Equal(request[len(laneMagic)+20:], laneAuthTag(key, []byte("client"), metadata)) {
		return meta, errors.New("lane authentication failed")
	}
	copy(meta.Group[:], metadata[:16])
	meta.Index = binary.BigEndian.Uint16(metadata[16:18])
	meta.Count = binary.BigEndian.Uint16(metadata[18:20])
	if meta.Count < 1 || meta.Count > maxLanes || meta.Index >= meta.Count {
		return laneMeta{}, errors.New("invalid lane metadata")
	}
	response := append(append([]byte{}, laneOK...), laneAuthTag(key, []byte("server"), metadata)...)
	if err := writeAll(conn, response); err != nil {
		return laneMeta{}, err
	}
	return meta, nil
}

type packetFrame struct {
	data     []byte
	payload  int
	sequence uint64
}

type tunnelLane struct {
	meta         laneMeta
	tlsConn      *tls.Conn
	tcp          *net.TCPConn
	send         chan *packetFrame
	dispatchMu   sync.Mutex
	active       atomic.Bool
	pendingBytes atomic.Int64
	rttUS        atomic.Uint32
	avoidUntilNS atomic.Int64
}

func newTunnelLane(meta laneMeta, tlsConn *tls.Conn, tcp *net.TCPConn) *tunnelLane {
	lane := &tunnelLane{meta: meta, tlsConn: tlsConn, tcp: tcp, send: make(chan *packetFrame, laneQueueDepth)}
	lane.active.Store(true)
	return lane
}

func closeLanes(lanes []*tunnelLane) {
	for _, lane := range lanes {
		if lane != nil {
			_ = lane.tlsConn.Close()
		}
	}
}

type multiCounters struct {
	txPackets, txBytes, rxPackets, rxBytes atomic.Uint64
	wTxPackets, wTxBytes                   atomic.Uint64
	wRxPackets, wRxBytes                   atomic.Uint64
	txDrops, wTxDrops                      atomic.Uint64
	rxLateDrops, rxGapDrops                atomic.Uint64
	wRxLateDrops, wRxGapDrops              atomic.Uint64
	slowWrites                             atomic.Uint64
	tlsWriteMaxNS, tunWriteMaxNS           atomic.Uint64
	sessionTLSMaxNS, sessionTunMaxNS       atomic.Uint64
}

func (s *multiCounters) recordTX(n int, d, slow time.Duration) {
	s.txPackets.Add(1)
	s.txBytes.Add(uint64(n))
	s.wTxPackets.Add(1)
	s.wTxBytes.Add(uint64(n))
	atomicMax(&s.tlsWriteMaxNS, uint64(d))
	atomicMax(&s.sessionTLSMaxNS, uint64(d))
	if d >= slow {
		s.slowWrites.Add(1)
	}
}

func (s *multiCounters) recordRX(n int, d time.Duration) {
	s.rxPackets.Add(1)
	s.rxBytes.Add(uint64(n))
	s.wRxPackets.Add(1)
	s.wRxBytes.Add(uint64(n))
	atomicMax(&s.tunWriteMaxNS, uint64(d))
	atomicMax(&s.sessionTunMaxNS, uint64(d))
}

func (s *multiCounters) recordDrop() {
	s.txDrops.Add(1)
	s.wTxDrops.Add(1)
}

func (s *multiCounters) recordLateDrop() {
	s.rxLateDrops.Add(1)
	s.wRxLateDrops.Add(1)
}

func (s *multiCounters) recordGapDrop(n uint64) {
	s.rxGapDrops.Add(n)
	s.wRxGapDrops.Add(n)
}

func monitorLaneHealth(ctx context.Context, lanes []*tunnelLane) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	previous := make([]uint32, len(lanes))
	for i, lane := range lanes {
		if health, ok := readTCPInfo(lane.tcp); ok {
			previous[i] = health.TotalRetrans
			lane.rttUS.Store(health.RTTUS)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for i, lane := range lanes {
				if !lane.active.Load() {
					continue
				}
				health, ok := readTCPInfo(lane.tcp)
				if !ok {
					continue
				}
				lane.rttUS.Store(health.RTTUS)
				if health.TotalRetrans > previous[i] || health.Lost > 0 || health.Retrans > 0 {
					lane.avoidUntilNS.Store(now.Add(500 * time.Millisecond).UnixNano())
				}
				previous[i] = health.TotalRetrans
			}
		}
	}
}

func reportMultiStats(ctx context.Context, stats *multiCounters, lanes []*tunnelLane, cfg diagnosticsConfig) {
	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	previous := make([]uint32, len(lanes))
	for i, lane := range lanes {
		if health, ok := readTCPInfo(lane.tcp); ok {
			previous[i] = health.TotalRetrans
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			txp, txb := stats.wTxPackets.Swap(0), stats.wTxBytes.Swap(0)
			rxp, rxb := stats.wRxPackets.Swap(0), stats.wRxBytes.Swap(0)
			drops := stats.wTxDrops.Swap(0)
			lateDrops := stats.wRxLateDrops.Swap(0)
			gapDrops := stats.wRxGapDrops.Swap(0)
			tlsMax := time.Duration(stats.tlsWriteMaxNS.Swap(0))
			tunMax := time.Duration(stats.tunWriteMaxNS.Swap(0))
			slow := stats.slowWrites.Swap(0)
			var rttMax, rttVarMax, cwndTotal, unackedTotal, lostTotal, retransNowTotal, retransTotal, retransDelta, pmtu uint32
			active := 0
			for i, lane := range lanes {
				if !lane.active.Load() {
					continue
				}
				h, ok := readTCPInfo(lane.tcp)
				if !ok {
					continue
				}
				active++
				delta := h.TotalRetrans - previous[i]
				previous[i] = h.TotalRetrans
				if h.RTTUS > rttMax {
					rttMax = h.RTTUS
				}
				if h.RTTVarUS > rttVarMax {
					rttVarMax = h.RTTVarUS
				}
				if h.PMTU > pmtu {
					pmtu = h.PMTU
				}
				cwndTotal += h.CWND
				unackedTotal += h.Unacked
				lostTotal += h.Lost
				retransNowTotal += h.Retrans
				retransTotal += h.TotalRetrans
				retransDelta += delta
				if delta > 0 || h.Lost > 0 || h.Retrans > 0 {
					log.Printf("lane_health lane=%d tcp_rtt=%.3fms rttvar=%.3fms cwnd=%d unacked=%d lost=%d retrans_now=%d retrans_total=%d retrans_delta=%d", i, float64(h.RTTUS)/1000, float64(h.RTTVarUS)/1000, h.CWND, h.Unacked, h.Lost, h.Retrans, h.TotalRetrans, delta)
				}
			}
			seconds := float64(cfg.IntervalSeconds)
			log.Printf("stats window=%ds lanes=%d/%d tx=%dpkts/%dbytes/%.2fMbps rx=%dpkts/%dbytes/%.2fMbps tx_drops=%d rx_late_drops=%d rx_gap_drops=%d tls_write_max=%.1fms slow_writes=%d tun_write_max=%.1fms tcp_rtt_max=%.3fms rttvar_max=%.3fms cwnd_total=%d unacked=%d lost=%d retrans_now=%d retrans_total=%d retrans_delta=%d pmtu=%d", cfg.IntervalSeconds, active, len(lanes), txp, txb, float64(txb)*8/seconds/1e6, rxp, rxb, float64(rxb)*8/seconds/1e6, drops, lateDrops, gapDrops, float64(tlsMax)/float64(time.Millisecond), slow, float64(tunMax)/float64(time.Millisecond), float64(rttMax)/1000, float64(rttVarMax)/1000, cwndTotal, unackedTotal, lostTotal, retransNowTotal, retransTotal, retransDelta, pmtu)
		}
	}
}

func sendBridgeError(ch chan<- error, err error) {
	if err == nil {
		err = errors.New("tunnel lane stopped")
	}
	select {
	case ch <- err:
	default:
	}
}

func chooseLane(lanes []*tunnelLane, next int, nowNS int64) int {
	best := -1
	bestScore := int64(^uint64(0) >> 1)
	for offset := 0; offset < len(lanes); offset++ {
		idx := (next + offset) % len(lanes)
		lane := lanes[idx]
		if !lane.active.Load() {
			continue
		}
		if len(lane.send) >= cap(lane.send) {
			continue
		}
		score := lane.pendingBytes.Load() + int64(lane.rttUS.Load()/4)
		if nowNS < lane.avoidUntilNS.Load() {
			score += 1 << 50
		}
		if score < bestScore {
			best, bestScore = idx, score
		}
	}
	return best
}

func smallestSequence(pending map[uint64]*packetFrame) uint64 {
	var smallest uint64
	for sequence := range pending {
		if smallest == 0 || sequence < smallest {
			smallest = sequence
		}
	}
	return smallest
}

func reorderToTun(ctx context.Context, tun tunDevice, received <-chan *packetFrame, stats *multiCounters, pool *sync.Pool, wait time.Duration) error {
	pending := make(map[uint64]*packetFrame)
	expected := uint64(1)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerC <-chan time.Time
	armTimer := func() {
		if timerC != nil {
			return
		}
		timer.Reset(wait)
		timerC = timer.C
	}
	stopTimer := func() {
		if timerC == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	deliver := func(frame *packetFrame) error {
		started := time.Now()
		err := writeAll(tun, frame.data[frameHeaderSize:frameHeaderSize+frame.payload])
		if err == nil {
			stats.recordRX(frame.payload, time.Since(started))
		}
		pool.Put(frame)
		return err
	}
	flush := func() error {
		for {
			frame := pending[expected]
			if frame == nil {
				break
			}
			delete(pending, expected)
			expected++
			if err := deliver(frame); err != nil {
				return err
			}
		}
		if len(pending) == 0 {
			stopTimer()
		} else {
			armTimer()
		}
		return nil
	}
	defer func() {
		for _, frame := range pending {
			pool.Put(frame)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-received:
			if frame.sequence < expected {
				stats.recordLateDrop()
				pool.Put(frame)
				continue
			}
			if _, duplicate := pending[frame.sequence]; duplicate {
				stats.recordLateDrop()
				pool.Put(frame)
				continue
			}
			pending[frame.sequence] = frame
			if frame.sequence == expected {
				if err := flush(); err != nil {
					return err
				}
			} else {
				armTimer()
			}
			if len(pending) >= maxReorderFrames {
				smallest := smallestSequence(pending)
				if smallest > expected {
					stats.recordGapDrop(smallest - expected)
					expected = smallest
				}
				if err := flush(); err != nil {
					return err
				}
			}
		case <-timerC:
			timerC = nil
			smallest := smallestSequence(pending)
			if smallest > expected {
				stats.recordGapDrop(smallest - expected)
				expected = smallest
			}
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func bridgeMulti(parent context.Context, tun tunDevice, lanes []*tunnelLane, diag diagnosticsConfig, performance performanceConfig) error {
	if len(lanes) == 0 {
		return errors.New("no TLS lanes")
	}
	ctx, cancel := context.WithCancel(parent)
	stats := &multiCounters{}
	errorsCh := make(chan error, len(lanes)*2+2)
	receivedCh := make(chan *packetFrame, maxReorderFrames)
	slow := time.Duration(diag.SlowWriteMS) * time.Millisecond
	framePool := sync.Pool{New: func() any { return &packetFrame{data: make([]byte, maxPacket+frameHeaderSize)} }}
	var wg sync.WaitGroup
	var activeLanes atomic.Int32
	activeLanes.Store(int32(len(lanes)))
	failLane := func(lane *tunnelLane, err error) {
		if ctx.Err() != nil || !lane.active.CompareAndSwap(true, false) {
			return
		}
		_ = lane.tlsConn.Close()
		dropped := 0
		lane.dispatchMu.Lock()
		defer lane.dispatchMu.Unlock()
		for {
			select {
			case frame := <-lane.send:
				lane.pendingBytes.Add(-int64(frame.payload + frameHeaderSize))
				stats.recordDrop()
				framePool.Put(frame)
				dropped++
			default:
				remaining := activeLanes.Add(-1)
				log.Printf("WARNING lane=%d disabled after error: %v; active_lanes=%d/%d queued_packets_dropped=%d", lane.meta.Index, err, remaining, len(lanes), dropped)
				if remaining == 0 {
					sendBridgeError(errorsCh, fmt.Errorf("all TLS lanes failed; last lane %d: %w", lane.meta.Index, err))
				}
				return
			}
		}
	}

	go reportMultiStats(ctx, stats, lanes, diag)
	go monitorLaneHealth(ctx, lanes)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reorderToTun(ctx, tun, receivedCh, stats, &framePool, time.Duration(performance.ReorderWaitMS)*time.Millisecond); err != nil {
			sendBridgeError(errorsCh, err)
		}
	}()
	for _, lane := range lanes {
		lane := lane
		wg.Add(1)
		go func() {
			defer wg.Done()
			keepalive := time.NewTicker(15 * time.Second)
			defer keepalive.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case frame := <-lane.send:
					started := time.Now()
					err := writeAll(lane.tlsConn, frame.data[:frame.payload+frameHeaderSize])
					elapsed := time.Since(started)
					lane.pendingBytes.Add(-int64(frame.payload + frameHeaderSize))
					stats.recordTX(frame.payload, elapsed, slow)
					framePool.Put(frame)
					if elapsed >= slow {
						log.Printf("WARNING lane=%d TLS write blocked for %.1fms; other lanes remain available", lane.meta.Index, float64(elapsed)/float64(time.Millisecond))
					}
					if err != nil {
						failLane(lane, fmt.Errorf("write: %w", err))
						return
					}
				case <-keepalive.C:
					if err := writeAll(lane.tlsConn, make([]byte, frameHeaderSize)); err != nil {
						failLane(lane, fmt.Errorf("keepalive: %w", err))
						return
					}
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				frame := framePool.Get().(*packetFrame)
				if _, err := io.ReadFull(lane.tlsConn, frame.data[:frameHeaderSize]); err != nil {
					framePool.Put(frame)
					failLane(lane, fmt.Errorf("read header: %w", err))
					return
				}
				n := int(binary.BigEndian.Uint32(frame.data[:4]))
				if n > maxPacket {
					framePool.Put(frame)
					failLane(lane, fmt.Errorf("invalid frame length %d", n))
					return
				}
				if n == 0 {
					framePool.Put(frame)
					continue
				}
				frame.payload = n
				frame.sequence = binary.BigEndian.Uint64(frame.data[4:frameHeaderSize])
				if frame.sequence == 0 {
					framePool.Put(frame)
					failLane(lane, errors.New("invalid zero sequence"))
					return
				}
				if _, err := io.ReadFull(lane.tlsConn, frame.data[frameHeaderSize:frameHeaderSize+n]); err != nil {
					framePool.Put(frame)
					failLane(lane, fmt.Errorf("read packet: %w", err))
					return
				}
				select {
				case receivedCh <- frame:
				case <-ctx.Done():
					framePool.Put(frame)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		next := 0
		sequence := uint64(1)
		for {
			ready, err := waitTunReadable(ctx, tun.Fd(), time.Second)
			if err != nil {
				sendBridgeError(errorsCh, err)
				return
			}
			if !ready {
				continue
			}
			frame := framePool.Get().(*packetFrame)
			n, err := tun.Read(frame.data[frameHeaderSize:])
			if err != nil {
				framePool.Put(frame)
				sendBridgeError(errorsCh, err)
				return
			}
			if n <= 0 {
				framePool.Put(frame)
				continue
			}
			frame.payload = n
			frame.sequence = sequence
			sequence++
			binary.BigEndian.PutUint32(frame.data[:4], uint32(n))
			binary.BigEndian.PutUint64(frame.data[4:frameHeaderSize], frame.sequence)
			deadline := time.Now().Add(2 * time.Millisecond)
			dispatched := false
			for !dispatched {
				idx := chooseLane(lanes, next, time.Now().UnixNano())
				if idx < 0 {
					if time.Now().After(deadline) {
						break
					}
					time.Sleep(100 * time.Microsecond)
					continue
				}
				lane := lanes[idx]
				lane.dispatchMu.Lock()
				if !lane.active.Load() {
					lane.dispatchMu.Unlock()
					continue
				}
				lane.pendingBytes.Add(int64(n + frameHeaderSize))
				select {
				case lane.send <- frame:
					next = (idx + 1) % len(lanes)
					dispatched = true
				case <-ctx.Done():
					lane.pendingBytes.Add(-int64(n + frameHeaderSize))
					lane.dispatchMu.Unlock()
					framePool.Put(frame)
					return
				default:
					lane.pendingBytes.Add(-int64(n + frameHeaderSize))
				}
				lane.dispatchMu.Unlock()
			}
			if !dispatched {
				stats.recordDrop()
				framePool.Put(frame)
			}
		}
	}()

	err := <-errorsCh
	cancel()
	closeLanes(lanes)
	wg.Wait()
	for _, lane := range lanes {
		for {
			select {
			case frame := <-lane.send:
				lane.pendingBytes.Add(-int64(frame.payload + frameHeaderSize))
				framePool.Put(frame)
			default:
				goto drained
			}
		}
	drained:
	}
	for {
		select {
		case frame := <-receivedCh:
			framePool.Put(frame)
		default:
			goto receivedDrained
		}
	}
receivedDrained:
	log.Printf("session summary lanes=%d tx=%dpkts/%dbytes rx=%dpkts/%dbytes tx_drops=%d rx_late_drops=%d rx_gap_drops=%d tls_write_max=%.1fms tun_write_max=%.1fms", len(lanes), stats.txPackets.Load(), stats.txBytes.Load(), stats.rxPackets.Load(), stats.rxBytes.Load(), stats.txDrops.Load(), stats.rxLateDrops.Load(), stats.rxGapDrops.Load(), float64(stats.sessionTLSMaxNS.Load())/float64(time.Millisecond), float64(stats.sessionTunMaxNS.Load())/float64(time.Millisecond))
	return err
}

type acceptedLane struct {
	lane *tunnelLane
	err  error
}

func acceptMultiLane(ctx context.Context, raw net.Conn, c *config, tlsCfg *tls.Config, key []byte, fp [32]byte) (*tunnelLane, error) {
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return nil, errors.New("accepted connection is not TCP")
	}
	if err := setSocketOptions(tcp, c.Performance); err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Server(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := serverAuthenticate(tlsConn, key, fp); err != nil {
		return nil, err
	}
	meta, err := serverJoinLane(tlsConn, key)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return newTunnelLane(meta, tlsConn, tcp), nil
}

type pendingLaneGroup struct {
	count   int
	lanes   []*tunnelLane
	created time.Time
}

func groupText(group [16]byte) string { return hex.EncodeToString(group[:4]) }

func runMultiServer(ctx context.Context, c *config, tun tunDevice, key []byte) error {
	tlsCfg, fp, err := serverTLSConfig(c)
	if err != nil {
		return err
	}
	listen := c.TLS.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(listen, fmt.Sprint(c.TLS.Port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	log.Printf("TLS server listening on %s:%d; lanes=%d; camouflage SNI %s; certificate SHA-256 %s", listen, c.TLS.Port, c.Performance.ParallelConnections, c.TLS.ServerName, fingerprintText(fp))

	acceptedCh := make(chan acceptedLane, maxLanes*2)
	acceptErrCh := make(chan error, 1)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				select {
				case acceptErrCh <- err:
				default:
				}
				return
			}
			go func(raw net.Conn) {
				lane, err := acceptMultiLane(ctx, raw, c, tlsCfg, key, fp)
				if err != nil {
					_ = raw.Close()
				}
				select {
				case acceptedCh <- acceptedLane{lane: lane, err: err}:
				case <-ctx.Done():
					if lane != nil {
						_ = lane.tlsConn.Close()
					}
				}
			}(raw)
		}
	}()

	pending := make(map[[16]byte]*pendingLaneGroup)
	bridgeDone := make(chan error, 1)
	cleanup := time.NewTicker(5 * time.Second)
	defer cleanup.Stop()
	active := false
	for {
		select {
		case <-ctx.Done():
			for _, group := range pending {
				closeLanes(group.lanes)
			}
			return nil
		case err := <-acceptErrCh:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case result := <-acceptedCh:
			if result.err != nil {
				log.Printf("TLS lane rejected: %v", result.err)
				continue
			}
			lane := result.lane
			if active {
				log.Printf("rejecting extra group %s while a tunnel is active", groupText(lane.meta.Group))
				_ = lane.tlsConn.Close()
				continue
			}
			group := pending[lane.meta.Group]
			if group == nil {
				group = &pendingLaneGroup{count: int(lane.meta.Count), lanes: make([]*tunnelLane, int(lane.meta.Count)), created: time.Now()}
				pending[lane.meta.Group] = group
			}
			if group.count != int(lane.meta.Count) || group.lanes[lane.meta.Index] != nil {
				log.Printf("rejecting inconsistent lane %d for group %s", lane.meta.Index, groupText(lane.meta.Group))
				_ = lane.tlsConn.Close()
				continue
			}
			group.lanes[lane.meta.Index] = lane
			complete := true
			for _, item := range group.lanes {
				if item == nil {
					complete = false
					break
				}
			}
			if complete {
				delete(pending, lane.meta.Group)
				for id, stale := range pending {
					closeLanes(stale.lanes)
					delete(pending, id)
				}
				active = true
				log.Printf("tunnel group %s connected with %d independent TLS lanes", groupText(lane.meta.Group), len(group.lanes))
				go func(lanes []*tunnelLane) { bridgeDone <- bridgeMulti(ctx, tun, lanes, c.Diagnostics, c.Performance) }(group.lanes)
			}
		case err := <-bridgeDone:
			active = false
			if ctx.Err() == nil {
				log.Printf("tunnel group closed: %v", err)
			}
		case now := <-cleanup.C:
			for id, group := range pending {
				if now.Sub(group.created) > 20*time.Second {
					log.Printf("incomplete tunnel group %s expired", groupText(id))
					closeLanes(group.lanes)
					delete(pending, id)
				}
			}
		}
	}

}

type dialLaneResult struct {
	lane *tunnelLane
	err  error
}

func dialClientMultiLane(ctx context.Context, c *config, key []byte, meta laneMeta) (*tunnelLane, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.TLS.Server, fmt.Sprint(c.TLS.Port)))
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	tcp := raw.(*net.TCPConn)
	if err := setSocketOptions(tcp, c.Performance); err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(raw, clientTLSConfig(c))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server provided no certificate")
	}
	fp := fingerprint(state.PeerCertificates[0].Raw)
	if err := clientAuthenticate(tlsConn, key, fp); err != nil {
		return nil, err
	}
	if err := clientJoinLane(tlsConn, key, meta); err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	success = true
	return newTunnelLane(meta, tlsConn, tcp), nil
}

func dialMultiGroup(ctx context.Context, c *config, key []byte, group [16]byte) ([]*tunnelLane, error) {
	count := c.Performance.ParallelConnections
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialLaneResult, count)
	for i := 0; i < count; i++ {
		meta := laneMeta{Group: group, Index: uint16(i), Count: uint16(count)}
		go func(meta laneMeta) {
			lane, err := dialClientMultiLane(attemptCtx, c, key, meta)
			results <- dialLaneResult{lane: lane, err: err}
		}(meta)
	}
	lanes := make([]*tunnelLane, 0, count)
	var firstErr error
	for i := 0; i < count; i++ {
		result := <-results
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		lanes = append(lanes, result.lane)
	}
	if firstErr != nil || len(lanes) != count {
		closeLanes(lanes)
		if firstErr == nil {
			firstErr = errors.New("incomplete TLS lane group")
		}
		return nil, firstErr
	}
	sort.Slice(lanes, func(i, j int) bool { return lanes[i].meta.Index < lanes[j].meta.Index })
	return lanes, nil
}

func runMultiClient(ctx context.Context, c *config, tun tunDevice, key []byte) error {
	delay := time.Second
	for ctx.Err() == nil {
		var group [16]byte
		if _, err := rand.Read(group[:]); err != nil {
			return err
		}
		lanes, err := dialMultiGroup(ctx, c, key, group)
		if err == nil {
			state := lanes[0].tlsConn.ConnectionState()
			fp := fingerprint(state.PeerCertificates[0].Raw)
			log.Printf("tunnel group %s connected with %d independent TLS lanes; TLS 0x%x %s; SNI %s; authenticated certificate SHA-256 %s", groupText(group), len(lanes), state.Version, tls.CipherSuiteName(state.CipherSuite), c.TLS.ServerName, fingerprintText(fp))
			delay = time.Second
			err = bridgeMulti(ctx, tun, lanes, c.Diagnostics, c.Performance)
		}
		closeLanes(lanes)
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("connect/disconnect: %v; retrying in %s", err, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
	return nil
}
