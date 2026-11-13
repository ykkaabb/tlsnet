package quicreality

import (
	"net"
	"sync"
	"time"
)

type UDPFallback struct {
	Listener    net.PacketConn
	Target      *net.UDPAddr
	IdleTimeout time.Duration
	MaxMappings int

	mu       sync.Mutex
	mappings map[string]*udpMapping
}

type udpMapping struct {
	conn     *net.UDPConn
	client   net.Addr
	lastSeen time.Time
}

func (f *UDPFallback) Forward(packet []byte, source net.Addr) {
	if f.Listener == nil || f.Target == nil || source == nil {
		return
	}
	mapping := f.mapping(source)
	if mapping == nil {
		return
	}
	_ = mapping.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = mapping.conn.Write(packet)
}

func (f *UDPFallback) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, mapping := range f.mappings {
		_ = mapping.conn.Close()
		delete(f.mappings, key)
	}
	return nil
}

func (f *UDPFallback) mapping(source net.Addr) *udpMapping {
	now := time.Now()
	idle := f.IdleTimeout
	if idle <= 0 {
		idle = 30 * time.Second
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mappings == nil {
		f.mappings = make(map[string]*udpMapping)
	}
	for key, mapping := range f.mappings {
		if now.Sub(mapping.lastSeen) > idle {
			_ = mapping.conn.Close()
			delete(f.mappings, key)
		}
	}
	key := source.String()
	if mapping := f.mappings[key]; mapping != nil {
		mapping.lastSeen = now
		return mapping
	}
	if f.MaxMappings > 0 && len(f.mappings) >= f.MaxMappings {
		return nil
	}
	conn, err := net.DialUDP("udp", nil, f.Target)
	if err != nil {
		return nil
	}
	mapping := &udpMapping{conn: conn, client: cloneAddr(source), lastSeen: now}
	f.mappings[key] = mapping
	go f.readReplies(key, mapping)
	return mapping
}

func (f *UDPFallback) readReplies(key string, mapping *udpMapping) {
	buffer := make([]byte, 64*1024)
	for {
		n, err := mapping.conn.Read(buffer)
		if err != nil {
			return
		}
		_, _ = f.Listener.WriteTo(buffer[:n], mapping.client)
		f.mu.Lock()
		if current := f.mappings[key]; current == mapping {
			mapping.lastSeen = time.Now()
		}
		f.mu.Unlock()
	}
}

func cloneAddr(address net.Addr) net.Addr {
	if udp, ok := address.(*net.UDPAddr); ok {
		copyAddr := *udp
		copyAddr.IP = append(net.IP(nil), udp.IP...)
		return &copyAddr
	}
	return address
}
