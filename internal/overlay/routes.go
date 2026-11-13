package overlay

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

type Route struct {
	Prefix netip.Prefix
	Peer   string
}

type RouteTable struct {
	mu     sync.RWMutex
	routes map[netip.Prefix]string
}

func NewRouteTable() *RouteTable {
	return &RouteTable{routes: make(map[netip.Prefix]string)}
}

func (t *RouteTable) AddBatch(peer string, prefixes []netip.Prefix) error {
	if peer == "" {
		return errors.New("peer is required")
	}
	canonical := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return errors.New("invalid route prefix")
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		canonical = append(canonical, prefix)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, prefix := range canonical {
		if owner, exists := t.routes[prefix]; exists && owner != peer {
			return fmt.Errorf("route %s is already owned by peer %q", prefix, owner)
		}
	}
	for _, prefix := range canonical {
		t.routes[prefix] = peer
	}
	return nil
}

func (t *RouteTable) RemovePeer(peer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for prefix, owner := range t.routes {
		if owner == peer {
			delete(t.routes, prefix)
		}
	}
}

func (t *RouteTable) Lookup(target netip.Addr) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bestBits := -1
	bestPeer := ""
	for prefix, peer := range t.routes {
		if prefix.Bits() > bestBits && prefix.Contains(target) {
			bestBits = prefix.Bits()
			bestPeer = peer
		}
	}
	return bestPeer, bestBits >= 0
}

func (t *RouteTable) AllowsSource(peer string, source netip.Addr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for prefix, owner := range t.routes {
		if owner == peer && prefix.Contains(source) {
			return true
		}
	}
	return false
}

func (t *RouteTable) Snapshot() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	routes := make([]Route, 0, len(t.routes))
	for prefix, peer := range t.routes {
		routes = append(routes, Route{Prefix: prefix, Peer: peer})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Prefix.Bits() != routes[j].Prefix.Bits() {
			return routes[i].Prefix.Bits() > routes[j].Prefix.Bits()
		}
		if routes[i].Prefix.Addr() != routes[j].Prefix.Addr() {
			return routes[i].Prefix.Addr().Less(routes[j].Prefix.Addr())
		}
		return routes[i].Peer < routes[j].Peer
	})
	return routes
}
