package control

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

type Allocator struct {
	mu       sync.Mutex
	pool     netip.Prefix
	reserved map[netip.Addr]struct{}
	byNode   map[string]netip.Addr
	byAddr   map[netip.Addr]string
}

func NewAllocator(pool netip.Prefix, reserved ...netip.Addr) (*Allocator, error) {
	pool = pool.Masked()
	if !pool.IsValid() || !pool.Addr().Is4() || pool.Bits() > 30 {
		return nil, errors.New("overlay pool must be an IPv4 prefix of /30 or larger")
	}
	a := &Allocator{
		pool:     pool,
		reserved: make(map[netip.Addr]struct{}),
		byNode:   make(map[string]netip.Addr),
		byAddr:   make(map[netip.Addr]string),
	}
	a.reserved[pool.Addr()] = struct{}{}
	last := pool.Addr()
	for next := last.Next(); pool.Contains(next); next = next.Next() {
		last = next
	}
	a.reserved[last] = struct{}{}
	for _, address := range reserved {
		if address.IsValid() {
			a.reserved[address.Unmap()] = struct{}{}
		}
	}
	return a, nil
}

func (a *Allocator) Allocate(node string, requested netip.Addr) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if current, ok := a.byNode[node]; ok {
		return current, nil
	}
	if requested.IsValid() {
		requested = requested.Unmap()
		if err := a.available(requested); err != nil {
			return netip.Addr{}, err
		}
		a.assign(node, requested)
		return requested, nil
	}
	for address := a.pool.Addr().Next(); a.pool.Contains(address); address = address.Next() {
		if a.available(address) == nil {
			a.assign(node, address)
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("overlay address pool is exhausted")
}

func (a *Allocator) Release(node string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if address, ok := a.byNode[node]; ok {
		delete(a.byNode, node)
		delete(a.byAddr, address)
	}
}

func (a *Allocator) available(address netip.Addr) error {
	if !a.pool.Contains(address) {
		return fmt.Errorf("requested address %s is outside overlay pool", address)
	}
	if _, reserved := a.reserved[address]; reserved {
		return fmt.Errorf("requested address %s is reserved", address)
	}
	if node, used := a.byAddr[address]; used {
		return fmt.Errorf("requested address %s is used by node %q", address, node)
	}
	return nil
}

func (a *Allocator) assign(node string, address netip.Addr) {
	a.byNode[node] = address
	a.byAddr[address] = node
}
