//go:build !linux

package app

import (
	"net"
	"time"
)

func setTCPUserTimeout(*net.TCPConn, time.Duration) error { return nil }
