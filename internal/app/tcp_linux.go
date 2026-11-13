//go:build linux

package app

import (
	"net"
	"syscall"
	"time"
)

const tcpUserTimeout = 18

func setTCPUserTimeout(conn *net.TCPConn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(timeout/time.Millisecond))
	})
	if err != nil {
		return err
	}
	return socketErr
}
