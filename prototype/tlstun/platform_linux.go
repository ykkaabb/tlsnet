//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const tunSetIFF = 0x400454ca
const iffTun = 0x0001
const iffNoPI = 0x1000

type ifReq struct {
	Name    [16]byte
	Flags   uint16
	Padding [22]byte
}
type fileTun struct{ *os.File }

func openTun(c *tunConfig) (tunDevice, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var req ifReq
	copy(req.Name[:], c.Name)
	req.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	if err := configureTun(c); err != nil {
		f.Close()
		return nil, err
	}
	return &fileTun{f}, nil
}

func configureTun(c *tunConfig) error {
	commands := [][]string{{"link", "set", "dev", c.Name, "mtu", fmt.Sprint(c.MTU)}, {"addr", "replace", c.Address, "dev", c.Name}, {"link", "set", "dev", c.Name, "up"}}
	for _, route := range c.Routes {
		commands = append(commands, []string{"route", "replace", route, "dev", c.Name})
	}
	for _, args := range commands {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, output)
		}
	}
	return nil
}

func waitTunReadable(ctx context.Context, fd uintptr, timeout time.Duration) (bool, error) {
	if fd >= 1024 {
		return false, errors.New("TUN fd exceeds select limit")
	}
	var set syscall.FdSet
	set.Bits[fd/64] |= 1 << (fd % 64)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	n, err := syscall.Select(int(fd)+1, &set, nil, nil, &tv)
	if err == syscall.EINTR {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	return n > 0, nil
}

func setSocketOptions(tcp *net.TCPConn, p performanceConfig) error {
	if err := tcp.SetNoDelay(true); err != nil {
		return err
	}
	if err := tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}); err != nil {
		return err
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		if p.TCPUserTimeoutSecond > 0 {
			controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 18, p.TCPUserTimeoutSecond*1000)
		}
		if controlErr == nil && p.SocketBufferBytes > 0 {
			controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, p.SocketBufferBytes)
			if controlErr == nil {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, p.SocketBufferBytes)
			}
		}
	})
	if err != nil {
		return err
	}
	return controlErr
}

type tcpInfo struct{ RTTUS, RTTVarUS, CWND, Unacked, Lost, Retrans, TotalRetrans, PMTU uint32 }

func readTCPInfo(tcp *net.TCPConn) (tcpInfo, bool) {
	var result tcpInfo
	raw, err := tcp.SyscallConn()
	if err != nil {
		return result, false
	}
	ok := true
	err = raw.Control(func(fd uintptr) {
		var data [104]byte
		length := uint32(len(data))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&length)), 0)
		if errno != 0 || length < 104 {
			ok = false
			return
		}
		result.Unacked = binary.NativeEndian.Uint32(data[24:28])
		result.Lost = binary.NativeEndian.Uint32(data[32:36])
		result.Retrans = binary.NativeEndian.Uint32(data[36:40])
		result.PMTU = binary.NativeEndian.Uint32(data[60:64])
		result.RTTUS = binary.NativeEndian.Uint32(data[68:72])
		result.RTTVarUS = binary.NativeEndian.Uint32(data[72:76])
		result.CWND = binary.NativeEndian.Uint32(data[80:84])
		result.TotalRetrans = binary.NativeEndian.Uint32(data[100:104])
	})
	return result, err == nil && ok
}
