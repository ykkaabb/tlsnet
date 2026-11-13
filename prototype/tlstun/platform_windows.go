//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"time"
)

func openTun(*tunConfig) (tunDevice, error) { return nil, errors.New("TUN mode is Linux only") }
func waitTunReadable(context.Context, uintptr, time.Duration) (bool, error) {
	return false, errors.New("TUN mode is Linux only")
}
func setSocketOptions(tcp *net.TCPConn, _ performanceConfig) error { return tcp.SetNoDelay(true) }

type tcpInfo struct{ RTTUS, RTTVarUS, CWND, Unacked, Lost, Retrans, TotalRetrans, PMTU uint32 }

func readTCPInfo(*net.TCPConn) (tcpInfo, bool) { return tcpInfo{}, false }
