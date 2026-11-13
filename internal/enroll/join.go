package enroll

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const prefix = "TLSNET1:"

type JoinCode struct {
	ServerAddress string `json:"server"`
	NetworkName   string `json:"network"`
	ServerName    string `json:"sni"`
	OverlayPool   string `json:"pool"`
	HomeNode      string `json:"home_node"`
	HomeSubnet    string `json:"home_subnet"`
}

func (c JoinCode) Encode() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func Decode(value string) (JoinCode, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix) {
		return JoinCode{}, errors.New("join code must start with TLSNET1:")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return JoinCode{}, errors.New("join code is not valid base64")
	}
	var code JoinCode
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&code); err != nil {
		return JoinCode{}, fmt.Errorf("decode join code: %w", err)
	}
	if err := code.Validate(); err != nil {
		return JoinCode{}, err
	}
	return code, nil
}

func (c JoinCode) Validate() error {
	host, portText, err := net.SplitHostPort(c.ServerAddress)
	if err != nil {
		return fmt.Errorf("join server address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if strings.TrimSpace(host) == "" || err != nil || port < 1 || port > 65535 {
		return errors.New("join server address requires a host and numeric port 1..65535")
	}
	if strings.TrimSpace(c.NetworkName) == "" || strings.TrimSpace(c.ServerName) == "" || strings.TrimSpace(c.HomeNode) == "" {
		return errors.New("join code is missing network, SNI, or home node")
	}
	pool, err := netip.ParsePrefix(c.OverlayPool)
	if err != nil || !pool.Addr().Is4() || pool.Bits() > 30 {
		return errors.New("join overlay pool must be an IPv4 /0../30 prefix")
	}
	home, err := netip.ParsePrefix(c.HomeSubnet)
	if err != nil || !home.Addr().Is4() {
		return errors.New("join home subnet must be IPv4")
	}
	pool = pool.Masked()
	home = home.Masked()
	if pool.Contains(home.Addr()) || home.Contains(pool.Addr()) {
		return errors.New("virtual network and home LAN subnet must not overlap")
	}
	return nil
}
