package control

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

const MaxMessageSize = 16 * 1024

type Hello struct {
	Node             string   `json:"node"`
	Role             string   `json:"role"`
	RequestedAddress string   `json:"requested_address,omitempty"`
	AdvertiseRoutes  []string `json:"advertise_routes,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	Lane             int      `json:"lane"`
	Auth             string   `json:"auth,omitempty"`
}

func SignHello(hello *Hello, key []byte) error {
	if hello == nil || len(key) == 0 {
		return errors.New("hello and authentication key are required")
	}
	hello.Auth = ""
	encoded, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tlsnet/control-hello/v1\x00"))
	_, _ = mac.Write(encoded)
	hello.Auth = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return nil
}

func VerifyHello(hello Hello, key []byte) bool {
	provided, err := base64.RawURLEncoding.DecodeString(hello.Auth)
	if err != nil || len(provided) != sha256.Size || len(key) == 0 {
		return false
	}
	hello.Auth = ""
	encoded, err := json.Marshal(hello)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tlsnet/control-hello/v1\x00"))
	_, _ = mac.Write(encoded)
	return hmac.Equal(provided, mac.Sum(nil))
}

type Welcome struct {
	Accepted  bool     `json:"accepted"`
	Error     string   `json:"error,omitempty"`
	Address   string   `json:"address,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
}

func Encode(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxMessageSize {
		return nil, errors.New("control message is too large")
	}
	return encoded, nil
}

func Decode(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxMessageSize {
		return errors.New("invalid control message size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing data after control message")
	}
	return nil
}

func (h Hello) Validate() error {
	if h.Node == "" || len(h.Node) > 63 {
		return errors.New("node name must contain 1..63 characters")
	}
	for _, r := range h.Node {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return errors.New("node name contains an invalid character")
		}
	}
	if h.Role != "client" && h.Role != "gateway" {
		return errors.New("role must be client or gateway")
	}
	if h.Lane < 0 || h.Lane > 15 {
		return errors.New("lane must be 0..15")
	}
	if h.Lane > 0 && strings.TrimSpace(h.SessionID) == "" {
		return errors.New("additional lanes require a session ID")
	}
	if h.RequestedAddress != "" && h.RequestedAddress != "auto" {
		address, err := netip.ParsePrefix(h.RequestedAddress)
		if err != nil || !address.Addr().Is4() {
			return errors.New("requested address must be an IPv4 prefix or auto")
		}
	}
	for _, route := range h.AdvertiseRoutes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("invalid advertised route %q", route)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("advertised route %q is not IPv4", route)
		}
	}
	return nil
}
