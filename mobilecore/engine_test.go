package mobilecore

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/ykkaabb/tlsnet/internal/control"
)

func androidConfig(routes string) string {
	return "config_version = 1\n" +
		"[node]\nrole = \"client\"\nname = \"android\"\n" +
		"[auth]\nnetwork_name = \"testnet\"\npassword = \"password\"\n" +
		"kdf_memory_mib = 1\nkdf_iterations = 1\nkdf_parallelism = 1\n" +
		"[server]\naddress = \"203.0.113.1:443\"\n" +
		"[reality]\nserver_name = \"www.speedtest.cn\"\ntcp_target = \"www.speedtest.cn:443\"\n" +
		"[transport]\nmode = \"quic\"\n" +
		"[transport.quic]\nenabled = true\n" +
		"[transport.tls]\nlanes = 2\n" +
		"[overlay]\naddress = \"auto\"\naccept_routes = [" + routes + "]\n"
}

func TestNewEngineValidatesSplitRoutes(t *testing.T) {
	engine, err := NewEngine(androidConfig("\"192.168.3.0/24\""))
	if err != nil {
		t.Fatal(err)
	}
	if engine.Status() != "idle" {
		t.Fatalf("status=%s", engine.Status())
	}
	if _, err := NewEngine(androidConfig("\"0.0.0.0/0\"")); err == nil {
		t.Fatal("accepted Android default route")
	}
}

func TestClientConfigFromJoinCode(t *testing.T) {
	code := "TLSNET1:eyJzZXJ2ZXIiOiIxMjQuMjIzLjIxOS42MTo0NDMiLCJuZXR3b3JrIjoidGxzbmV0Iiwic25pIjoid3d3LnNwZWVkdGVzdC5jbiIsInBvb2wiOiIxMC45MS4wLjAvMjQiLCJob21lX25vZGUiOiJob21lIiwiaG9tZV9zdWJuZXQiOiIxOTIuMTY4LjMuMC8yNCJ9"
	generated, err := ClientConfig(code, "phone", "password with spaces")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(generated)
	if err != nil {
		t.Fatal(err)
	}
	if engine.config.Node.Name != "phone" || engine.config.Auth.Password != "password with spaces" {
		t.Fatalf("unexpected generated config: %+v", engine.config)
	}
}

func TestPacketPumps(t *testing.T) {
	session := &fakePacketSession{receive: [][]byte{[]byte("from-overlay")}}
	sendResult := make(chan error, 1)
	go pumpTunToSession(bytes.NewReader([]byte("from-tun")), session, sendResult)
	if err := <-sendResult; !errors.Is(err, io.EOF) {
		t.Fatalf("send pump error=%v", err)
	}
	if string(session.sent) != "from-tun" {
		t.Fatalf("sent=%q", session.sent)
	}

	var output bytes.Buffer
	receiveResult := make(chan error, 1)
	go pumpSessionToTun(&output, session, receiveResult)
	if err := <-receiveResult; !errors.Is(err, io.EOF) {
		t.Fatalf("receive pump error=%v", err)
	}
	if output.String() != "from-overlay" {
		t.Fatalf("output=%q", output.String())
	}
}

type fakePacketSession struct {
	sent    []byte
	receive [][]byte
}

func (s *fakePacketSession) Welcome() control.Welcome { return control.Welcome{} }
func (s *fakePacketSession) Transport() string        { return "fake" }
func (s *fakePacketSession) Send(packet []byte) error {
	s.sent = append([]byte(nil), packet...)
	return nil
}
func (s *fakePacketSession) Receive() ([]byte, error) {
	if len(s.receive) == 0 {
		return nil, io.EOF
	}
	packet := s.receive[0]
	s.receive = s.receive[1:]
	return packet, nil
}
func (s *fakePacketSession) Close() error { return nil }
