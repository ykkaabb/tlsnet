package enroll

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ykkaabb/tlsnet/internal/config"
)

func passwordSequence(values ...string) func(string) (string, error) {
	index := 0
	return func(string) (string, error) {
		value := values[index]
		index++
		return value, nil
	}
}

func TestRelayWizardProducesReusableJoinCode(t *testing.T) {
	input := strings.NewReader("relay\n124.223.219.61\n\n\n\n\n\n\n\n")
	var output bytes.Buffer
	result, err := RunWizard(WizardOptions{
		Input: input, Output: &output, Hostname: "relay-host",
		ReadPassword: passwordSequence("any length ! 密码", "any length ! 密码"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Node.Role != "relay" || result.Config.Overlay.Address != "10.91.0.1/24" {
		t.Fatalf("unexpected relay config: %+v", result.Config)
	}
	code, err := Decode(result.JoinCode)
	if err != nil {
		t.Fatal(err)
	}
	if code.ServerAddress != "124.223.219.61:443" || code.HomeSubnet != "192.168.3.0/24" {
		t.Fatalf("unexpected join code: %+v", code)
	}
	encoded, err := config.Encode(result.Config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Auth.Password != "any length ! 密码" {
		t.Fatal("password did not survive TOML round trip")
	}
}

func TestGatewayWizardNeedsOnlyJoinCodeAndLocalInterface(t *testing.T) {
	code, err := (JoinCode{
		ServerAddress: "124.223.219.61:443", NetworkName: "home", ServerName: "www.speedtest.cn",
		OverlayPool: "10.91.0.0/24", HomeNode: "fnos", HomeSubnet: "192.168.3.0/24",
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader("gateway\n" + code + "\n\neth0\n")
	result, err := RunWizard(WizardOptions{
		Input: input, Output: &bytes.Buffer{}, Hostname: "ignored",
		ReadPassword: passwordSequence("secret", "secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Node.Name != "fnos" || result.Config.Gateway.LANInterface != "eth0" ||
		result.Config.Overlay.Address != "10.91.0.2/24" {
		t.Fatalf("unexpected gateway config: %+v", result.Config)
	}
}
