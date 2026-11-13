package mobilecore

import (
	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/enroll"
)

// ClientConfig converts a password-free join code plus local credentials into
// a complete Android client TOML configuration.
func ClientConfig(joinCode, node, password string) (string, error) {
	code, err := enroll.Decode(joinCode)
	if err != nil {
		return "", err
	}
	cfg, err := enroll.Build("client", node, password, "", code)
	if err != nil {
		return "", err
	}
	encoded, err := config.Encode(cfg)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
