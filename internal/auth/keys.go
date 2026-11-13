package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const keySize = 32

type KDFParams struct {
	MemoryMiB   uint32
	Iterations  uint32
	Parallelism uint8
}

type Keys struct {
	TCPRoute    [keySize]byte
	QUICRoute   [keySize]byte
	Certificate [keySize]byte
	Session     [keySize]byte
	Path        [keySize]byte
}

func Derive(password, networkName, serverName string, params KDFParams) (*Keys, error) {
	if password == "" || networkName == "" || serverName == "" {
		return nil, errors.New("password, network name, and server name are required")
	}
	if params.MemoryMiB == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return nil, errors.New("invalid Argon2id parameters")
	}
	if params.MemoryMiB > ^uint32(0)/1024 {
		return nil, errors.New("Argon2id memory size overflows KiB value")
	}

	saltInput := "tlsnet/v1/kdf\x00" + networkName + "\x00" + strings.ToLower(strings.TrimSuffix(serverName, "."))
	salt := sha256.Sum256([]byte(saltInput))
	master := argon2.IDKey([]byte(password), salt[:], params.Iterations, params.MemoryMiB*1024, params.Parallelism, keySize)
	defer clear(master)

	keys := &Keys{}
	for label, dst := range map[string][]byte{
		"tcp-route":   keys.TCPRoute[:],
		"quic-route":  keys.QUICRoute[:],
		"certificate": keys.Certificate[:],
		"session":     keys.Session[:],
		"path":        keys.Path[:],
	} {
		reader := hkdf.New(sha256.New, master, nil, []byte("tlsnet/v1/"+label))
		if _, err := io.ReadFull(reader, dst); err != nil {
			return nil, fmt.Errorf("derive %s key: %w", label, err)
		}
	}
	return keys, nil
}
