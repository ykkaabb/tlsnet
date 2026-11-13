//go:build windows

package main

import (
	"os"

	"github.com/ykkaabb/tlsnet/internal/windowsapp"
)

var version = "dev"

func main() {
	windowsapp.Main(os.Args, version)
}
