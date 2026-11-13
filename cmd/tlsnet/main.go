package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ykkaabb/tlsnet/internal/app"
	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/enroll"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tlsnet:", err)
		os.Exit(1)
	}
}

func execute(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: tlsnet <run|check|configure|version>")
	}
	if arguments[0] == "version" {
		fmt.Println("tlsnet", version)
		return nil
	}
	if arguments[0] == "configure" {
		return configure(arguments[1:])
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	path := flags.String("c", "config.toml", "configuration file")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if arguments[0] == "check" {
		fmt.Printf("configuration OK: role=%s node=%s transport=%s\n", cfg.Node.Role, cfg.Node.Name, cfg.Transport.Mode)
		return nil
	}
	if arguments[0] != "run" {
		return fmt.Errorf("unknown command %q", arguments[0])
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Logging.Level)); err != nil {
		return fmt.Errorf("logging level: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cfg, logger)
}

func configure(arguments []string) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	path := flags.String("o", "config.toml", "output configuration file")
	force := flags.Bool("force", false, "replace an existing configuration")
	role := flags.String("role", "", "preselect relay, gateway, or client")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	passwordReader := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(value), err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		passwordReader = nil
	}
	result, err := enroll.RunWizard(enroll.WizardOptions{
		Input: os.Stdin, Output: os.Stderr, ReadPassword: passwordReader, Hostname: enroll.SystemHostname(), Role: *role,
	})
	if err != nil {
		return err
	}
	encoded, err := config.Encode(result.Config)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	if !*force {
		if _, err := os.Stat(absolute); err == nil {
			return fmt.Errorf("configuration already exists: %s (use -force to replace it)", absolute)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	directory := filepath.Dir(absolute)
	temporary, err := os.CreateTemp(directory, ".tlsnet-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if *force {
		_ = os.Remove(absolute)
	}
	if err := os.Rename(temporaryPath, absolute); err != nil {
		return err
	}
	fmt.Printf("configuration written: %s\n", absolute)
	if result.Config.Node.Role == "relay" {
		fmt.Println("join code (does not contain the password):")
		fmt.Println(result.JoinCode)
		fmt.Println("Paste this code on the home gateway and every access client, then enter the same password.")
	}
	return nil
}
