package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ykkaabb/tlsnet/internal/app"
	"github.com/ykkaabb/tlsnet/internal/config"
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
		return errors.New("usage: tlsnet <run|check|version> [-c config.toml]")
	}
	if arguments[0] == "version" {
		fmt.Println("tlsnet", version)
		return nil
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
