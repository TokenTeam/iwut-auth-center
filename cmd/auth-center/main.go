package main

import (
	"fmt"
	"log/slog"
	"os"

	"iwut-auth-center/internal/config"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service.name", serviceName))
	if err := run(); err != nil {
		slog.Error("auth-center failed", "error.type", "startup")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		if os.Args[1] == "bootstrap-platform-admin" {
			return bootstrapPlatformAdmin(os.Args[2:], os.Stdout)
		}
		if os.Args[1] == "reconcile-account-closures" {
			return reconcileAccountClosures(os.Args[2:], os.Stdout)
		}
		return fmt.Errorf("unknown command")
	}
	configuration, err := config.LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	app, cleanup, err := wireApp(configuration)
	if err != nil {
		return fmt.Errorf("build composition: %w", err)
	}
	defer cleanup()
	if err := app.Run(); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
