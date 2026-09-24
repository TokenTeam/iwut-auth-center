package main

import (
	"fmt"
	"log"
	"os"

	"iwut-auth-center/internal/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("auth-center: %v", err)
	}
}

func run() error {
	if len(os.Args) > 1 {
		if os.Args[1] == "bootstrap-platform-admin" {
			return bootstrapPlatformAdmin(os.Args[2:], os.Stdout)
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
