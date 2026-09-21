package main

import (
	"fmt"
	"log"

	"iwut-auth-center/internal/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("auth-center: %v", err)
	}
}

func run() error {
	configuration, err := config.LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	app, err := wireApp(configuration)
	if err != nil {
		return fmt.Errorf("build composition: %w", err)
	}
	if err := app.Run(); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
