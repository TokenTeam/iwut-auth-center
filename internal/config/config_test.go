package config

import (
	"errors"
	"testing"
)

func TestLoadUsesDefaultGRPCAddress(t *testing.T) {
	configuration, err := Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.GRPCAddr != DefaultGRPCAddr {
		t.Fatalf("GRPCAddr = %q, want %q", configuration.GRPCAddr, DefaultGRPCAddr)
	}
}

func TestLoadAcceptsExplicitGRPCAddress(t *testing.T) {
	configuration, err := Load(func(key string) (string, bool) {
		if key == GRPCAddrEnv {
			return " 127.0.0.1:19000 ", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.GRPCAddr != "127.0.0.1:19000" {
		t.Fatalf("GRPCAddr = %q", configuration.GRPCAddr)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		lookup LookupEnv
	}{
		{name: "nil lookup", lookup: nil},
		{name: "empty explicit address", lookup: func(string) (string, bool) { return " ", true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(test.lookup)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Load() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}
