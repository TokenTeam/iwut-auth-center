package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	GRPCAddrEnv     = "AUTH_CENTER_GRPC_ADDR"
	DefaultGRPCAddr = ":9000"
)

var ErrInvalidConfiguration = errors.New("invalid auth center configuration")

type LookupEnv func(key string) (value string, found bool)

type Config struct {
	GRPCAddr string
}

func LoadFromEnvironment() (Config, error) {
	return Load(os.LookupEnv)
}

func Load(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("%w: environment lookup is nil", ErrInvalidConfiguration)
	}
	address := DefaultGRPCAddr
	if raw, found := lookup(GRPCAddrEnv); found {
		address = strings.TrimSpace(raw)
		if address == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, GRPCAddrEnv)
		}
	}
	return Config{GRPCAddr: address}, nil
}
