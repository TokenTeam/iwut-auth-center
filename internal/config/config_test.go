package config

import (
	"errors"
	"testing"
)

func TestLoadUsesDefaults(t *testing.T) {
	configuration, err := Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.GRPCAddr != DefaultGRPCAddr {
		t.Fatalf("GRPCAddr = %q, want %q", configuration.GRPCAddr, DefaultGRPCAddr)
	}
	if configuration.MongoURI != DefaultMongoURI {
		t.Fatalf("MongoURI = %q, want %q", configuration.MongoURI, DefaultMongoURI)
	}
	if configuration.MongoDatabase != DefaultMongoDatabase {
		t.Fatalf("MongoDatabase = %q, want %q", configuration.MongoDatabase, DefaultMongoDatabase)
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

func TestLoadAcceptsExplicitMongoConfiguration(t *testing.T) {
	configuration, err := Load(func(key string) (string, bool) {
		switch key {
		case MongoURIEnv:
			return " mongodb://mongo:27017 ", true
		case MongoDatabaseEnv:
			return " auth_test ", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.MongoURI != "mongodb://mongo:27017" || configuration.MongoDatabase != "auth_test" {
		t.Fatalf("mongo configuration = (%q, %q)", configuration.MongoURI, configuration.MongoDatabase)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		lookup LookupEnv
	}{
		{name: "nil lookup", lookup: nil},
		{name: "empty explicit address", lookup: func(key string) (string, bool) {
			if key == GRPCAddrEnv {
				return " ", true
			}
			return "", false
		}},
		{name: "empty explicit mongo URI", lookup: func(key string) (string, bool) {
			if key == MongoURIEnv {
				return " ", true
			}
			return "", false
		}},
		{name: "empty explicit mongo database", lookup: func(key string) (string, bool) {
			if key == MongoDatabaseEnv {
				return " ", true
			}
			return "", false
		}},
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
