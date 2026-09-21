package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	GRPCAddrEnv          = "AUTH_CENTER_GRPC_ADDR"
	MongoURIEnv          = "AUTH_CENTER_MONGO_URI"
	MongoDatabaseEnv     = "AUTH_CENTER_MONGO_DATABASE"
	DefaultGRPCAddr      = ":9000"
	DefaultMongoURI      = "mongodb://127.0.0.1:27017"
	DefaultMongoDatabase = "iwut_auth_center"
)

var ErrInvalidConfiguration = errors.New("invalid auth center configuration")

type LookupEnv func(key string) (value string, found bool)

type Config struct {
	GRPCAddr      string
	MongoURI      string
	MongoDatabase string
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
	mongoURI := DefaultMongoURI
	if raw, found := lookup(MongoURIEnv); found {
		mongoURI = strings.TrimSpace(raw)
		if mongoURI == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, MongoURIEnv)
		}
	}
	database := DefaultMongoDatabase
	if raw, found := lookup(MongoDatabaseEnv); found {
		database = strings.TrimSpace(raw)
		if database == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, MongoDatabaseEnv)
		}
	}
	return Config{GRPCAddr: address, MongoURI: mongoURI, MongoDatabase: database}, nil
}
