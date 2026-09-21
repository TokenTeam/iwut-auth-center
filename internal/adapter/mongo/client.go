package mongo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const connectTimeout = 10 * time.Second

func NewClient(uri string) (*drivermongo.Client, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, errors.New("mongodb uri is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	client, err := drivermongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect mongodb: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("ping mongodb: %w", err)
	}
	return client, nil
}

func NewDatabase(client *drivermongo.Client, name string) (*drivermongo.Database, error) {
	if client == nil {
		return nil, errors.New("mongodb client is required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("mongodb database name is required")
	}
	return client.Database(name), nil
}
