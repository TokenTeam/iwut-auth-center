package data

import (
	"context"
	"fmt"
	"iwut-auth-center/internal/conf"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewAuthRepo)

// Data .
type Data struct {
	mongo *mongo.Client
}

// NewData .
func NewData(c *conf.Data) (*Data, func(), error) {
	mongoClient, err := initMongo(c)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := mongoClient.Disconnect(ctx); err != nil {
			log.Error("failed to disconnect mongodb:", err)
		}
		log.Info("closing the data resources")
	}
	return &Data{mongo: mongoClient}, cleanup, nil
}

func initMongo(c *conf.Data) (*mongo.Client, error) {
	uri := c.GetMongodb().GetUri()
	if uri == "" {
		return nil, fmt.Errorf("mongodb uri is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	clientOpts := options.Client().ApplyURI(uri)

	if c.Mongodb.GetUsername() != "" && c.Mongodb.GetPassword() != "" {
		cred := options.Credential{
			Username:   c.Mongodb.GetUsername(),
			Password:   c.Mongodb.GetPassword(),
			AuthSource: c.Mongodb.GetAuthSource(),
		}
		clientOpts.SetAuth(cred)
	}

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return client, nil
}
