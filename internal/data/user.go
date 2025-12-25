package data

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type userRepo struct {
	data           *Data
	log            *log.Helper
	userCollection *mongo.Collection
	sha256Util     *util.Sha256Util
}

func NewUserRepo(data *Data, c *conf.Data, logger log.Logger, sha256Util *util.Sha256Util) biz.UserRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	return &userRepo{
		data:           data,
		log:            log.NewHelper(logger),
		userCollection: usersCollection,
		sha256Util:     sha256Util,
	}
}

func (r *userRepo) UpdateUserPassword(ctx context.Context, userId string, oldPassword string, newPassword string) error {
	oldPassword = r.sha256Util.HashPassword(oldPassword)
	newPassword = r.sha256Util.HashPassword(newPassword)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := util.RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, UpdateUserPassword called with userId: %s", reqId, userId)

	collection := r.userCollection
	filter := bson.M{"_id": userId, "password": oldPassword}

	var result struct {
		version   int        `bson:"version"`
		deletedAt *time.Time `bson:"deleted_at"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return biz.UserNotFoundError
		}
		r.log.Errorf("failed to find user: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to find user: %w, traceId: %s", err, reqId)
	} else if result.deletedAt != nil {
		return biz.UserHasBeenDeletedError
	}
	update := bson.M{
		"$set": bson.M{
			"password":   newPassword,
			"updated_at": time.Now(),
			"version":    (result.version + 1) % (1e9 + 7),
		},
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.log.Errorf("failed to update user password: %v, traceId: %s", err, reqId)
		return fmt.Errorf("failed to update user password: %w, traceId: %s", err, reqId)
	}
	return nil
}
