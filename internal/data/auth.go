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

type authRepo struct {
	data           *Data
	log            *log.Helper
	userCollection *mongo.Collection
	sha256Util     *util.Sha256Util
}

func NewAuthRepo(data *Data, c *conf.Data, logger log.Logger, sha256Util *util.Sha256Util) biz.AuthRepo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	return &authRepo{
		data:           data,
		log:            log.NewHelper(logger),
		userCollection: usersCollection,
		sha256Util:     sha256Util,
	}
}

type reqIDKey struct{}

// 获取ctx中的 reqIDKey 作为 追踪ID 但是计划只在dev环境使用
// 但是这Go的条件编译是基于文件的。。。
// 如果使用环境变量控制 运行时判断 感觉有点可惜。。

func RequestIDFrom(ctx context.Context) string {
	if v := ctx.Value(reqIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (r *authRepo) CheckPasswordAndGetUserBaseInfo(ctx context.Context, email string, password string) (string, error) {
	password = r.sha256Util.HashPassword(password)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqId := RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, CheckPasswordAndGetUserBaseInfo called with email: %s", reqId, email)

	collection := r.userCollection
	filter := bson.M{"email": email, "password": password}

	var result struct {
		UserID string `bson:"_id"`
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", biz.ErrUserNotFound
		}
		return "", fmt.Errorf("failed to find user: %w", err)
	}
	return result.UserID, nil
}

func (r *authRepo) GetPasswordByEmail(ctx context.Context, email string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqID := RequestIDFrom(ctx)
	r.log.Debugf("RequestID: %s, GetPasswordByEmail called with email: %s", reqID, email)

	collection := r.userCollection
	filter := bson.M{"email": email}

	var result struct {
		Password string `bson:"password"`
	}

	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", biz.ErrUserNotFound
		}
		r.log.Errorf("FindOne error req=%s err=%v", reqID, err)
		return "", fmt.Errorf("failed to find user: %w", err)
	}
	return result.Password, nil
}
