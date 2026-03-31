package data

import (
	"context"
	"encoding/json"
	"fmt"
	v1 "iwut-auth-center/api/gen/go/auth_center/v1/error_reason"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type oauth2Repo struct {
	data                   *Data
	log                    *log.Helper
	userCollection         *mongo.Collection
	userConsentsCollection *mongo.Collection
	refreshTokenLifeSpan   time.Duration
}

func NewOauth2Repo(data *Data, c *conf.Data, jwtConf *conf.Jwt, logger log.Logger) biz.Oauth2Repo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")

	return &oauth2Repo{
		data:                   data,
		log:                    log.NewHelper(logger),
		userCollection:         usersCollection,
		userConsentsCollection: userConsentsCollection,
		refreshTokenLifeSpan:   time.Duration(jwtConf.GetRefreshTokenLifeSpan()) * time.Second,
	}
}

// ---- Code Info (Redis cache) ----

const codeInfoTTL = 5 * time.Minute

func (r *oauth2Repo) SetCodeInfo(ctx context.Context, code string, codeInfo *biz.CodeInfo) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetCodeInfo code: %s, codeInfo: %+v", code, codeInfo)

	key := GetRedisKey("oauth2_code", code)
	b, err := json.Marshal(codeInfo)
	if err != nil {
		return err
	}
	return r.data.redis.Set(ctx, key, b, codeInfoTTL).Err()
}

func (r *oauth2Repo) GetCodeInfo(ctx context.Context, code string) (*biz.CodeInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetCodeInfo code: %s", code)

	key := GetRedisKey("oauth2_code", code)
	val, err := r.data.redis.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	var codeInfo biz.CodeInfo
	if err := json.Unmarshal([]byte(val), &codeInfo); err != nil {
		return nil, err
	}
	return &codeInfo, nil
}

func (r *oauth2Repo) EraseCodeInfo(ctx context.Context, code string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("EraseCodeInfo code: %s", code)
	return r.data.redis.Del(ctx, GetRedisKey("oauth2_code", code)).Err()
}

// ---- User Consent Records ----

func (r *oauth2Repo) LoadUserConsentRecords(ctx context.Context, uid string, clientId string) ([]biz.UserConsentRecord, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	filter := bson.M{
		"user_id":   uid,
		"client_id": clientId,
	}
	cursor, err := r.userConsentsCollection.Find(ctx, filter)
	if err != nil {
		l.Errorf("LoadUserConsentRecords Find error: %v", err)
		return nil, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	consents := make([]biz.UserConsentRecord, 0, 2)
	for cursor.Next(ctx) {
		var doc struct {
			AgreedVersion int32    `bson:"agreed_version"`
			OptionalScope []string `bson:"optional_scope"`
			Type          string   `bson:"type"`
		}
		if err := cursor.Decode(&doc); err != nil {
			l.Errorf("LoadUserConsentRecords Decode error: %v", err)
			return nil, err
		}
		consents = append(consents, biz.UserConsentRecord{
			AgreedVersion: doc.AgreedVersion,
			OptionalScope: doc.OptionalScope,
			Type:          doc.Type,
		})
	}
	if err := cursor.Err(); err != nil {
		l.Errorf("LoadUserConsentRecords cursor error: %v", err)
		return nil, err
	}
	return consents, nil
}

func (r *oauth2Repo) GetUserConsentJTIs(ctx context.Context, uid string, clientId string, status string) ([]string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	filter := bson.M{
		"user_id":   uid,
		"client_id": clientId,
		"type":      status,
	}
	var doc struct {
		TokenID []string `bson:"token_id"`
	}
	err := r.userConsentsCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.NotFound(v1.ErrorReason_USER_CONSENT_NOT_FOUND.String(), "user consent not found")
		}
		l.Errorf("GetUserConsentJTIs FindOne error: %v", err)
		return nil, err
	}
	return doc.TokenID, nil
}

func (r *oauth2Repo) UpdateUserConsentJTIs(ctx context.Context, uid string, clientId string, status string, tokenIDs []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	filter := bson.M{
		"user_id":   uid,
		"client_id": clientId,
		"type":      status,
	}
	update := bson.M{
		"$set": bson.M{
			"token_id": tokenIDs,
		},
	}
	_, err := r.userConsentsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("UpdateUserConsentJTIs UpdateOne error: %v", err)
		return err
	}
	return nil
}

func (r *oauth2Repo) CheckUserConsentExists(ctx context.Context, uid string, clientId string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	filter := bson.M{
		"user_id":   uid,
		"client_id": clientId,
	}
	err := r.userConsentsCollection.FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		l.Errorf("CheckUserConsentExists user consent not found for userId: %s, clientId: %s", uid, clientId)
		return errors.NotFound(v1.ErrorReason_USER_CONSENT_NOT_FOUND.String(), "user consent not found")
	} else if err != nil {
		l.Errorf("CheckUserConsentExists FindOne error: %v", err)
		return err
	}
	return nil
}

// ---- JTI Allow/Remove (Redis) ----

func (r *oauth2Repo) AllowJTIs(ctx context.Context, jtis []string) error {
	if len(jtis) == 0 {
		return nil
	}

	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))
	l.Debugf("AllowJTIs jtis: %+v", jtis)

	pipe := r.data.redis.Pipeline()
	for _, id := range jtis {
		if id == "" {
			continue
		}
		key := GetRedisKey("allowed_tokens", id)
		pipe.Set(ctx, key, "1", r.refreshTokenLifeSpan)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		l.Errorf("AllowJTIs pipeline exec error err=%v", err)
		return err
	}
	return nil
}

// ---- Per-Client Storage ----

func (r *oauth2Repo) GetUserStorageData(ctx context.Context, uid string, applicationId string, storageKeys []string) (map[string]*string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	if err := validateApplicationId(applicationId); err != nil {
		l.Errorf("GetUserStorageData invalid application id: %s", applicationId)
		return nil, errors.InternalServer(v1.ErrorReason_INVALID_APP_ID.String(), "invalid application id")
	}

	proj := bson.D{}
	for _, s := range storageKeys {
		proj = append(proj, bson.E{Key: applicationId + "." + s, Value: 1})
	}

	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"uid", uid}}}},
		{{"$project", proj}},
	}

	cur, err := r.userCollection.Aggregate(ctx, pipeline)
	if err != nil {
		l.Errorf("GetUserStorageData aggregate error: %v", err)
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			l.Errorf("GetUserStorageData cursor error: %v", err)
			return nil, err
		}
		return nil, errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
	}

	var doc bson.M
	if err := cur.Decode(&doc); err != nil {
		l.Errorf("GetUserStorageData decode error: %v", err)
		return nil, err
	}

	conv, err := util.ConvertBSONValueToGOType(doc)
	if err != nil {
		l.Errorf("GetUserStorageData ConvertBSONValueToGOType error: %v", err)
		return nil, err
	}
	convMap, ok := conv.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("GetUserStorageData ConvertBSONValueToGOType unexpected type: %T", conv)
	}

	storageKeyValue := map[string]*string{}
	for _, k := range storageKeys {
		fullKey := applicationId + "." + k
		val, err := getNestedStringValue(fullKey, convMap)
		if err != nil {
			return nil, err
		}
		storageKeyValue[k] = val
	}
	return storageKeyValue, nil
}

func (r *oauth2Repo) SetUserStorageData(ctx context.Context, uid string, applicationId string, storageKeyValues map[string]string, memLimit int64) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	if err := validateApplicationId(applicationId); err != nil {
		l.Errorf("SetUserStorageData invalid application id: %s", applicationId)
		return errors.InternalServer(v1.ErrorReason_INVALID_APP_ID.String(), "invalid application id")
	}

	filter := bson.M{"uid": uid}

	var doc bson.M
	err := r.userCollection.FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{applicationId: 1})).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.NotFound(v1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
		}
		l.Errorf("SetUserStorageData FindOne error: %v", err)
		return err
	}

	existedKeyValue, illegalKeys, _ := util.BsonMToStringMap(doc)
	if illegalKeys != nil {
		l.Warnf("SetUserStorageData illegalKeys: %v", illegalKeys)
		delKeys := make(map[string]string)
		for k := range illegalKeys {
			delKeys[applicationId+"."+k] = ""
		}
		_, cleanupErr := r.userCollection.UpdateOne(ctx, filter, bson.M{"$unset": delKeys})
		if cleanupErr != nil {
			l.Errorf("SetUserStorageData cleanup illegal keys error: %v", cleanupErr)
		}
	}

	for k, v := range storageKeyValues {
		existedKeyValue[k] = v
	}

	if len(existedKeyValue) > 1000 {
		return errors.BadRequest(v1.ErrorReason_TOO_MANY_KEYS.String(), "too many storage keys to set")
	}

	var totalLength int64
	for k, v := range existedKeyValue {
		totalLength += int64(len(k) + len(v))
	}
	if totalLength > memLimit {
		return errors.New(413, v1.ErrorReason_OAUTH2_INFO_MEMORY_LIMITATION_EXCEEDED.String(), "oauth2 info memory limitation exceeded")
	}

	update := bson.M{}
	for k, v := range existedKeyValue {
		update[applicationId+"."+k] = v
	}

	_, err = r.userCollection.UpdateOne(ctx, bson.M{"uid": uid}, bson.M{"$set": update})
	if err != nil {
		l.Errorf("SetUserStorageData update error: %v", err)
		return err
	}
	return nil
}

// ---- Helpers ----

func validateApplicationId(applicationId string) error {
	splits := strings.Split(applicationId, ".")
	if len(splits) != 2 || splits[0] == "" || splits[1] == "" {
		return fmt.Errorf("invalid application id format")
	}
	if strings.HasPrefix(splits[0], ".") || strings.HasPrefix(splits[0], "$") {
		return fmt.Errorf("invalid application id prefix")
	}
	return nil
}

func getNestedStringValue(key string, doc map[string]any) (*string, error) {
	keys := strings.Split(key, ".")
	var errorKey string
	if len(keys) > 0 {
		errorKey = keys[len(keys)-1]
	} else {
		errorKey = key
	}
	cur := doc
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			return nil, nil
		}
		if i == len(keys)-1 {
			if s, ok := v.(string); ok {
				return &s, nil
			}
			return nil, fmt.Errorf("key %s is not a string", errorKey)
		}
		if mp, ok := v.(map[string]any); ok {
			cur = mp
		} else {
			return nil, fmt.Errorf("key %s is not a map", errorKey)
		}
	}
	return nil, nil
}
