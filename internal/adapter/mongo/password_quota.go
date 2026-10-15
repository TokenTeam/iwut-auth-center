package mongo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/password/domain"
	"iwut-auth-center/internal/password/port"
)

const PasswordQuotaCollection = "auth_password_quotas"

type PasswordQuota struct{ auth *AuthenticationRepository }

func NewPasswordQuota(auth *AuthenticationRepository) (*PasswordQuota, error) {
	if auth == nil {
		return nil, domain.ErrUnavailable
	}
	return &PasswordQuota{auth}, nil
}
func EnsurePasswordQuotaSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return domain.ErrUnavailable
	}
	_, err := db.Collection(PasswordQuotaCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "key", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_quota_key_unique")},
		{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("password_quota_expiry")},
	})
	return err
}

func (q *PasswordQuota) General(ctx context.Context, source, owner string, now time.Time) error {
	return q.consume(ctx, "general", source, owner, 1, 600, 120, 30, now)
}
func (q *PasswordQuota) Work(ctx context.Context, source, owner string, units int, now time.Time) error {
	return q.consume(ctx, "work", source, owner, units, 120, 20, 10, now)
}

func (q *PasswordQuota) OwnerRequest(ctx context.Context, owner string, now time.Time) error {
	if owner == "" || now.IsZero() {
		return domain.ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(owner))
	return q.consumeTargets(ctx, "general", []quotaTarget{{"general:owner:" + hex.EncodeToString(digest[:]), 30}}, 1, now)
}

type quotaTarget struct {
	key   string
	limit int
}
type passwordQuotaDocument struct {
	Key       string      `bson:"key"`
	Units     []time.Time `bson:"units"`
	ExpiresAt time.Time   `bson:"expiresAt"`
}

func (q *PasswordQuota) consume(ctx context.Context, kind, source, owner string, units, globalLimit, sourceLimit, ownerLimit int, now time.Time) error {
	address, err := netip.ParseAddr(source)
	if err != nil || address.Zone() != "" || units < 1 || units > 2 || now.IsZero() {
		return domain.ErrInvalidInput
	}
	// owner is authoritative authId, or a stable protected address key provided
	// by the email adapter for anonymous operations, never plaintext email.
	if kind == "work" && owner == "" {
		return domain.ErrInvalidInput
	}
	sourceDigest := sha256.Sum256([]byte(address.Unmap().String()))
	targets := []quotaTarget{{kind + ":global", globalLimit}, {kind + ":source:" + hex.EncodeToString(sourceDigest[:]), sourceLimit}}
	if owner != "" {
		ownerDigest := sha256.Sum256([]byte(owner))
		targets = append(targets, quotaTarget{kind + ":owner:" + hex.EncodeToString(ownerDigest[:]), ownerLimit})
	}
	return q.consumeTargets(ctx, kind, targets, units, now)
}

func (q *PasswordQuota) consumeTargets(ctx context.Context, kind string, targets []quotaTarget, units int, now time.Time) error {
	return q.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := q.auth.currentTime(now)
		// TTL can be delayed or disabled. Drain only expired rows in a bounded
		// batch, then enforce a physical cap too; never evict a live budget.
		cursor, err := q.auth.database.Collection(PasswordQuotaCollection).Find(tx, bson.M{"expiresAt": bson.M{"$lte": observed}}, options.Find().SetProjection(bson.M{"_id": 1}).SetSort(bson.D{{Key: "expiresAt", Value: 1}}).SetLimit(64))
		if err != nil {
			return err
		}
		var expired []bson.M
		if err = cursor.All(tx, &expired); err != nil {
			cursor.Close(tx)
			return err
		}
		cursor.Close(tx)
		if len(expired) > 0 {
			ids := make(bson.A, 0, len(expired))
			for _, row := range expired {
				ids = append(ids, row["_id"])
			}
			if _, err = q.auth.database.Collection(PasswordQuotaCollection).DeleteMany(tx, bson.M{"_id": bson.M{"$in": ids}, "expiresAt": bson.M{"$lte": observed}}); err != nil {
				return err
			}
		}
		for _, target := range targets {
			var raw bson.Raw
			err := q.auth.database.Collection(PasswordQuotaCollection).FindOne(tx, bson.M{"key": target.key}).Decode(&raw)
			fresh := errors.Is(err, m.ErrNoDocuments)
			if err != nil && !fresh {
				return err
			}
			doc := passwordQuotaDocument{Key: target.key}
			if !fresh {
				if !identityFields(raw, map[string]bson.Type{"key": bson.TypeString, "units": bson.TypeArray, "expiresAt": bson.TypeDateTime}) || bson.Unmarshal(raw, &doc) != nil || doc.Key != target.key || len(doc.Units) > target.limit {
					return domain.ErrUnavailable
				}
			}
			live := make([]time.Time, 0, target.limit)
			for _, at := range doc.Units {
				if at.After(observed) {
					return domain.ErrUnavailable
				}
				if at.After(observed.Add(-time.Minute)) {
					live = append(live, at)
				}
			}
			if len(live)+units > target.limit {
				return domain.ErrLimited
			}
			if (fresh || !doc.ExpiresAt.After(observed)) && target.key != kind+":global" {
				count, err := q.auth.database.Collection(PasswordQuotaCollection).CountDocuments(tx, bson.M{"key": bson.M{"$regex": "^" + kind + ":"}}, options.Count().SetLimit(4097))
				if err != nil {
					return err
				}
				if count >= 4097 {
					return domain.ErrLimited
				}
			}
			for i := 0; i < units; i++ {
				live = append(live, observed)
			}
			doc.Units = live
			doc.ExpiresAt = observed.Add(time.Minute)
			if _, err = q.auth.database.Collection(PasswordQuotaCollection).ReplaceOne(tx, bson.M{"key": target.key}, doc, options.Replace().SetUpsert(true)); err != nil {
				return err
			}
		}
		return nil
	})
}

var _ port.Quota = (*PasswordQuota)(nil)
