package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
)

func prunePasswordRowsTx(ctx context.Context, db *m.Database, col string, now time.Time) error {
	cur, err := db.Collection(col).Find(ctx, bson.M{"retainUntil": bson.M{"$lte": now}}, options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(64))
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	var rows []bson.M
	if err = cur.All(ctx, &rows); err != nil {
		return err
	}
	ids := bson.A{}
	for _, row := range rows {
		ids = append(ids, row["_id"])
	}
	if len(ids) > 0 {
		_, err = db.Collection(col).DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}, "retainUntil": bson.M{"$lte": now}})
	}
	return err
}
func ensurePasswordOutboxCapacityTx(ctx context.Context, db *m.Database, now time.Time) error {
	if err := prunePasswordRowsTx(ctx, db, PasswordNotificationCollection, now); err != nil {
		return err
	}
	count, err := db.Collection(PasswordNotificationCollection).CountDocuments(ctx, bson.M{}, options.Count().SetLimit(1000000))
	if err != nil {
		return err
	}
	if count >= 1000000 {
		return d.ErrLimited
	}
	return nil
}
func (r *PasswordRepository) PrunePasswordOperations(ctx context.Context, now time.Time) error {
	return r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		now = r.auth.currentTime(now)
		for _, col := range []string{PasswordChangeCollection, PasswordResetCollection, PasswordLoginCollection, PasswordNotificationCollection} {
			if err := prunePasswordRowsTx(tx, r.auth.database, col, now); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r *PasswordRepository) ClaimNotification(ctx context.Context, lease string, now time.Time, duration time.Duration) (p.Notification, bool, error) {
	var out p.Notification
	found := false
	if !deviceprotocol.ValidID(lease) || duration <= 0 {
		return out, false, d.ErrInvalidInput
	}
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		found = false
		now = r.auth.currentTime(now)
		raw, err := r.auth.database.Collection(PasswordNotificationCollection).FindOne(tx, bson.M{"state": bson.M{"$in": bson.A{"PENDING", "SENDING"}}, "nextAttemptAt": bson.M{"$lte": now}, "retainUntil": bson.M{"$gt": now}, "attempts": bson.M{"$lt": int64(8)}, "$or": bson.A{bson.M{"leaseUntil": bson.M{"$exists": false}}, bson.M{"leaseUntil": bson.M{"$lte": now}}}}, options.FindOne().SetSort(bson.D{{Key: "nextAttemptAt", Value: 1}, {Key: "eventId", Value: 1}})).Raw()
		if errors.Is(err, m.ErrNoDocuments) {
			return nil
		}
		if err != nil {
			return err
		}
		if !identityFields(raw, map[string]bson.Type{"eventId": bson.TypeString, "authId": bson.TypeString, "email": bson.TypeString, "kind": bson.TypeString, "state": bson.TypeString, "attempts": bson.TypeInt64, "createdAt": bson.TypeDateTime, "nextAttemptAt": bson.TypeDateTime, "retainUntil": bson.TypeDateTime}) {
			return d.ErrUnavailable
		}
		out = p.Notification{EventID: raw.Lookup("eventId").StringValue(), AuthID: raw.Lookup("authId").StringValue(), Email: raw.Lookup("email").StringValue(), Kind: raw.Lookup("kind").StringValue(), LeaseID: lease, Attempts: raw.Lookup("attempts").Int64() + 1, ChangedAt: raw.Lookup("createdAt").Time()}
		normalized, err := email.NormalizeEmail(out.Email)
		if err != nil || normalized != out.Email || !deviceprotocol.ValidID(out.EventID) || out.AuthID == "" || (out.Kind != "PASSWORD_CHANGED" && out.Kind != "PASSWORD_RESET") || out.Attempts < 1 || out.Attempts > 8 || !raw.Lookup("retainUntil").Time().Equal(out.ChangedAt.Add(24*time.Hour)) {
			return d.ErrUnavailable
		}
		var principal bson.Raw
		err = r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": out.AuthID}).Decode(&principal)
		if err != nil {
			return d.ErrUnavailable
		}
		status := principal.Lookup("accountStatus")
		if status.Type != bson.TypeString {
			return d.ErrUnavailable
		}
		if status.StringValue() == "CLOSED" {
			if !validClosedPrincipal(principal) {
				return d.ErrUnavailable
			}
			_, err = r.auth.database.Collection(PasswordNotificationCollection).UpdateOne(tx, bson.M{"eventId": out.EventID}, bson.M{"$set": bson.M{"state": "CANCELLED"}})
			return err
		}
		if status.StringValue() != "ACTIVE" && status.StringValue() != "DISABLED" {
			return d.ErrUnavailable
		}
		_, err = r.auth.database.Collection(PasswordNotificationCollection).UpdateOne(tx, bson.M{"eventId": out.EventID, "attempts": out.Attempts - 1}, bson.M{"$set": bson.M{"state": "SENDING", "attempts": out.Attempts, "leaseId": lease, "leaseUntil": now.Add(duration), "nextAttemptAt": now.Add(duration)}})
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}
func (r *PasswordRepository) FinishNotification(ctx context.Context, n p.Notification, delivered bool, now time.Time) error {
	return r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		now = r.auth.currentTime(now)
		status := "PENDING"
		delay := time.Minute * time.Duration(1<<min(n.Attempts-1, 6))
		delay = min(delay, time.Hour)
		if delivered {
			status = "SENT"
		} else if n.Attempts >= 8 {
			status = "FAILED"
		}
		_, err := r.auth.database.Collection(PasswordNotificationCollection).UpdateOne(tx, bson.M{"eventId": n.EventID, "authId": n.AuthID, "state": "SENDING", "leaseId": n.LeaseID, "attempts": n.Attempts, "retainUntil": bson.M{"$gt": now}}, bson.M{"$set": bson.M{"state": status, "nextAttemptAt": now.Add(delay)}, "$unset": bson.M{"leaseId": "", "leaseUntil": ""}})
		return err
	})
}

var _ p.NotificationRepository = (*PasswordRepository)(nil)
