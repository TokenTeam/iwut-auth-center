package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/accountclosure/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	"time"
)

// Retain is the only controlled exception to append-only audit storage. A
// subject must already be CLOSED, and every event keeps its full 180 days.
func (r *AccountClosureRepository) Retain(ctx context.Context, now time.Time, limit int) error {
	if limit < 1 || limit > 500 {
		return d.ErrInvalid
	}
	if e := r.retireClosureSecrets(ctx, now, limit); e != nil {
		return e
	}
	return r.transaction(ctx, func(tx context.Context) error {
		cutoff := now.Add(-180 * 24 * time.Hour)
		for _, spec := range []struct{ collection, subject, at string }{
			{AccountClosureAuditCollection, "subjectAuthId", "occurredAt"}, {PlatformAdminAuditCollection, "subjectAuthId", "occurredAt"}, {PermissionAuditCollection, "subjectAuthId", "occurredAt"}, {AccountStatusAuditCollection, "subjectAuthId", "occurredAt"}, {DeveloperApplicationAuditCollection, "subjectAuthId", "occurredAt"}, {"auth_developer_lifecycle_audit_events", "subjectAuthId", "occurredAt"}, {SessionManagementAuditCollection, "actorAuthId", "occurredAt"}, {EmailAuditCollection, "authId", "at"}, {EmailLoginAuditCollection, "authId", "at"}, {"auth_oauth_audit", "data.authid", "data.at"},
		} {
			cur, e := r.auth.database.Collection(spec.collection).Aggregate(tx, m.Pipeline{bson.D{{Key: "$match", Value: bson.M{spec.at: bson.M{"$lte": cutoff}}}}, bson.D{{Key: "$lookup", Value: bson.M{"from": PrincipalCollection, "localField": spec.subject, "foreignField": "authId", "as": "closureSubject"}}}, bson.D{{Key: "$match", Value: bson.M{"closureSubject.accountStatus": "CLOSED"}}}, bson.D{{Key: "$limit", Value: int64(limit)}}, bson.D{{Key: "$unset", Value: "closureSubject"}}})
			if e != nil {
				return e
			}
			for cur.Next(tx) {
				raw := cur.Current
				var id bson.M
				if bson.Unmarshal(raw, &id) != nil {
					cur.Close(tx)
					return d.ErrUnavailable
				}
				var subject bson.RawValue
				if spec.subject == "data.authid" {
					subject = raw.Lookup("data", "authid")
				} else {
					subject = raw.Lookup(spec.subject)
				}
				if subject.Type != bson.TypeString {
					cur.Close(tx)
					return d.ErrUnavailable
				}
				var principal bson.Raw
				e = r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": subject.StringValue(), "accountStatus": "CLOSED"}).Decode(&principal)
				if errors.Is(e, m.ErrNoDocuments) {
					continue
				}
				if e != nil {
					cur.Close(tx)
					return e
				}
				if !validClosedPrincipal(principal) || principal.Lookup("terminatedAt").Time().After(now) {
					cur.Close(tx)
					return d.ErrUnavailable
				}
				if spec.collection == PlatformAdminAuditCollection && raw.Lookup("actorType").Type == bson.TypeString && raw.Lookup("actorType").StringValue() == "BOOTSTRAP_COMMAND" {
					if _, e = r.auth.administratorMarkerTx(tx); e != nil {
						cur.Close(tx)
						return e
					}
					event := raw.Lookup("eventId")
					if event.Type != bson.TypeString {
						cur.Close(tx)
						return d.ErrUnavailable
					}
					res, e := r.auth.database.Collection(AuthenticationRuntimeCollection).UpdateOne(tx, bson.M{"_id": bootstrapMarker, "eventId": event.StringValue(), "subjectAuthId": subject.StringValue(), "occurredAt": bson.M{"$lte": cutoff}}, bson.M{"$set": bson.M{"auditRetiredAt": now}})
					if e != nil || res.MatchedCount != 1 {
						cur.Close(tx)
						return d.ErrUnavailable
					}
				}
				if _, e = r.auth.database.Collection(spec.collection).DeleteOne(tx, bson.M{"_id": id["_id"]}); e != nil {
					cur.Close(tx)
					return e
				}
			}
			if e = cur.Err(); e != nil {
				cur.Close(tx)
				return e
			}
			cur.Close(tx)
		}
		expired, e := r.auth.database.Collection(AccountClosureCollection).Aggregate(tx, m.Pipeline{bson.D{{Key: "$match", Value: bson.M{"retainUntil": bson.M{"$lte": now}, "terminatedAt": bson.M{"$exists": false}}}}, bson.D{{Key: "$lookup", Value: bson.M{"from": OwnerExitCollection, "localField": "operationId", "foreignField": "operationId", "as": "exitDecision"}}}, bson.D{{Key: "$match", Value: bson.M{"$or": bson.A{bson.M{"exitDecision": bson.M{"$size": 0}}, bson.M{"exitDecision.decision": owner.Cancelled, "exitDecision.appAcknowledged": true}}}}}, bson.D{{Key: "$limit", Value: int64(limit)}}})
		if e != nil {
			return e
		}
		for expired.Next(tx) {
			var o closureOperationDocument
			if expired.Decode(&o) != nil {
				expired.Close(tx)
				return d.ErrUnavailable
			}
			if _, e = r.auth.database.Collection(AccountClosureCollection).DeleteOne(tx, bson.M{"operationId": o.OperationID}); e != nil {
				expired.Close(tx)
				return e
			}
		}
		if e = expired.Err(); e != nil {
			expired.Close(tx)
			return e
		}
		expired.Close(tx)
		tasks, e := r.auth.database.Collection(AccountClosureTaskCollection).Find(tx, bson.M{"localComplete": true, "appComplete": true, "terminatedAt": bson.M{"$lte": now.Add(-30 * 24 * time.Hour)}}, options.Find().SetLimit(int64(limit)))
		if e != nil {
			return e
		}
		defer tasks.Close(tx)
		for tasks.Next(tx) {
			var t closureTask
			if tasks.Decode(&t) != nil {
				return d.ErrUnavailable
			}
			_, e = r.auth.database.Collection(AccountClosureCollection).DeleteOne(tx, bson.M{"operationId": t.OperationID})
			if e != nil {
				return e
			}
			_, e = r.auth.database.Collection(AccountClosureTaskCollection).DeleteOne(tx, bson.M{"operationId": t.OperationID})
			if e != nil {
				return e
			}
		}
		return tasks.Err()
	})
}

// Secret expiry cannot depend on the availability of App or a restored decision
// receipt. It commits separately from audit/task retirement and is always bounded.
func (r *AccountClosureRepository) retireClosureSecrets(ctx context.Context, now time.Time, limit int) error {
	return r.transaction(ctx, func(tx context.Context) error {
		ids, e := r.batchIDs(tx, AccountClosureCollection, bson.M{"retainUntil": bson.M{"$lte": now}, "$or": bson.A{bson.M{"receiptDigest": bson.M{"$exists": true}}, bson.M{"confirmationDigest": bson.M{"$exists": true}}, bson.M{"secretsRetiredAt": bson.M{"$exists": false}}}}, limit)
		if e != nil || len(ids) == 0 {
			return e
		}
		_, e = r.auth.database.Collection(AccountClosureCollection).UpdateMany(tx, bson.M{"_id": bson.M{"$in": ids}}, bson.M{"$unset": bson.M{"confirmationDigest": "", "receiptDigest": "", "publicKey": "", "developerHandle": "", "mutationDigest": ""}, "$set": bson.M{"secretsRetiredAt": now}})
		return e
	})
}
