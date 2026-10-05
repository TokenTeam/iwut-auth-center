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

type closureTask struct {
	OperationID     string    `bson:"operationId"`
	AuthID          string    `bson:"authId"`
	AccountRevision int64     `bson:"accountRevision"`
	TerminatedAt    time.Time `bson:"terminatedAt"`
	LedgerConfirmed bool      `bson:"ledgerConfirmed"`
	Step            int       `bson:"step"`
	LocalComplete   bool      `bson:"localComplete"`
}

func (t closureTask) termination() d.Termination {
	return d.Termination{AuthID: t.AuthID, AccountRevision: t.AccountRevision, OperationID: t.OperationID, TerminatedAt: t.TerminatedAt}
}
func (t closureTask) operation() d.Operation {
	return d.Operation{OperationID: t.OperationID, AuthID: t.AuthID, AccountRevision: t.AccountRevision - 1, TerminatedAt: &t.TerminatedAt, LedgerConfirmed: t.LedgerConfirmed, LocalCleanupComplete: t.LocalComplete}
}
func (r *AccountClosureRepository) Pending(ctx context.Context, now time.Time, limit int) ([]d.Operation, error) {
	if limit < 1 || limit > 500 {
		return nil, d.ErrInvalid
	}
	cur, e := r.auth.database.Collection(AccountClosureTaskCollection).Find(ctx, bson.M{"$or": bson.A{bson.M{"localComplete": false}, bson.M{"ledgerConfirmed": false}, bson.M{"appComplete": bson.M{"$ne": true}}}}, options.Find().SetSort(bson.D{{Key: "ledgerConfirmed", Value: 1}, {Key: "lastAttemptAt", Value: 1}, {Key: "operationId", Value: 1}}).SetLimit(int64(limit)))
	if e != nil {
		return nil, d.ErrUnavailable
	}
	defer cur.Close(ctx)
	var out []d.Operation
	for cur.Next(ctx) {
		var t closureTask
		if cur.Decode(&t) != nil || t.AccountRevision < 2 || !owner.ValidAuthID(t.AuthID) || !owner.ValidOperationID(t.OperationID) || t.TerminatedAt.IsZero() {
			return nil, d.ErrUnavailable
		}
		out = append(out, t.operation())
	}
	return out, cur.Err()
}
func (r *AccountClosureRepository) MarkLedger(ctx context.Context, t d.Termination) error {
	return r.transaction(ctx, func(tx context.Context) error {
		res, e := r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(tx, bson.M{"operationId": t.OperationID, "authId": t.AuthID, "accountRevision": t.AccountRevision, "terminatedAt": t.TerminatedAt}, bson.M{"$set": bson.M{"ledgerConfirmed": true}})
		if e != nil {
			return e
		}
		if res.MatchedCount != 1 {
			return d.ErrUnavailable
		}
		_, e = r.auth.database.Collection(AccountClosureCollection).UpdateOne(tx, bson.M{"operationId": t.OperationID, "authId": t.AuthID}, bson.M{"$set": bson.M{"ledgerConfirmed": true}})
		return e
	})
}
func (r *AccountClosureRepository) Replay(ctx context.Context, t d.Termination) error {
	if !owner.ValidAuthID(t.AuthID) || !owner.ValidOperationID(t.OperationID) || t.AccountRevision < 2 || t.TerminatedAt.IsZero() {
		return d.ErrUnavailable
	}
	return r.transaction(ctx, func(tx context.Context) error {
		var raw bson.Raw
		e := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": t.AuthID}).Decode(&raw)
		if e != nil && !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		if e == nil {
			if !identityFields(raw, map[string]bson.Type{"principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64}) || raw.Lookup("principalType").StringValue() != "USER" {
				return d.ErrUnavailable
			}
			rev := raw.Lookup("accountRevision").Int64()
			state := raw.Lookup("accountStatus").StringValue()
			if state == "CLOSED" {
				if rev != t.AccountRevision || raw.Lookup("closureOperationId").Type != bson.TypeString || raw.Lookup("closureOperationId").StringValue() != t.OperationID || raw.Lookup("terminatedAt").Type != bson.TypeDateTime || !raw.Lookup("terminatedAt").Time().Equal(t.TerminatedAt) {
					return d.ErrUnavailable
				}
			} else if (state != "ACTIVE" && state != "DISABLED") || rev >= t.AccountRevision {
				return d.ErrUnavailable
			}
		}
		if e = r.writeTerminalTx(tx, t); e != nil {
			return e
		}
		_, e = r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(tx, bson.M{"operationId": t.OperationID, "authId": t.AuthID, "accountRevision": t.AccountRevision}, bson.M{"$set": bson.M{"ledgerConfirmed": true}})
		if e != nil {
			return e
		}
		_, e = r.auth.database.Collection(AccountClosureCollection).UpdateOne(tx, bson.M{"operationId": t.OperationID, "authId": t.AuthID}, bson.M{"$set": bson.M{"terminatedAt": t.TerminatedAt, "state": d.Terminated, "ledgerConfirmed": true, "retainUntil": t.TerminatedAt.Add(30 * 24 * time.Hour)}})
		if e != nil {
			return e
		}
		// Restored pending decisions may be advanced only by the durable terminal fact.
		old, e := r.auth.ReadOwnerExitTx(tx, t.AuthID, t.OperationID)
		if errors.Is(e, owner.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if old.Purpose != owner.Closure || old.Decision == owner.Cancelled {
			return d.ErrUnavailable
		}
		if old.Decision == owner.Pending {
			if old.ReceiptID == "" {
				return nil
			}
			_, e = r.auth.database.Collection(OwnerExitCollection).UpdateOne(tx, bson.M{"operationId": t.OperationID, "decision": owner.Pending}, bson.M{"$set": bson.M{"decision": owner.Committed, "decidedAt": t.TerminatedAt, "notificationPending": true, "nextAttemptAt": t.TerminatedAt}})
		}
		return e
	})
}

// RecoverOwner repairs a restored database whose original App preparation was
// not included in the backup. Only an exact App receipt may complete the record.
func (r *AccountClosureRepository) RecoverOwner(ctx context.Context, t d.Termination, status owner.Status) error {
	return r.transaction(ctx, func(tx context.Context) error {
		if status.AuthID != t.AuthID || status.OperationID != t.OperationID || status.Purpose != owner.Closure || !owner.ValidReceiptID(status.ReceiptID) || (status.Decision != owner.Pending && status.Decision != owner.Committed) {
			return d.ErrUnavailable
		}
		old, e := r.auth.ReadOwnerExitTx(tx, t.AuthID, t.OperationID)
		if e == nil {
			if old.Decision == owner.Cancelled || old.ReceiptID != "" && old.ReceiptID != status.ReceiptID {
				return d.ErrUnavailable
			}
			if old.Decision == owner.Committed {
				return nil
			}
		} else if !errors.Is(e, owner.ErrNotFound) {
			return e
		}
		at := t.TerminatedAt
		o := owner.Operation{OperationID: t.OperationID, AuthID: t.AuthID, Purpose: owner.Closure, Decision: owner.Committed, ReceiptID: status.ReceiptID, AccountRevision: t.AccountRevision - 1, DeveloperRevision: 0, PermissionRevision: 1, CreatedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute), DecidedAt: &at, NotificationPending: true, NextAttemptAt: at}
		_, e = r.auth.database.Collection(OwnerExitCollection).ReplaceOne(tx, bson.M{"operationId": t.OperationID}, o, options.Replace().SetUpsert(true))
		return e
	})
}
func (r *AccountClosureRepository) batchIDs(ctx context.Context, col string, q bson.M, limit int) ([]any, error) {
	cur, e := r.auth.database.Collection(col).Find(ctx, q, options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(int64(limit)))
	if e != nil {
		return nil, e
	}
	defer cur.Close(ctx)
	var ids []any
	for cur.Next(ctx) {
		var doc bson.M
		if cur.Decode(&doc) != nil {
			return nil, d.ErrUnavailable
		}
		ids = append(ids, doc["_id"])
	}
	return ids, cur.Err()
}
func (r *AccountClosureRepository) deleteBatch(ctx context.Context, col string, q bson.M, limit int) (bool, error) {
	ids, e := r.batchIDs(ctx, col, q, limit)
	if e != nil {
		return false, e
	}
	if len(ids) == 0 {
		return true, nil
	}
	_, e = r.auth.database.Collection(col).DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	return false, e
}
func (r *AccountClosureRepository) Cleanup(ctx context.Context, id string, now time.Time, limit int) (bool, error) {
	if limit < 1 || limit > 500 {
		return false, d.ErrInvalid
	}
	complete := false
	err := r.transaction(ctx, func(tx context.Context) error {
		var task closureTask
		if e := r.auth.database.Collection(AccountClosureTaskCollection).FindOne(tx, bson.M{"operationId": id}).Decode(&task); e != nil {
			return e
		}
		if !task.LedgerConfirmed {
			return d.ErrUnavailable
		}
		var principal bson.Raw
		if e := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": task.AuthID}).Decode(&principal); e != nil {
			return e
		}
		if principal.Lookup("accountStatus").Type != bson.TypeString || principal.Lookup("accountStatus").StringValue() != "CLOSED" || principal.Lookup("closureOperationId").Type != bson.TypeString || principal.Lookup("closureOperationId").StringValue() != id {
			return d.ErrUnavailable
		}
		if task.LocalComplete {
			complete = true
			owned, e := r.auth.ReadOwnerExitTx(tx, task.AuthID, id)
			if e != nil {
				return e
			}
			if owned.AppAcknowledged && owned.AppCleanupState == "COMPLETE" {
				_, e = r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(tx, bson.M{"operationId": id}, bson.M{"$set": bson.M{"appComplete": true}})
			}
			return e
		}
		authID := task.AuthID
		done := false
		var e error
		switch task.Step {
		case 0: // Occupancy is permanent even after the public key bytes are deleted.
			cur, err := r.auth.database.Collection(CredentialCollection).Find(tx, bson.M{"authId": authID}, options.Find().SetLimit(int64(limit)))
			if err != nil {
				return err
			}
			defer cur.Close(tx)
			n := 0
			for cur.Next(tx) {
				var c CredentialDocument
				if cur.Decode(&c) != nil || !validCredential(c) {
					return d.ErrUnavailable
				}
				_, e = r.auth.database.Collection(CredentialTombstoneCollection).UpdateOne(tx, bson.M{"fingerprint": c.Fingerprint}, bson.M{"$setOnInsert": bson.M{"authId": authID}}, options.UpdateOne().SetUpsert(true))
				if e != nil {
					return e
				}
				var tomb bson.M
				if e = r.auth.database.Collection(CredentialTombstoneCollection).FindOne(tx, bson.M{"fingerprint": c.Fingerprint}).Decode(&tomb); e != nil || tomb["authId"] != authID {
					return d.ErrUnavailable
				}
				_, e = r.auth.database.Collection(CredentialCollection).DeleteOne(tx, bson.M{"authId": authID, "credentialId": c.CredentialID})
				if e != nil {
					return e
				}
				n++
			}
			if e = cur.Err(); e != nil {
				return e
			}
			done = n == 0
		case 1: // Collect linked email references before removing registration results.
			cur, err := r.auth.database.Collection(AuthenticationOperationCollection).Find(tx, bson.M{"$or": bson.A{bson.M{"authId": authID}, bson.M{"completedAuthId": authID}}}, options.Find().SetLimit(int64(limit)))
			if err != nil {
				return err
			}
			defer cur.Close(tx)
			var ids []string
			for cur.Next(tx) {
				var op OperationDocument
				if cur.Decode(&op) != nil || op.OperationID == "" {
					return d.ErrUnavailable
				}
				ids = append(ids, op.OperationID)
			}
			if e = cur.Err(); e != nil {
				return e
			}
			if len(ids) > 0 {
				_, e = r.auth.database.Collection(EmailOperationCollection).DeleteMany(tx, bson.M{"operationId": bson.M{"$in": ids}})
				if e != nil {
					return e
				}
				_, e = r.auth.database.Collection(AuthenticationOperationCollection).DeleteMany(tx, bson.M{"operationId": bson.M{"$in": ids}})
			}
			done = len(ids) == 0
		case 2:
			done, e = r.deleteBatch(tx, EmailOperationCollection, bson.M{"owner": authID}, limit)
		case 3:
			done, e = r.deleteBatch(tx, EmailBindingCollection, bson.M{"authId": authID}, limit)
		case 4: // Refresh only carries familyId. Drain children before deleting family.
			var family bson.Raw
			err := r.auth.database.Collection("auth_oauth_families").FindOne(tx, bson.M{"data.authid": authID}).Decode(&family)
			if errors.Is(err, m.ErrNoDocuments) {
				done = true
			} else if err != nil {
				return err
			} else {
				fid := family.Lookup("_id")
				if fid.Type != bson.TypeString {
					return d.ErrUnavailable
				}
				drained, err := r.deleteBatch(tx, "auth_oauth_refresh", bson.M{"data.familyid": fid.StringValue()}, limit)
				if err != nil {
					return err
				}
				if drained {
					_, e = r.auth.database.Collection("auth_oauth_families").DeleteOne(tx, bson.M{"_id": fid.StringValue(), "data.authid": authID})
				}
			}
		case 5, 6, 7, 8, 9:
			col := []string{"interactions", "codes", "access", "grants", "subjects"}[task.Step-5]
			done, e = r.deleteBatch(tx, "auth_oauth_"+col, bson.M{"$or": bson.A{bson.M{"data.authid": authID}, bson.M{"authId": authID}}}, limit)
		case 10:
			done, e = r.deleteBatch(tx, SessionCollection, bson.M{"authId": authID}, limit)
		case 11:
			done, e = r.cleanupAssociationTx(tx, id, authID, now)
		case 12:
			var raw bson.Raw
			e = r.auth.database.Collection(DeveloperHandleCollection).FindOne(tx, bson.M{"authId": authID}).Decode(&raw)
			if e == nil {
				if !identityFields(raw, map[string]bson.Type{"developerHandle": bson.TypeString, "claimedAt": bson.TypeDateTime}) {
					return d.ErrUnavailable
				}
				_, e = r.auth.database.Collection(DeveloperHandleCollection).ReplaceOne(tx, bson.M{"authId": authID}, bson.M{"authId": authID, "developerHandle": raw.Lookup("developerHandle").StringValue(), "claimedAt": raw.Lookup("claimedAt").Time(), "terminal": true})
			} else if errors.Is(e, m.ErrNoDocuments) {
				e = nil
			}
			if e != nil {
				return e
			}
			done, e = r.deleteBatch(tx, DeveloperActivationCollection, bson.M{"authId": authID}, limit)
		case 13:
			done, e = r.deleteBatch(tx, AccountClosureCollection, bson.M{"authId": authID, "operationId": bson.M{"$ne": id}}, limit)
		case 14:
			done, e = r.deleteBatch(tx, OwnerExitRequestCollection, bson.M{"authId": authID}, limit)
		default:
			complete = true
		}
		if e != nil {
			return e
		}
		if done {
			task.Step++
		}
		if task.Step > 14 {
			complete = true
		}
		_, e = r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(tx, bson.M{"operationId": id}, bson.M{"$set": bson.M{"step": task.Step, "localComplete": complete, "lastAttemptAt": now}})
		if e != nil {
			return e
		}
		if complete {
			_, e = r.auth.database.Collection(AccountClosureCollection).UpdateOne(tx, bson.M{"operationId": id}, bson.M{"$set": bson.M{"localCleanupComplete": true}, "$unset": bson.M{"publicKey": "", "developerHandle": "", "mutationDigest": ""}})
		}
		return e
	})
	return complete, err
}
func (r *AccountClosureRepository) cleanupAssociationTx(ctx context.Context, id, authID string, now time.Time) (bool, error) {
	var member struct {
		AssociationID string `bson:"associationId"`
	}
	e := r.auth.database.Collection(AssociationMemberCollection).FindOne(ctx, bson.M{"authId": authID}).Decode(&member)
	if errors.Is(e, m.ErrNoDocuments) {
		if e = r.auth.database.Collection(AccountClosureTaskCollection).FindOne(ctx, bson.M{"operationId": id}).Decode(&member); e != nil {
			return false, e
		}
		if member.AssociationID == "" {
			return true, nil
		}
	} else if e != nil || member.AssociationID == "" {
		return false, d.ErrUnavailable
	}
	var group associationDocument
	e = r.auth.database.Collection(AssociationCollection).FindOne(ctx, bson.M{"associationId": member.AssociationID}).Decode(&group)
	if errors.Is(e, m.ErrNoDocuments) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	if _, e = r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(ctx, bson.M{"operationId": id}, bson.M{"$set": bson.M{"associationId": member.AssociationID}}); e != nil {
		return false, e
	}
	if _, e = r.auth.database.Collection(AssociationMemberCollection).DeleteOne(ctx, bson.M{"authId": authID, "associationId": member.AssociationID}); e != nil {
		return false, e
	}
	n, e := r.auth.database.Collection(AssociationMemberCollection).CountDocuments(ctx, bson.M{"associationId": member.AssociationID})
	if e != nil {
		return false, e
	}
	if n > 0 {
		return true, nil
	}
	pending, e := r.auth.database.Collection(AuthenticationOperationCollection).CountDocuments(ctx, bson.M{"status": "PENDING", "expiresAt": bson.M{"$gt": now}, "keyVersion": group.KeyVersion, "lookupKey": group.LookupKey})
	if e != nil {
		return false, e
	}
	if pending > 0 {
		return false, nil
	}
	_, e = r.auth.database.Collection(AssociationCollection).DeleteOne(ctx, bson.M{"associationId": member.AssociationID})
	return e == nil, e
}
func (r *AccountClosureRepository) Attempt(ctx context.Context, id string, now time.Time) error {
	return r.transaction(ctx, func(tx context.Context) error {
		_, e := r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(tx, bson.M{"operationId": id}, bson.M{"$set": bson.M{"lastAttemptAt": now}})
		return e
	})
}

// VerifyLedger distinguishes an unconfirmed local commit (safe to export) from
// an already acknowledged durable fact missing in an empty/wrong ledger mount.
func (r *AccountClosureRepository) VerifyLedger(ctx context.Context, records []d.Termination) error {
	known := map[string]d.Termination{}
	for _, t := range records {
		if _, ok := known[t.AuthID]; ok {
			return d.ErrUnavailable
		}
		known[t.AuthID] = t
	}
	return r.transaction(ctx, func(tx context.Context) error {
		cur, e := r.auth.database.Collection(PrincipalCollection).Find(tx, bson.M{"accountStatus": "CLOSED"})
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			raw := cur.Current
			if !validClosedPrincipal(raw) {
				return d.ErrUnavailable
			}
			id := raw.Lookup("authId").StringValue()
			t := d.Termination{AuthID: id, OperationID: raw.Lookup("closureOperationId").StringValue(), AccountRevision: raw.Lookup("accountRevision").Int64(), TerminatedAt: raw.Lookup("terminatedAt").Time()}
			if saved, ok := known[id]; ok {
				if saved.AuthID != t.AuthID || saved.AccountRevision != t.AccountRevision || saved.OperationID != t.OperationID || !saved.TerminatedAt.Equal(t.TerminatedAt) {
					return d.ErrUnavailable
				}
				continue
			}
			var task closureTask
			e = r.auth.database.Collection(AccountClosureTaskCollection).FindOne(tx, bson.M{"operationId": t.OperationID, "authId": id}).Decode(&task)
			if e != nil || task.LedgerConfirmed || task.AccountRevision != t.AccountRevision || !task.TerminatedAt.Equal(t.TerminatedAt) {
				return d.ErrUnavailable
			}
		}
		return cur.Err()
	})
}
