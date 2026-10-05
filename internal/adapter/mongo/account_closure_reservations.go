package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/accountclosure/domain"
)

func (r *AccountClosureRepository) CaptureReservations(ctx context.Context, t d.Termination) (d.NamespaceReservations, error) {
	out := d.NamespaceReservations{AuthID: t.AuthID, OperationID: t.OperationID}
	e := r.transaction(ctx, func(tx context.Context) error {
		out.Fingerprints = nil
		out.Handle = nil
		var raw bson.Raw
		if e := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": t.AuthID}).Decode(&raw); e != nil {
			return e
		}
		if !validClosedPrincipal(raw) || raw.Lookup("closureOperationId").StringValue() != t.OperationID {
			return d.ErrUnavailable
		}
		for _, col := range []string{CredentialCollection, CredentialTombstoneCollection} {
			cur, e := r.auth.database.Collection(col).Find(tx, bson.M{"authId": t.AuthID})
			if e != nil {
				return e
			}
			for cur.Next(tx) {
				v := cur.Current.Lookup("fingerprint")
				if v.Type != bson.TypeBinary {
					cur.Close(tx)
					return d.ErrUnavailable
				}
				_, fp := v.Binary()
				if len(fp) != 32 {
					cur.Close(tx)
					return d.ErrUnavailable
				}
				out.Fingerprints = append(out.Fingerprints, append([]byte{}, fp...))
			}
			if e = cur.Err(); e != nil {
				cur.Close(tx)
				return e
			}
			cur.Close(tx)
		}
		if len(out.Fingerprints) == 0 {
			return d.ErrUnavailable
		}
		e := r.auth.database.Collection(DeveloperHandleCollection).FindOne(tx, bson.M{"authId": t.AuthID}).Decode(&raw)
		if errors.Is(e, m.ErrNoDocuments) {
			return nil
		}
		if e != nil {
			return e
		}
		if !validHandleDocument(raw) && !validTerminalHandleDocument(raw) {
			return d.ErrUnavailable
		}
		out.Handle = &d.HandleReservation{DeveloperHandle: raw.Lookup("developerHandle").StringValue(), ClaimedAt: raw.Lookup("claimedAt").Time()}
		return nil
	})
	return out, e
}

// ReplayReservations is called only for a validated durable termination fact.
// Conflicting ownership indicates a corrupt/incompatible backup and fails closed.
func (r *AccountClosureRepository) ReplayReservations(ctx context.Context, v d.NamespaceReservations) error {
	return r.transaction(ctx, func(tx context.Context) error {
		for _, fp := range v.Fingerprints {
			if len(fp) != 32 {
				return d.ErrUnavailable
			}
			for _, col := range []string{CredentialCollection, CredentialTombstoneCollection} {
				var raw bson.Raw
				e := r.auth.database.Collection(col).FindOne(tx, bson.M{"fingerprint": fp}).Decode(&raw)
				if e == nil {
					if raw.Lookup("authId").Type != bson.TypeString || raw.Lookup("authId").StringValue() != v.AuthID {
						return d.ErrUnavailable
					}
				} else if !errors.Is(e, m.ErrNoDocuments) {
					return e
				}
			}
			if _, e := r.auth.database.Collection(CredentialTombstoneCollection).UpdateOne(tx, bson.M{"fingerprint": fp}, bson.M{"$setOnInsert": bson.M{"authId": v.AuthID}}, options.UpdateOne().SetUpsert(true)); e != nil {
				return e
			}
		}
		if v.Handle == nil {
			return nil
		}
		var raw bson.Raw
		e := r.auth.database.Collection(DeveloperHandleCollection).FindOne(tx, bson.M{"$or": bson.A{bson.M{"authId": v.AuthID}, bson.M{"developerHandle": v.Handle.DeveloperHandle}}}).Decode(&raw)
		if e == nil {
			if (!validHandleDocument(raw) && !validTerminalHandleDocument(raw)) || raw.Lookup("authId").StringValue() != v.AuthID || raw.Lookup("developerHandle").StringValue() != v.Handle.DeveloperHandle || !raw.Lookup("claimedAt").Time().Equal(v.Handle.ClaimedAt) {
				return d.ErrUnavailable
			}
		} else if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		_, e = r.auth.database.Collection(DeveloperHandleCollection).ReplaceOne(tx, bson.M{"authId": v.AuthID}, bson.M{"authId": v.AuthID, "developerHandle": v.Handle.DeveloperHandle, "claimedAt": v.Handle.ClaimedAt, "terminal": true}, options.Replace().SetUpsert(true))
		return e
	})
}
