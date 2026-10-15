package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	d "iwut-auth-center/internal/emailaccount/domain"
	email "iwut-auth-center/internal/emailbinding/domain"
)

const EmailDirectoryCollection = "auth_email_directories"
const EmailAccountOperationCollection = "auth_email_account_operations"
const EmailAccountMutationCollection = "auth_email_account_mutations"

type emailDirectoryDocument struct {
	AuthID            string `bson:"authId"`
	LoginBindingID    string `bson:"loginBindingId"`
	Revision          int64  `bson:"revision"`
	LoginRoleRevision int64  `bson:"loginRoleRevision"`
	VerifiedCount     int64  `bson:"verifiedCount"`
}
type emailBindingDocument struct {
	BindingID  string    `bson:"bindingId"`
	AuthID     string    `bson:"authId"`
	Email      string    `bson:"email"`
	VerifiedAt time.Time `bson:"verifiedAt"`
}

func EnsureEmailAccountSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	// No automatic data migration. An empty legacy collection may retire its old
	// one-binding-per-owner index; populated old records require explicit rebuild.
	indexes, err := db.Collection(EmailBindingCollection).Indexes().List(ctx)
	if err != nil {
		return err
	}
	var prior []bson.M
	if err = indexes.All(ctx, &prior); err != nil {
		return err
	}
	for _, index := range prior {
		name, _ := index["name"].(string)
		unique, _ := index["unique"].(bool)
		if name == "authId_1" && unique {
			count, err := db.Collection(EmailBindingCollection).CountDocuments(ctx, bson.M{}, options.Count().SetLimit(1))
			if err != nil {
				return err
			}
			if count != 0 {
				return d.ErrUnavailable
			}
			if err = db.Collection(EmailBindingCollection).Indexes().DropOne(ctx, name); err != nil {
				return err
			}
		}
	}
	for col, models := range map[string][]m.IndexModel{
		EmailDirectoryCollection: {{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_directory_owner_unique")}, {Keys: bson.D{{Key: "loginBindingId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_login_binding_unique")}},
		EmailBindingCollection: {
			{Keys: bson.D{{Key: "bindingId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_binding_id_unique")},
			{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_address_unique")},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "verifiedAt", Value: 1}, {Key: "bindingId", Value: 1}}, Options: options.Index().SetName("email_binding_owner_order")},
		},
		EmailAccountOperationCollection: {
			{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_account_operation_unique")},
			{Keys: bson.D{{Key: "purpose", Value: 1}, {Key: "actor", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_account_request_unique")},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}, Options: options.Index().SetName("email_account_owner_pending")},
			{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("email_account_retention")},
		},
		EmailAccountMutationCollection: {
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "purpose", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_mutation_request_unique")},
			{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_mutation_operation_unique")},
			{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("email_mutation_retention")},
		},
		EmailQuotaCollection: {{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
		EmailAuditCollection: {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_audit_operation_unique")}},
	} {
		if _, err := db.Collection(col).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	return nil
}

func ReadEmailDirectoryTx(ctx context.Context, db *m.Database, authID string) (d.Directory, error) {
	var raw bson.Raw
	err := db.Collection(EmailDirectoryCollection).FindOne(ctx, bson.M{"authId": authID}).Decode(&raw)
	if err != nil {
		return d.Directory{}, d.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "loginBindingId": bson.TypeString, "revision": bson.TypeInt64, "loginRoleRevision": bson.TypeInt64, "verifiedCount": bson.TypeInt64}) {
		return d.Directory{}, d.ErrUnavailable
	}
	var directory emailDirectoryDocument
	if bson.Unmarshal(raw, &directory) != nil || directory.AuthID != authID || directory.Revision <= 0 || directory.LoginRoleRevision <= 0 || directory.LoginRoleRevision > directory.Revision || directory.VerifiedCount < 1 || directory.VerifiedCount > 10 || !deviceprotocol.ValidID(directory.LoginBindingID) {
		return d.Directory{}, d.ErrUnavailable
	}
	cur, err := db.Collection(EmailBindingCollection).Find(ctx, bson.M{"authId": authID}, options.Find().SetSort(bson.D{{Key: "verifiedAt", Value: 1}, {Key: "bindingId", Value: 1}}).SetLimit(11))
	if err != nil {
		return d.Directory{}, err
	}
	defer cur.Close(ctx)
	out := d.Directory{AuthID: authID, Revision: directory.Revision, LoginRoleRevision: directory.LoginRoleRevision, LoginBindingID: directory.LoginBindingID, Bindings: []d.Binding{}}
	primary := 0
	for cur.Next(ctx) {
		var raw bson.Raw
		if err = cur.Decode(&raw); err != nil {
			return d.Directory{}, err
		}
		if !identityFields(raw, map[string]bson.Type{"bindingId": bson.TypeString, "authId": bson.TypeString, "email": bson.TypeString, "verifiedAt": bson.TypeDateTime}) {
			return d.Directory{}, d.ErrUnavailable
		}
		var binding emailBindingDocument
		if bson.Unmarshal(raw, &binding) != nil {
			return d.Directory{}, d.ErrUnavailable
		}
		normalized, err := email.NormalizeEmail(binding.Email)
		if err != nil || normalized != binding.Email || binding.AuthID != authID || !deviceprotocol.ValidID(binding.BindingID) || binding.VerifiedAt.IsZero() {
			return d.Directory{}, d.ErrUnavailable
		}
		if binding.BindingID == directory.LoginBindingID {
			primary++
		}
		out.Bindings = append(out.Bindings, d.Binding{BindingID: binding.BindingID, AuthID: authID, Email: binding.Email, VerifiedAt: binding.VerifiedAt})
	}
	if cur.Err() != nil {
		return d.Directory{}, cur.Err()
	}
	if int64(len(out.Bindings)) != directory.VerifiedCount || primary != 1 {
		return d.Directory{}, d.ErrUnavailable
	}
	return out, nil
}

func ReadPrimaryEmailTx(ctx context.Context, db *m.Database, authID string) (d.Binding, int64, error) {
	directory, err := ReadEmailDirectoryTx(ctx, db, authID)
	if err != nil {
		return d.Binding{}, 0, err
	}
	primary, ok := directory.Primary()
	if !ok {
		return d.Binding{}, 0, d.ErrUnavailable
	}
	return primary, directory.LoginRoleRevision, nil
}

// ResolvePrimaryEmailTx never authorizes a non-primary binding. Ownership of an
// address is not its login/recovery role, and no missing directory is repaired.
func ResolvePrimaryEmailTx(ctx context.Context, db *m.Database, address string) (d.Binding, int64, bool, error) {
	var raw bson.Raw
	err := db.Collection(EmailBindingCollection).FindOne(ctx, bson.M{"email": address}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.Binding{}, 0, false, nil
	}
	if err != nil {
		return d.Binding{}, 0, false, err
	}
	owner := raw.Lookup("authId")
	if owner.Type != bson.TypeString || owner.StringValue() == "" {
		return d.Binding{}, 0, false, d.ErrUnavailable
	}
	binding, revision, err := ReadPrimaryEmailTx(ctx, db, owner.StringValue())
	if err != nil {
		return d.Binding{}, 0, false, err
	}
	if binding.Email != address {
		return d.Binding{}, 0, false, nil
	}
	return binding, revision, true, nil
}
