package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	admin "iwut-auth-center/internal/administrator/domain"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/managedusersearch/domain"
	system "iwut-auth-center/internal/systemprincipal/domain"
)

type ManagedUserSearchRepository struct{ auth *AuthenticationRepository }

func NewManagedUserSearchRepository(auth *AuthenticationRepository) *ManagedUserSearchRepository {
	return &ManagedUserSearchRepository{auth}
}

func (r *ManagedUserSearchRepository) Search(ctx context.Context, actor string, query d.Query) (d.Result, error) {
	var result d.Result
	var cause error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		result = d.Result{}
		cause = r.auth.RequireAdministratorTx(tx, actor)
		switch {
		case errors.Is(cause, admin.ErrIdentity):
			cause = d.ErrIdentity
		case errors.Is(cause, admin.ErrForbidden):
			cause = d.ErrForbidden
		case cause != nil:
			cause = d.ErrUnavailable
		default:
			result, cause = r.search(tx, query)
		}
		return cause
	})
	if ctx.Err() != nil {
		return d.Result{}, ctx.Err()
	}
	if err != nil {
		for _, known := range []error{d.ErrIdentity, d.ErrForbidden, d.ErrInvalid} {
			if errors.Is(cause, known) {
				return d.Result{}, known
			}
		}
		return d.Result{}, d.ErrUnavailable
	}
	return result, nil
}

func (r *ManagedUserSearchRepository) search(ctx context.Context, query d.Query) (d.Result, error) {
	result := d.Result{Items: []d.Summary{}, AsOf: r.auth.currentTime(time.Time{})}
	subject := query.Value
	var binding bson.Raw
	switch query.Kind {
	case "authId":
		if !d.ValidID(subject) {
			return d.Result{}, d.ErrInvalid
		}
	case "email":
		address, err := email.NormalizeEmail(query.Value)
		if err != nil {
			return d.Result{}, d.ErrInvalid
		}
		binding, err = r.findUnique(ctx, EmailBindingCollection, bson.M{"email": address})
		if err != nil {
			return d.Result{}, err
		}
		if binding == nil {
			return result, nil
		}
		if !identityFields(binding, map[string]bson.Type{"authId": bson.TypeString, "bindingId": bson.TypeString, "email": bson.TypeString, "verifiedAt": bson.TypeDateTime}) ||
			binding.Lookup("email").StringValue() != address || !d.ValidID(binding.Lookup("authId").StringValue()) {
			return d.Result{}, d.ErrUnavailable
		}
		subject = binding.Lookup("authId").StringValue()
	default:
		return d.Result{}, d.ErrInvalid
	}
	raw, err := r.findUnique(ctx, PrincipalCollection, bson.M{"authId": subject})
	if err != nil {
		return d.Result{}, err
	}
	if raw == nil {
		if binding != nil {
			return d.Result{}, d.ErrUnavailable
		}
		return result, nil
	}
	summary, visible, err := managedUserSummary(raw, subject)
	if err != nil {
		return d.Result{}, err
	}
	if !visible {
		return result, nil
	}
	if binding != nil {
		directory, err := ReadEmailDirectoryTx(ctx, r.auth.database, subject)
		if err != nil {
			return d.Result{}, d.ErrUnavailable
		}
		found := false
		for _, item := range directory.Bindings {
			if item.BindingID == binding.Lookup("bindingId").StringValue() && item.Email == binding.Lookup("email").StringValue() {
				found = true
			}
		}
		if !found {
			return d.Result{}, d.ErrUnavailable
		}
	}
	result.Items = append(result.Items, summary)
	return result, nil
}

// Each selector uses a unique index; the second record detects corrupt uniqueness.
func (r *ManagedUserSearchRepository) findUnique(ctx context.Context, collection string, filter bson.M) (bson.Raw, error) {
	cursor, err := r.auth.database.Collection(collection).Find(ctx, filter, options.Find().SetLimit(2))
	if err != nil {
		return nil, d.ErrUnavailable
	}
	defer cursor.Close(ctx)
	var records []bson.Raw
	if err := cursor.All(ctx, &records); err != nil || len(records) > 1 {
		return nil, d.ErrUnavailable
	}
	if len(records) == 0 {
		return nil, nil
	}
	return records[0], nil
}

func managedUserSummary(raw bson.Raw, subject string) (d.Summary, bool, error) {
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString}) || raw.Lookup("authId").StringValue() != subject {
		return d.Summary{}, false, d.ErrUnavailable
	}
	switch raw.Lookup("principalType").StringValue() {
	case "SYSTEM":
		purpose, ok := raw.Lookup("systemPurpose").StringValueOK()
		if _, err := system.NewPurpose(purpose); !ok || err != nil || raw.Lookup("developerStatus").Type != bson.TypeNull {
			return d.Summary{}, false, d.ErrUnavailable
		}
		return d.Summary{}, false, nil
	case "USER":
	default:
		return d.Summary{}, false, d.ErrUnavailable
	}
	status, ok := raw.Lookup("accountStatus").StringValueOK()
	if ok && status == "CLOSED" && validClosedPrincipal(raw) {
		return d.Summary{}, false, nil
	}
	if !ok || (status != "ACTIVE" && status != "DISABLED") || !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64}) ||
		raw.Lookup("accountRevision").Int64() <= 0 || !validDeveloperLifecycle(raw) {
		return d.Summary{}, false, d.ErrUnavailable
	}
	summary := d.Summary{AuthID: subject, AccountStatus: status}
	if raw.Lookup("developerStatus").Type == bson.TypeString {
		summary.DeveloperStatus = raw.Lookup("developerStatus").StringValue()
	}
	return summary, true, nil
}
