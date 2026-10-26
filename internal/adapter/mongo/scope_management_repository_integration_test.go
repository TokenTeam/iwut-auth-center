package mongo

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	administrator "iwut-auth-center/internal/administrator/domain"
	od "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/scopemanagement/domain"
)

func TestScopeManagementMongoAdministratorRevocationRace(t *testing.T) {
	for _, name := range []string{"race-one", "race-two", "race-three", "race-four"} {
		t.Run(name, func(t *testing.T) {
			r, oauth, actor := scopeManagementFixture(t)
			oldIdentity := account.WithIdentity(t.Context(), actor, 1)
			governance, err := NewPlatformAdministratorRepository(r.auth, true)
			if err != nil {
				t.Fatal(err)
			}
			second := "scope-revoker"
			adminCandidate(t, r.auth.database, second)
			if _, err := governance.Manage(oldIdentity, administrator.Command{ActorAuthID: actor, SubjectAuthID: second, Action: "GRANT", Reason: "independent administrator for revocation race", ExpectedRevision: 1}); err != nil {
				t.Fatal(err)
			}
			revokerIdentity := account.WithIdentity(t.Context(), second, 1)
			command := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
			start := make(chan struct{})
			var wg sync.WaitGroup
			var changed d.Operation
			var changeErr, revokeErr error
			wg.Add(2)
			go func() { defer wg.Done(); <-start; changed, changeErr = r.Change(oldIdentity, command) }()
			go func() {
				defer wg.Done()
				<-start
				_, revokeErr = governance.Manage(revokerIdentity, administrator.Command{ActorAuthID: second, SubjectAuthID: actor, Action: "REVOKE", Reason: "revoke during catalog mutation", ExpectedRevision: 2})
			}()
			close(start)
			wg.Wait()
			if revokeErr != nil {
				t.Fatal("governance revocation failed", revokeErr)
			}
			if changeErr != nil && !errors.Is(changeErr, d.ErrForbidden) {
				t.Fatal("nonlinearizable change result", changeErr)
			}
			// The exact pre-revocation identity context, including a successful
			// operation replay, cannot bypass the next online administrator gate.
			if _, err := r.Change(oldIdentity, command); !errors.Is(err, d.ErrForbidden) {
				t.Fatal("old identity changed/replayed after revocation", err)
			}
			if _, err := r.Operation(oldIdentity, actor, command.OperationID); !errors.Is(err, d.ErrForbidden) {
				t.Fatal("old identity queried after revocation", err)
			}
			live, err := oauth.ReadCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			audits, err := r.auth.database.Collection(ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{"operationId": command.OperationID})
			if err != nil {
				t.Fatal(err)
			}
			receipt, receiptErr := r.Operation(revokerIdentity, second, command.OperationID)
			if changeErr == nil {
				if changed.Outcome != "APPLIED" || live.Revision != 2 || live.Scopes[0].Enabled || audits != 1 || receiptErr != nil || receipt != changed {
					t.Fatal("change-first result was not atomically retained", changed, live, audits, receipt, receiptErr)
				}
			} else if live.Revision != 1 || !live.Scopes[0].Enabled || audits != 0 || !errors.Is(receiptErr, d.ErrNotFound) {
				t.Fatal("revoke-first mutation leaked state", live, audits, receipt, receiptErr)
			}
		})
	}
}

func TestScopeManagementMongoUnknownCommitQueriesAndSameIDRecovery(t *testing.T) {
	r, _, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	command := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	fault, appName := sessionRevocationFaultRepository(t, r.auth.database)
	faultRepository, err := NewScopeManagementRepository(fault, oauthScopes([]d.Definition{r.providers["email"], r.providers["openid"]}), func([]od.Scope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	admin := r.auth.database.Client().Database("admin")
	if err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	off := func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(off)
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	result, err := faultRepository.Change(bounded, command)
	if !errors.Is(err, d.ErrUnavailable) || result.OperationID != "" {
		t.Fatal("unconfirmed result escaped", result, err)
	}
	off()
	if _, err := r.Operation(ctx, actor, command.OperationID); !errors.Is(err, d.ErrNotFound) {
		t.Fatal("unexpected receipt at checkpoint", err)
	}
	// This failpoint rejected commit. A caller does not infer that fact: using
	// the same original ID is safe whether an uncertain transaction committed.
	result, err = r.Change(ctx, command)
	if err != nil || result.ResultRevision != 2 {
		t.Fatal(result, err)
	}
	replay, err := r.Change(ctx, command)
	if err != nil || replay != result {
		t.Fatal(replay, err)
	}
}

func TestScopeManagementMongoRegistrationContractAndPureProvisionGate(t *testing.T) {
	r, oauth, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	provider := od.Scope{Name: "profile.basic.name", Label: "Name", Description: "Read profile name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING", Enabled: true}
	manifest := []od.Scope{provider}
	for _, v := range r.providers {
		manifest = append(manifest, oauthScopes([]d.Definition{v})...)
	}
	managed, err := NewScopeManagementRepository(r.auth, manifest, func([]od.Scope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	registration := scopeDefinitions([]od.Scope{provider})[0]
	registration.ProfileValueType = ""
	command := scopeCommand(t, managed, actor, d.Change{Kind: "REGISTER", Definition: registration, Contract: "Only read the basic.name field", ProviderEvidence: "UC028 plus delivered profile provider"})
	result, err := managed.Change(ctx, command)
	if err != nil || result.ResultRevision != 2 {
		t.Fatal(result, err)
	}
	var evidence bson.Raw
	if err := r.auth.database.Collection(ScopeManagementContractCollection).FindOne(t.Context(), bson.M{"_id": provider.Name}).Decode(&evidence); err != nil || evidence.Lookup("contract").StringValue() != "Only read the basic.name field" {
		t.Fatal(evidence, err)
	}
	live, err := oauth.ReadCatalog(t.Context())
	if err != nil || len(live.Scopes) != 3 || live.Scopes[2].ProfileValueType != "STRING" {
		t.Fatal(live, err)
	}
	command = scopeCommand(t, managed, actor, d.Change{Kind: "REGISTER", Definition: registration, Contract: "same", ProviderEvidence: "same"})
	if _, err := managed.Change(ctx, command); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("occupied name registered", err)
	}
	// A separate never-initialized database must not commit even the marker if
	// its initial runtime dependency gate fails.
	fresh := newAuthenticationFixture(t, EnsureOAuthSchema)
	freshOAuth := NewOAuthRepository(fresh.r, fresh.r.database)
	if err := freshOAuth.SeedCatalogValidated(t.Context(), manifest, func([]od.Scope) error { return errors.New("route missing") }); !errors.Is(err, od.ErrScope) {
		t.Fatal(err)
	}
	for _, target := range []struct{ collection, id string }{{"auth_oauth_catalog", "current"}, {AuthenticationRuntimeCollection, scopeCatalogProvisionID}} {
		count, err := fresh.r.database.Collection(target.collection).CountDocuments(t.Context(), bson.M{"_id": target.id})
		if err != nil || count != 0 {
			t.Fatal("failed gate provisioned state", target, count, err)
		}
	}
}

func TestScopeManagementMongoConcurrentRegisterAndUC001Snapshot(t *testing.T) {
	r, oauth, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	provider := od.Scope{Name: "profile.basic.name", Label: "Name", Description: "Read profile name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING", Enabled: true}
	manifest := []od.Scope{provider}
	for _, v := range r.providers {
		manifest = append(manifest, oauthScopes([]d.Definition{v})...)
	}
	managed, err := NewScopeManagementRepository(r.auth, manifest, func([]od.Scope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	definition := scopeDefinitions([]od.Scope{provider})[0]
	definition.ProfileValueType = ""
	command := scopeCommand(t, managed, actor, d.Change{Kind: "REGISTER", Definition: definition, Contract: "Read only basic.name", ProviderEvidence: "UC028 delivered profile provider"})
	start := make(chan struct{})
	failures := make(chan error, 65)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 8; j++ {
				if _, err := NewOAuthCatalog(oauth).GetSnapshot(t.Context()); err != nil {
					failures <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, err := managed.Change(ctx, command)
		if err != nil {
			failures <- err
		}
	}()
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal("atomic REGISTER caused a catalog read failure", err)
	}
	snapshot, err := NewOAuthCatalog(oauth).GetSnapshot(t.Context())
	if err != nil || snapshot.Revision() != 2 {
		t.Fatal(snapshot, err)
	}
}

func scopeManagementFixture(t *testing.T) (*ScopeManagementRepository, *OAuthRepository, string) {
	t.Helper()
	admin, db, actor := administratorFixture(t)
	if err := EnsureOAuthSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	oauth := NewOAuthRepository(admin.authentication, db)
	seed := []od.Scope{{Name: "email", Label: "Email", Description: "Read verified email", Kind: "PROTOCOL", Enabled: true}, {Name: "openid", Label: "Login", Description: "Identify user", Kind: "PROTOCOL", Enabled: true}}
	if err := oauth.SeedCatalog(t.Context(), seed); err != nil {
		t.Fatal(err)
	}
	r, err := NewScopeManagementRepository(admin.authentication, seed, func([]od.Scope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return r, oauth, actor
}

func scopeCommand(t *testing.T, r *ScopeManagementRepository, actor string, change d.Change) d.Command {
	t.Helper()
	s, err := r.Get(account.WithIdentity(t.Context(), actor, 1), actor)
	if err != nil {
		t.Fatal(err)
	}
	return d.Command{ActorAuthID: actor, OperationID: uuid.NewString(), ExpectedRevision: s.Revision, ExpectedDigest: s.Digest, Reason: "test formal scope management", Changes: []d.Change{change}}
}

func TestScopeManagementMongoCASNoopReplayAndStartupAuthority(t *testing.T) {
	r, oauth, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	command := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	operation, err := r.Change(ctx, command)
	if err != nil || operation.Outcome != "APPLIED" || operation.ResultRevision != 2 {
		t.Fatal(operation, err)
	}
	replayed, err := r.Change(ctx, command)
	if err != nil || replayed != operation {
		t.Fatal(replayed, err)
	}
	query, err := r.Operation(ctx, actor, command.OperationID)
	if err != nil || query != operation {
		t.Fatal(query, err)
	}
	altered := command
	altered.Reason = "different"
	if _, err := r.Change(ctx, altered); !errors.Is(err, d.ErrOperationConflict) {
		t.Fatal(err)
	}
	command.OperationID = uuid.NewString()
	if _, err := r.Change(ctx, command); !errors.Is(err, d.ErrConflict) {
		t.Fatal("stale noop", err)
	}
	noopCommand := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	noop, err := r.Change(ctx, noopCommand)
	if err != nil || noop.Outcome != "NO_CHANGE" || noop.ResultRevision != 2 || !noop.ResultGeneratedAt.Equal(operation.ResultGeneratedAt) {
		t.Fatal(noop, err)
	}
	seed := []od.Scope{{Name: "email", Label: "old config text", Description: "old description", Kind: "PROTOCOL", Enabled: true}, {Name: "openid", Label: "Login", Description: "Identify user", Kind: "PROTOCOL", Enabled: true}, {Name: "offline_access", Label: "Refresh", Description: "Issue refresh token", Kind: "PROTOCOL", Enabled: true}}
	if err := oauth.SeedCatalog(t.Context(), seed); err != nil {
		t.Fatal(err)
	}
	live, err := r.Get(ctx, actor)
	if err != nil || live.Revision != 2 || len(live.Scopes) != 2 || live.Scopes[0].Enabled || live.Scopes[0].Label != "Email" {
		t.Fatal(live, err)
	}
	count, err := r.auth.database.Collection(ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 3 {
		t.Fatal("baseline and two distinct operations expected", count, err)
	}
	// An old receipt is immutable even after later valid operations.
	_, err = r.Change(ctx, scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: true}))
	if err != nil {
		t.Fatal(err)
	}
	if replayed, err = r.Change(ctx, alteredWithOriginal(command, operation)); err != nil || replayed != operation {
		t.Fatal(replayed, err)
	}
}
func alteredWithOriginal(c d.Command, o d.Operation) d.Command {
	c.OperationID = o.OperationID
	return c
}

func TestScopeManagementMongoConcurrentCASAuditRollbackAndRevisionLimit(t *testing.T) {
	r, _, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	one := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	two := one
	two.OperationID = uuid.NewString()
	two.Changes = []d.Change{{Kind: "CORRECT_TEXT", Name: "openid", Label: "Login", Description: "Identify the current account"}}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, c := range []d.Command{one, two} {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := r.Change(ctx, c); results <- err }()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, d.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal(success, conflicts)
	}
	blocked := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: true})
	if _, err := r.auth.database.Collection(ScopeManagementAuditCollection).InsertOne(t.Context(), bson.M{"_id": blocked.OperationID, "operationId": blocked.OperationID}); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Get(ctx, actor)
	if _, err := r.Change(ctx, blocked); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("audit insertion did not rollback", err)
	}
	after, _ := r.Get(ctx, actor)
	if before.Revision != after.Revision || before.Digest != after.Digest {
		t.Fatal("catalog committed without audit")
	}
	if _, err := r.Operation(ctx, actor, blocked.OperationID); !errors.Is(err, d.ErrNotFound) {
		t.Fatal("receipt committed without audit", err)
	}
	if _, err := r.auth.database.Collection("auth_oauth_catalog").UpdateOne(t.Context(), bson.M{"_id": "current"}, bson.M{"$set": bson.M{"data.revision": int64(math.MaxInt64)}}); err != nil {
		t.Fatal(err)
	}
	max := scopeCommand(t, r, actor, d.Change{Kind: "CORRECT_TEXT", Name: "openid", Label: "Login", Description: "Corrected login description"})
	if _, err := r.Change(ctx, max); !errors.Is(err, d.ErrRevisionExhausted) {
		t.Fatal("overflow", err)
	}
}

func TestScopeManagementMongoProvisionMarkersAndCurrentAdmin(t *testing.T) {
	r, oauth, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	command := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	if _, err := r.Change(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := r.auth.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": actor}, bson.M{"$set": bson.M{"permissions": bson.A{}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Change(ctx, command); !errors.Is(err, d.ErrForbidden) {
		t.Fatal("replay bypassed revocation", err)
	}
	if _, err := r.Operation(ctx, actor, command.OperationID); !errors.Is(err, d.ErrForbidden) {
		t.Fatal("read bypassed revocation", err)
	}
	if _, err := r.auth.database.Collection("auth_oauth_catalog").DeleteOne(t.Context(), bson.M{"_id": "current"}); err != nil {
		t.Fatal(err)
	}
	if err := oauth.SeedCatalog(t.Context(), []od.Scope{{Name: "openid", Label: "Login", Description: "Identify user", Kind: "PROTOCOL", Enabled: true}}); !errors.Is(err, od.ErrUnavailable) {
		t.Fatal("silently reprovisioned", err)
	}
	if _, err := oauth.ReadCatalog(t.Context()); !errors.Is(err, od.ErrUnavailable) {
		t.Fatal("missing catalog read", err)
	}
}

func TestScopeManagementMongoRuntimeGateAndClockRollback(t *testing.T) {
	r, oauth, actor := scopeManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	r.validate = func(scopes []od.Scope) error {
		for _, v := range scopes {
			if v.Name == "email" && !v.Enabled {
				return errors.New("dependency")
			}
		}
		return nil
	}
	command := scopeCommand(t, r, actor, d.Change{Kind: "SET_ENABLED", Name: "email", Enabled: false})
	if _, err := r.Change(ctx, command); !errors.Is(err, d.ErrBlocked) {
		t.Fatal("dependency ignored", err)
	}
	r.validate = func([]od.Scope) error { return nil }
	live, err := oauth.ReadCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r.auth.clock = func() time.Time { return live.GeneratedAt.Add(-time.Hour) }
	if _, err := r.Change(ctx, command); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("generatedAt rolled back", err)
	}
}
