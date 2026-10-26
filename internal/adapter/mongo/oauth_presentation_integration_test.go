package mongo

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/oauth/domain"
)

func TestOAuthMongoConsentPresentationCatalogAndTabs(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	scopes := []string{"openid", "email"}
	view := f.begin(t, scopes, "public-client", 1)
	if view.PresentationID == "" || len(view.Definitions) != 2 {
		t.Fatal("missing request-specific display evidence")
	}
	// A real administrator changes a scope outside R. Global revision changes,
	// but the page remains valid because its requested definitions did not.
	next := append([]d.Scope(nil), f.seed...)
	next[3].Description += " corrected"
	if err := updateOAuthFixtureCatalog(t, f.repo, next); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, scopes, true); err != nil {
		t.Fatal("unrelated catalog change invalidated consent", err)
	}
	view = f.begin(t, scopes, "public-client", 1)
	next[1].Description += " corrected"
	if err := updateOAuthFixtureCatalog(t, f.repo, next); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, scopes, true); !errors.Is(err, d.ErrConflict) {
		t.Fatal("related wording change did not require a new view", err)
	}
	fresh, err := f.service.View(ctx, view.InteractionID, view.CSRF, f.session)
	if err != nil || fresh.PresentationID == view.PresentationID {
		t.Fatal("new View failed to rotate evidence", err)
	}
	if _, err = f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, scopes, true); !errors.Is(err, d.ErrConflict) {
		t.Fatal("old tab borrowed latest server snapshot", err)
	}
	if _, err = f.service.Confirm(ctx, fresh.InteractionID, fresh.CSRF, "", f.session, scopes, true); !errors.Is(err, d.ErrConflict) {
		t.Fatal("missing presentation accepted", err)
	}
	if _, err = f.service.Confirm(ctx, fresh.InteractionID, fresh.CSRF, fresh.PresentationID, f.session, scopes, true); err != nil {
		t.Fatal("fresh consent failed", err)
	}
	var interaction oauthDocument[d.Interaction]
	if err = f.repo.db.Collection("auth_oauth_interactions").FindOne(ctx, bson.M{"_id": fresh.InteractionID}).Decode(&interaction); err != nil || interaction.Data.Status != "APPROVED" {
		t.Fatal("confirmation did not persist", err)
	}
	var audit oauthDocument[d.Audit]
	if err = f.repo.db.Collection("auth_oauth_audit").FindOne(ctx, bson.M{"data.presentation.id": fresh.PresentationID}).Decode(&audit); err != nil {
		t.Fatal("actual display evidence missing from audit", err)
	}
	if audit.Data.ConsentSource != "EXPLICIT" || !validOAuthConsentAudit(audit.Data) || audit.Data.Presentation.Definitions[0].Name != "email" {
		t.Fatalf("bad explicit consent audit: %+v", audit.Data)
	}
}

func TestOAuthMongoConsentLegacyRequiresViewAndRejectsMalformedEvidence(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	view := f.begin(t, []string{"openid", "email"}, "public-client", 1)
	collection := f.repo.db.Collection("auth_oauth_interactions")
	if _, err := collection.UpdateOne(ctx, bson.M{"_id": view.InteractionID}, bson.M{"$unset": bson.M{"data.presentation": ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, []string{"openid", "email"}, true); !errors.Is(err, d.ErrConflict) {
		t.Fatal("legacy evidence-free interaction authorized directly", err)
	}
	newView, err := f.service.View(ctx, view.InteractionID, view.CSRF, f.session)
	if err != nil || newView.PresentationID == "" {
		t.Fatal("legacy interaction could not be re-presented", err)
	}
	if _, err = collection.UpdateOne(ctx, bson.M{"_id": view.InteractionID}, bson.M{"$unset": bson.M{"data.presentation.definitions.0.enabled": ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.View(ctx, view.InteractionID, view.CSRF, f.session); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("malformed evidence silently repaired", err)
	}
}

func TestOAuthMongoConsentAuditFailureRollsBack(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	view := f.begin(t, []string{"openid", "email"}, "public-client", 1)
	// Fail only the audit write in the real Mongo transaction. No successful
	// code, grant, or APPROVED interaction may survive the late failure.
	if err := f.repo.db.RunCommand(ctx, bson.D{{Key: "collMod", Value: "auth_oauth_audit"}, {Key: "validator", Value: bson.M{"$expr": false}}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.repo.db.RunCommand(cleanupContext, bson.D{{Key: "collMod", Value: "auth_oauth_audit"}, {Key: "validator", Value: bson.M{}}}).Err(); err != nil {
			t.Error("restore fixture audit validator", err)
		}
	})
	if _, err := f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, []string{"openid", "email"}, true); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("audit failure not surfaced", err)
	}
	for _, collection := range []string{"auth_oauth_codes", "auth_oauth_grants", "auth_oauth_audit"} {
		if count, err := f.repo.db.Collection(collection).CountDocuments(ctx, bson.M{}); err != nil || count != 0 {
			t.Fatalf("partial commit in %s: %d %v", collection, count, err)
		}
	}
	var interaction oauthDocument[d.Interaction]
	if err := f.repo.db.Collection("auth_oauth_interactions").FindOne(ctx, bson.M{"_id": view.InteractionID}).Decode(&interaction); err != nil || interaction.Data.Status != "PENDING" {
		t.Fatal("interaction committed despite failed audit", err)
	}
	if err := f.repo.db.RunCommand(ctx, bson.D{{Key: "collMod", Value: "auth_oauth_audit"}, {Key: "validator", Value: bson.M{}}}).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Confirm(ctx, view.InteractionID, view.CSRF, view.PresentationID, f.session, []string{"openid", "email"}, true); err != nil {
		t.Fatal("rollback consumed valid presentation", err)
	}
}

func TestOAuthMongoConsentSilentReuseDoesNotFabricateDisplay(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	f.code(t, []string{"openid", "email"}, "public-client")
	next := append([]d.Scope(nil), f.seed...)
	next[1].Description += " corrected"
	if err := updateOAuthFixtureCatalog(t, f.repo, next); err != nil {
		t.Fatal(err)
	}
	state, _ := f.crypto.Random()
	nonce, _ := f.crypto.Random()
	view, err := f.service.Begin(ctx, d.AuthorizationRequest{ClientID: "public-client", RedirectURI: f.app.runtime.Redirects[0], State: state, Nonce: nonce, Challenge: f.challenge, ChallengeMethod: "S256", Channel: "TEST", Major: 1, Prompt: "none", Scopes: []string{"openid", "email"}}, f.session)
	if err != nil || view.Redirect == "" {
		t.Fatal("same-scope historical consent did not allow prompt=none", err)
	}
	var audit oauthDocument[d.Audit]
	if err = f.repo.db.Collection("auth_oauth_audit").FindOne(ctx, bson.M{"data.consentsource": "PRIOR_GRANT_REUSE"}).Decode(&audit); err != nil {
		t.Fatal("reuse source missing from audit", err)
	}
	if !validOAuthConsentAudit(audit.Data) || audit.Data.ReusedGrantRevision != 1 || audit.Data.Presentation != nil {
		t.Fatalf("silent reuse synthesized historical display: %+v", audit.Data)
	}
	if count, err := f.repo.db.Collection("auth_oauth_audit").CountDocuments(ctx, bson.M{"data.consentsource": "EXPLICIT"}); err != nil || count != 1 {
		t.Fatal("silent reuse altered explicit history", count, err)
	}
}
