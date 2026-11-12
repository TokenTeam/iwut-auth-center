package domain

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestIndependentReviewPermissionProjection(t *testing.T) {
	now := time.Now()
	for _, permissions := range [][]string{{}, {"app.profile.review"}, {"app.version.review"}, {"app.profile.review", "app.version.review"}} {
		s := Snapshot{AccountRevision: 1, AuthID: "u", PermissionRevision: 1, SessionExpiresAt: now.Add(time.Hour), DeveloperStatus: "APPROVED", Permissions: append([]string{"unknown", "auth.reviewer.manage"}, permissions...)}
		app, err := Project(s, AppAudience, "jti", now, time.Minute)
		if err != nil || !reflect.DeepEqual(app.Permissions, permissions) || app.DeveloperStatus != "APPROVED" {
			t.Fatal(app, err)
		}
		auth, err := Project(s, AuthAudience, "jti", now, time.Minute)
		if err != nil || !reflect.DeepEqual(auth.Permissions, []string{"auth.reviewer.manage"}) || auth.DeveloperStatus != "" {
			t.Fatal(auth, err)
		}
	}
}

func TestApplicationOperationsPermissionsProjectOnlyToAppAudience(t *testing.T) {
	now := time.Now()
	snapshot := Snapshot{AccountRevision: 1, AuthID: "operator", PermissionRevision: 2, SessionExpiresAt: now.Add(time.Hour), Permissions: []string{"app.application.suspend", "app.application.restore", "auth.platform-admin.manage"}}
	app, err := Project(snapshot, AppAudience, "app-jti", now, time.Minute)
	if err != nil || !reflect.DeepEqual(app.Permissions, []string{"app.application.restore", "app.application.suspend"}) {
		t.Fatal(app, err)
	}
	auth, err := Project(snapshot, AuthAudience, "auth-jti", now, time.Minute)
	if err != nil || !reflect.DeepEqual(auth.Permissions, []string{"auth.platform-admin.manage"}) {
		t.Fatal(auth, err)
	}
}

func TestScriptPermissionProjectionIsExplicitAndAppOnly(t *testing.T) {
	now := time.Now()
	original := []string{"app.application.restore", "app.application.suspend", "app.profile.review", "app.version.review"}
	for _, grant := range []string{"", "app.script.review", "app.script.publish", "app.script.suspend", "app.script.restore"} {
		permissions := append(slices.Clone(original), "app.script.*", "app.script.unknown", "app.script.maintain", "auth.platform-admin.manage")
		want := slices.Clone(original)
		if grant != "" {
			permissions = append(permissions, grant)
			want = append(want, grant)
			slices.Sort(want)
		}
		snapshot := Snapshot{AccountRevision: 1, AuthID: "operator", PermissionRevision: 2, SessionExpiresAt: now.Add(time.Hour), DeveloperStatus: "APPROVED", Permissions: permissions}
		app, err := Project(snapshot, AppAudience, "app-jti", now, time.Minute)
		if err != nil || !slices.Equal(app.Permissions, want) {
			t.Fatal(app, err)
		}
		auth, err := Project(snapshot, AuthAudience, "auth-jti", now, time.Minute)
		if err != nil || !slices.Equal(auth.Permissions, []string{"auth.platform-admin.manage"}) {
			t.Fatal(auth, err)
		}
	}
}
