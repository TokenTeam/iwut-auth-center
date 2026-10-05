package domain

import (
	"reflect"
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
