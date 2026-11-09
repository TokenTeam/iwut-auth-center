package domain

import (
	"errors"
	"slices"
	"testing"
)

func TestProjectOwnCompleteAllowlistedSet(t *testing.T) {
	for _, permissions := range [][]string{{}, {Search}, {Restore, Search, Suspend}, {Suspend}, {Restore}, {Suspend, "app.profile.review", Restore}, {"auth.platform-admin.manage", "auth.reviewer.manage", "auth.account.manage", "auth.developer.manage"}} {
		out, err := ProjectOwn("user", 9007199254740993, permissions)
		if err != nil || out.AuthID != "user" || out.Revision != 9007199254740993 || out.EffectivePermissions == nil {
			t.Fatal(out, err)
		}
		want := []string{}
		for _, permission := range Permissions() {
			if slices.Contains(permissions, permission) {
				want = append(want, permission)
			}
		}
		if !slices.Equal(out.EffectivePermissions, want) {
			t.Fatal(out, want)
		}
	}
}

func TestProjectOwnRejectsCorruptionBeforeProjection(t *testing.T) {
	for _, permissions := range [][]string{nil, {Suspend, Suspend}, {Suspend, ""}, {Suspend, "unpublished.\tbad"}, {"app.*"}, {"bad\xff"}} {
		if out, err := ProjectOwn("user", 1, permissions); !errors.Is(err, ErrUnavailable) || out.AuthID != "" {
			t.Fatal(out, err)
		}
	}
	for _, revision := range []int64{0, -1} {
		if _, err := ProjectOwn("user", revision, []string{}); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
}
