package transport

import (
	identityv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	"testing"
)

func TestIdentityIssuanceAcceptedFullMethod(t *testing.T) {
	// Pin the accepted cross-service contract independently of generated callers.
	const accepted = "/auth_center.v1.identity.UserIdentityService/IssueUserIdentityFromSession"
	if identityv1.UserIdentityService_IssueUserIdentityFromSession_FullMethodName != accepted {
		t.Fatal("issuance RPC drifted from auth-session-identity-issuance-v1")
	}
	if permission, protected := permissionForOperation(accepted); !protected || permission != PermissionIdentityIssue {
		t.Fatal("accepted method is not explicitly service protected")
	}
	for _, name := range []string{"/auth_center.v1.user_identity.UserIdentityService/IssueUserIdentityFromSession", accepted + "Other", "/auth_center.v1.identity.OtherService/IssueUserIdentityFromSession"} {
		if _, protected := permissionForOperation(name); protected {
			t.Fatal("unregistered method authorized", name)
		}
	}
}
