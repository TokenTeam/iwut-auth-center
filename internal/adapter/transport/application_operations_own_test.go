package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_operations_permission"
	"google.golang.org/protobuf/encoding/protowire"

	"iwut-auth-center/internal/applicationoperations/domain"
	"iwut-auth-center/internal/applicationoperations/usecase"
)

type ownOperationsRepository struct {
	calls int
	err   error
}

func (r *ownOperationsRepository) Manage(context.Context, domain.Command) (domain.State, error) {
	panic("own read reached management")
}
func (r *ownOperationsRepository) Get(context.Context, string, string) (domain.State, error) {
	panic("own read reached target read")
}
func (r *ownOperationsRepository) GetOwn(_ context.Context, actor string) (domain.OwnState, error) {
	r.calls++
	if r.err != nil {
		return domain.OwnState{}, r.err
	}
	return domain.OwnState{AuthID: actor, Revision: 9007199254740993, EffectivePermissions: []string{}}, nil
}

type ownOperationsLimiter struct{}

func (ownOperationsLimiter) AllowBegin(string, time.Time) bool    { return true }
func (ownOperationsLimiter) AllowComplete(string, time.Time) bool { return true }

func TestOwnApplicationOperationsHTTPOrdinaryUSERAndStrictResource(t *testing.T) {
	key, verifier := userKey(t)
	repository := &ownOperationsRepository{}
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{
		Authentication: &AuthenticationService{}, Profile: &UserProfileServer{},
		ProfileIdentity: UserCapabilityIdentityMiddleware(verifier), MaxAuthenticationMessageBytes: 16384,
		ApplicationOperations: NewApplicationOperationsPermissionService(usecase.New(repository, ownOperationsLimiter{})),
	}}, nil)
	ordinary := signUser(t, key, userClaims("ordinary"))
	wrongAudience := userClaims("ordinary")
	wrongAudience["aud"] = "iwut-app-center"
	const ownPath = "/v1/users/me/application-operation-capabilities"
	for _, test := range []struct {
		path, body, token string
		want              int
	}{
		{ownPath, "", ordinary, 200}, {ownPath, "", "", 401},
		{ownPath, "", signUser(t, key, wrongAudience), 401},
		{ownPath + "?subjectAuthId=other", "", ordinary, 400},
		{ownPath + "?", "", ordinary, 400}, {ownPath, `{}`, ordinary, 400},
		{ownPath, " ", ordinary, 400},
		{"/v1/users/ordinary/application-operation-permissions", "", ordinary, 403},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, strings.NewReader(test.body))
		if test.token != "" {
			request.Header.Set("X-Iwut-Identity", test.token)
		}
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, request)
		if rr.Code != test.want {
			t.Fatal(test.path, rr.Code, rr.Body.String())
		}
		if strings.HasPrefix(test.path, ownPath) && rr.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("private read/error cache policy missing", rr.Header())
		}
		if test.want == 200 {
			var resource map[string]json.RawMessage
			if json.Unmarshal(rr.Body.Bytes(), &resource) != nil || len(resource) != 3 || string(resource["subjectAuthId"]) != `"ordinary"` || string(resource["permissionRevision"]) != `"9007199254740993"` || string(resource["effectivePermissions"]) != `[]` {
				t.Fatal("missing/extra fields or lost int64 precision", rr.Body.String())
			}
		}
	}
	if repository.calls != 1 {
		t.Fatal("rejected request reached own repository", repository.calls)
	}
	for _, failure := range []error{domain.ErrIdentity, domain.ErrUnavailable, domain.ErrRate} {
		repository.err = failure
		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, ownPath, nil)
		request.Header.Set("X-Iwut-Identity", ordinary)
		server.ServeHTTP(rr, request)
		if rr.Code == 200 || strings.Contains(rr.Body.String(), "effectivePermissions") {
			t.Fatal("failure became successful permission set", failure, rr.Code, rr.Body.String())
		}
	}
}

func TestOwnApplicationOperationsStrictEmptyWireAndExactMethod(t *testing.T) {
	request := &pb.GetOwnApplicationOperationsPermissionsRequest{}
	if err := applicationOperationsPermissionWire(nil, request); err != nil {
		t.Fatal(err)
	}
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)
	if err := NewProfileStrictCodec().Unmarshal(unknown, request); err != nil || len(request.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("unknown input silently discarded", err, request)
	}
	method := pb.ApplicationOperationsPermissionService_GetOwnApplicationOperationsPermissions_FullMethodName
	if !applicationOperationsPermissionMethod(method) || !ownApplicationOperationsPermissionMethod(method) || ownApplicationOperationsPermissionMethod(method+"Unknown") || ownApplicationOperationsPermissionMethod(pb.ApplicationOperationsPermissionService_GetApplicationOperationsPermissions_FullMethodName) {
		t.Fatal("own method whitelist is not exact")
	}
}
