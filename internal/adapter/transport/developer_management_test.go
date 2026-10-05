package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_management"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	d "iwut-auth-center/internal/developer/domain"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeveloperManagementErrorMappingAndExactOperations(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code codes.Code
		http int
	}{{d.ErrManagementIdentity, codes.Unauthenticated, 401}, {d.ErrManagementForbidden, codes.PermissionDenied, 403}, {d.ErrManagementSubject, codes.NotFound, 404}, {d.ErrManagementConflict, codes.Aborted, 409}, {d.ErrRestoreBlocked, codes.FailedPrecondition, 409}, {d.ErrDeveloperRevisionExhausted, codes.FailedPrecondition, 409}, {d.ErrManagementUnavailable, codes.Unavailable, 503}, {d.ErrManagementRate, codes.ResourceExhausted, 429}} {
		e := developerManagementError(tc.err)
		if status.Code(e) != tc.code {
			t.Fatal(e)
		}
		w := httptest.NewRecorder()
		authHTTPErrorEncoder(w, httptest.NewRequest("POST", "/v1/developers:manage-status", nil), e)
		if w.Code != tc.http {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, op := range []string{pb.DeveloperManagementService_ManageDeveloperStatus_FullMethodName, pb.DeveloperManagementService_GetManagedDeveloperStatus_FullMethodName} {
		if !isDeveloperManagementOperation(op) || isDeveloperManagementOperation(op+"Unknown") {
			t.Fatal(op)
		}
	}
}
func TestDeveloperManagementDecodeRemainsBounded(t *testing.T) {
	for _, body := range []string{`{"subjectAuthId":"x","unknown":true}`, `{"subjectAuthId":"x","subjectAuthId":"y"}`, strings.Repeat(" ", 16385) + `{}`} {
		r := httptest.NewRequest("POST", "/v1/developers:get-managed-status", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if e := authHTTPDecoder(1024*1024)(r, &pb.GetManagedDeveloperStatusRequest{}); e == nil {
			t.Fatal("accepted invalid body")
		}
	}
}
