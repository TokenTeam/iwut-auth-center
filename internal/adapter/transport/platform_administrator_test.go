package transport

import (
	"encoding/json"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/platform_administrator"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	d "iwut-auth-center/internal/administrator/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdministratorErrorsKeepGRPCCodeAndHTTPConflict(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code codes.Code
		http int
	}{{d.ErrInvalid, codes.InvalidArgument, 400}, {d.ErrForbidden, codes.PermissionDenied, 403}, {d.ErrSubject, codes.NotFound, 404}, {d.ErrConflict, codes.Aborted, 409}, {&d.Blocked{Blocker: "EMAIL_REQUIRED"}, codes.FailedPrecondition, 409}, {d.ErrLast, codes.FailedPrecondition, 409}, {d.ErrExhausted, codes.FailedPrecondition, 409}, {d.ErrRate, codes.ResourceExhausted, 429}, {errors.New("storage detail"), codes.Unavailable, 503}} {
		err := platformAdministratorError(tc.err)
		if status.Code(err) != tc.code {
			t.Fatal(err, tc.code)
		}
		rr := httptest.NewRecorder()
		authHTTPErrorEncoder(rr, httptest.NewRequest("POST", "/v1/platform-administrators:manage", nil), err)
		if rr.Code != tc.http || strings.Contains(rr.Body.String(), "storage detail") {
			t.Fatal(rr.Code, rr.Body.String())
		}
		if errors.Is(tc.err, d.ErrGrantBlocked) {
			details := status.Convert(err).Details()
			info, ok := details[0].(*errdetails.ErrorInfo)
			if !ok || info.Metadata["blocker"] != "EMAIL_REQUIRED" {
				t.Fatal(details)
			}
			var response map[string]any
			if json.Unmarshal(rr.Body.Bytes(), &response) != nil || response["metadata"].(map[string]any)["blocker"] != "EMAIL_REQUIRED" {
				t.Fatal(response)
			}
		}
	}
}
func TestAdministratorStrictDecodeCapsConfiguredLargeBody(t *testing.T) {
	decoder := authHTTPDecoder(1024 * 1024)
	for _, body := range []string{`{"pageSize":1,"pageSize":2}`, `{"unknown":1}`, strings.Repeat(" ", 16385) + `{}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/platform-administrators:list", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if e := decoder(r, &pb.ListPlatformAdministratorsRequest{}); e == nil {
			t.Fatal("accepted", len(body))
		}
	}
}
func TestAdministratorMethodAllowlistIsExact(t *testing.T) {
	for _, method := range []string{pb.PlatformAdministratorService_ManagePlatformAdministrator_FullMethodName, pb.PlatformAdministratorService_GetPlatformAdministrator_FullMethodName, pb.PlatformAdministratorService_ListPlatformAdministrators_FullMethodName} {
		if !isPlatformAdministratorOperation(method) || isPlatformAdministratorOperation(method+"Unknown") {
			t.Fatal(method)
		}
	}
}
