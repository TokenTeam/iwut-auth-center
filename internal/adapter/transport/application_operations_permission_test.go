package transport

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_operations_permission"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"iwut-auth-center/internal/applicationoperations/domain"
)

func TestApplicationOperationsPermissionErrors(t *testing.T) {
	for _, test := range []struct {
		err      error
		code     codes.Code
		httpCode int
	}{
		{domain.ErrIdentity, codes.Unauthenticated, 401},
		{domain.ErrInvalid, codes.InvalidArgument, 400},
		{domain.ErrForbidden, codes.PermissionDenied, 403},
		{domain.ErrSubject, codes.NotFound, 404},
		{domain.ErrConflict, codes.Aborted, 409},
		{&domain.Blocked{Blocker: "EMAIL_REQUIRED"}, codes.FailedPrecondition, 409},
		{domain.ErrExhausted, codes.FailedPrecondition, 409},
		{domain.ErrRate, codes.ResourceExhausted, 429},
		{errors.New("storage detail"), codes.Unavailable, 503},
	} {
		err := applicationOperationsPermissionError(test.err)
		if status.Code(err) != test.code {
			t.Fatal(test.err, err)
		}
		recorder := httptest.NewRecorder()
		authHTTPErrorEncoder(recorder, httptest.NewRequest(http.MethodPut, "/v1/users/user/application-operation-permissions/app.application.suspend", nil), err)
		if recorder.Code != test.httpCode || strings.Contains(recorder.Body.String(), "storage detail") {
			t.Fatal(test.err, recorder.Code, recorder.Body.String())
		}
		if errors.Is(test.err, domain.ErrGrantBlocked) {
			detail, ok := status.Convert(err).Details()[0].(*errdetails.ErrorInfo)
			if !ok || detail.Metadata["blocker"] != "EMAIL_REQUIRED" {
				t.Fatal(detail)
			}
			var response map[string]any
			if json.Unmarshal(recorder.Body.Bytes(), &response) != nil || response["metadata"].(map[string]any)["blocker"] != "EMAIL_REQUIRED" {
				t.Fatal(response)
			}
		}
	}
}

func TestApplicationOperationsPermissionStrictWireAndHTTP(t *testing.T) {
	duplicate := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "one")
	duplicate = protowire.AppendString(protowire.AppendTag(duplicate, 1, protowire.BytesType), "two")
	if applicationOperationsPermissionWire(duplicate, &pb.GetApplicationOperationsPermissionsRequest{}) == nil {
		t.Fatal("duplicate singular field accepted")
	}
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1)
	if applicationOperationsPermissionWire(unknown, &pb.ManageApplicationOperationsPermissionRequest{}) == nil {
		t.Fatal("unknown field accepted")
	}
	decoder := authHTTPDecoder(1024 * 1024)
	for _, body := range []string{`{"permission":"app.application.suspend","permission":"app.application.restore"}`, `{"unknown":1}`, strings.Repeat(" ", 16385) + `{}`} {
		request := httptest.NewRequest(http.MethodPut, "/v1/users/user/application-operation-permissions/app.application.suspend", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := decoder(request, &pb.ManageApplicationOperationsPermissionRequest{}); err == nil {
			t.Fatal("accepted", len(body))
		}
	}
	for _, method := range []string{pb.ApplicationOperationsPermissionService_ManageApplicationOperationsPermission_FullMethodName, pb.ApplicationOperationsPermissionService_GetApplicationOperationsPermissions_FullMethodName} {
		if !applicationOperationsPermissionMethod(method) || applicationOperationsPermissionMethod(method+"Unknown") {
			t.Fatal(method)
		}
	}
}
