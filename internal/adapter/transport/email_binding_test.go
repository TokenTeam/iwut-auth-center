package transport

import (
	"encoding/json"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	d "iwut-auth-center/internal/emailbinding/domain"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmailStrictProtoWire(t *testing.T) {
	codec := NewProfileStrictCodec()
	field := func(n protowire.Number, b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
	}
	for _, wire := range [][]byte{append(field(3, nil), field(4, nil)...), append(field(1, []byte("x")), field(1, []byte("y"))...), field(5, nil), field(3, field(2, nil)), field(4, field(1, field(3, nil))), field(4, field(2, nil))} {
		message := &pb.BeginSetEmailRequest{}
		if e := codec.Unmarshal(wire, message); e != nil {
			t.Fatal("codec errors become grpc INTERNAL", e)
		}
		if status.Code(checkEmailMessage(message)) != codes.InvalidArgument {
			t.Fatal("ambiguous/unknown proto lost rejection marker")
		}
	}
	if e := codec.Unmarshal(field(3, protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 0)), &pb.BeginSetEmailRequest{}); e != nil {
		t.Fatalf("explicit revision zero rejected: %v", e)
	}
	oversized := &pb.BeginSetEmailRequest{}
	if e := codec.Unmarshal(field(1, make([]byte, 16*1024+1)), oversized); e != nil {
		t.Fatal(e)
	}
	if status.Code(checkEmailMessage(oversized)) != codes.ResourceExhausted {
		t.Fatal("oversize marker lost admission bound")
	}
}
func TestEmailErrorStatusMappings(t *testing.T) {
	for _, tc := range []struct {
		err  error
		grpc codes.Code
		http int
	}{{d.ErrInvalid, codes.InvalidArgument, 400}, {d.ErrVerification, codes.InvalidArgument, 400}, {d.ErrSession, codes.Unauthenticated, 401}, {d.ErrFlow, codes.FailedPrecondition, 409}, {d.ErrRevision, codes.Aborted, 409}, {d.ErrConflict, codes.AlreadyExists, 409}, {d.ErrOccupied, codes.AlreadyExists, 409}, {d.ErrRate, codes.ResourceExhausted, 429}, {d.ErrDelivery, codes.Unavailable, 503}, {d.ErrUnavailable, codes.Unavailable, 503}} {
		e := emailError(tc.err)
		if status.Code(e) != tc.grpc {
			t.Fatalf("%v grpc: %v", tc.err, status.Code(e))
		}
		w := httptest.NewRecorder()
		authHTTPErrorEncoder(w, httptest.NewRequest(http.MethodPost, "/v1/email-bindings", nil), e)
		if w.Code != tc.http {
			t.Fatalf("%v HTTP: %d", tc.err, w.Code)
		}
		var body struct{ Reason string }
		json.Unmarshal(w.Body.Bytes(), &body)
		if body.Reason != tc.err.Error() {
			t.Fatal("reason lost")
		}
		if tc.err == d.ErrRate && w.Header().Get("Retry-After") == "" {
			t.Fatal("retry metadata missing")
		}
	}
}
