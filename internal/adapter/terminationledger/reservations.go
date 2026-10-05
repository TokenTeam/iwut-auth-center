package terminationledger

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	d "iwut-auth-center/internal/accountclosure/domain"
	p "iwut-auth-center/internal/accountclosure/port"
	developer "iwut-auth-center/internal/developer/domain"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const reservationsSuffix = ".reservations.json"

// File sizes are bounded before parsing; this accommodates over a million
// historical credentials without accepting an unbounded allocation from disk.
const maxReservationsBytes = 64 << 20

type reservationsRecord struct {
	Version      int           `json:"version"`
	AuthID       string        `json:"authId"`
	OperationID  string        `json:"operationId"`
	Fingerprints []string      `json:"fingerprints"`
	Handle       *handleRecord `json:"handle"`
}
type handleRecord struct {
	DeveloperHandle string `json:"developerHandle"`
	ClaimedAt       string `json:"claimedAt"`
}

func validOperationID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.Version() == 4 && parsed.Variant() == uuid.RFC4122 && parsed.String() == id
}
func canonicalReservations(value d.NamespaceReservations) ([]byte, error) {
	if !validOperationID(value.OperationID) || value.AuthID == "" || len(value.AuthID) > 200 || !utf8.ValidString(value.AuthID) || strings.TrimSpace(value.AuthID) != value.AuthID {
		return nil, errors.New("invalid namespace reservation identity")
	}
	if len(value.Fingerprints) == 0 {
		return nil, errors.New("namespace reservations require at least one credential fingerprint")
	}
	r := reservationsRecord{Version: 1, AuthID: value.AuthID, OperationID: value.OperationID, Fingerprints: []string{}}
	// Sort by raw fingerprint bytes, independently of base64's alphabet order.
	fingerprints := make([][]byte, 0, len(value.Fingerprints))
	for _, f := range value.Fingerprints {
		if len(f) != 32 {
			return nil, errors.New("invalid namespace fingerprint")
		}
		fingerprints = append(fingerprints, append([]byte(nil), f...))
	}
	sort.Slice(fingerprints, func(i, j int) bool { return bytes.Compare(fingerprints[i], fingerprints[j]) < 0 })
	for i, f := range fingerprints {
		if i == 0 || !bytes.Equal(f, fingerprints[i-1]) {
			r.Fingerprints = append(r.Fingerprints, base64.RawURLEncoding.EncodeToString(f))
		}
	}
	if value.Handle != nil {
		h := value.Handle
		normalized, err := developer.NormalizeDeveloperHandle(h.DeveloperHandle)
		if err != nil || normalized != h.DeveloperHandle || h.ClaimedAt.IsZero() || h.ClaimedAt.Year() < 1970 || h.ClaimedAt.Year() > 9999 {
			return nil, errors.New("invalid namespace handle")
		}
		r.Handle = &handleRecord{h.DeveloperHandle, h.ClaimedAt.UTC().Format(time.RFC3339Nano)}
	}
	encoded, err := json.Marshal(r)
	if len(encoded)+1 > maxReservationsBytes {
		return nil, errors.New("namespace reservations exceed file limit")
	}
	return append(encoded, '\n'), err
}
func (l *Ledger) readReservations(path string) (d.NamespaceReservations, []byte, error) {
	var out d.NamespaceReservations
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil, p.ErrReservationsNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxReservationsBytes {
		return out, nil, errors.New("invalid namespace reservations file")
	}
	f, err := os.Open(path)
	if err != nil {
		return out, nil, err
	}
	defer f.Close()
	encoded, err := io.ReadAll(io.LimitReader(f, maxReservationsBytes+1))
	if err != nil || len(encoded) > maxReservationsBytes {
		return out, nil, errors.New("cannot read namespace reservations")
	}
	var r reservationsRecord
	if json.Unmarshal(encoded, &r) != nil {
		return out, nil, errors.New("corrupt namespace reservations JSON")
	}
	out = d.NamespaceReservations{AuthID: r.AuthID, OperationID: r.OperationID, Fingerprints: [][]byte{}}
	for _, encoded := range r.Fingerprints {
		f, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return out, nil, errors.New("invalid namespace fingerprint encoding")
		}
		out.Fingerprints = append(out.Fingerprints, f)
	}
	if r.Handle != nil {
		at, err := time.Parse(time.RFC3339Nano, r.Handle.ClaimedAt)
		if err != nil {
			return out, nil, err
		}
		out.Handle = &d.HandleReservation{DeveloperHandle: r.Handle.DeveloperHandle, ClaimedAt: at}
	}
	want, err := canonicalReservations(out)
	if err != nil || r.Version != 1 || !bytes.Equal(encoded, want) || filepath.Base(path) != r.OperationID+reservationsSuffix {
		return out, nil, errors.New("noncanonical namespace reservations")
	}
	return out, encoded, nil
}
func (l *Ledger) StoreReservations(ctx context.Context, value d.NamespaceReservations) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := canonicalReservations(value)
	if err != nil {
		return err
	}
	return l.publish(ctx, filepath.Join(l.directory, value.OperationID+reservationsSuffix), encoded, func(path string) ([]byte, error) { _, encoded, err := l.readReservations(path); return encoded, err })
}
func (l *Ledger) Reservations(ctx context.Context, id string) (d.NamespaceReservations, error) {
	if err := ctx.Err(); err != nil {
		return d.NamespaceReservations{}, err
	}
	if !validOperationID(id) {
		return d.NamespaceReservations{}, errors.New("invalid reservation operation id")
	}
	out, _, err := l.readReservations(filepath.Join(l.directory, id+reservationsSuffix))
	return out, err
}
