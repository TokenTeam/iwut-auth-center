// Package terminationledger stores irreversible termination facts independently
// of MongoDB. Deployment must back up this directory without rolling it back
// alongside a business database restore.
package terminationledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"iwut-auth-center/internal/accountclosure/domain"
	"iwut-auth-center/internal/accountclosure/port"
)

const maxRecordBytes = 4096

type Ledger struct{ directory string }

var _ port.TerminationLedger = (*Ledger)(nil)

type record struct {
	Version         int    `json:"version"`
	AuthID          string `json:"authId"`
	AccountRevision int64  `json:"accountRevision"`
	TerminatedAt    string `json:"terminatedAt"`
	OperationID     string `json:"operationId"`
}

// Open requires an existing directory: a missing mount must never be silently
// replaced by an empty directory and mistaken for a complete ledger on startup.
func Open(directory string) (*Ledger, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("termination ledger requires a clean absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errors.New("termination ledger directory must exist without symlinks")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("termination ledger directory must be private")
	}
	ledger := &Ledger{directory: directory}
	if _, err = ledger.Records(context.Background()); err != nil {
		return nil, err
	}
	return ledger, nil
}

func canonical(value domain.Termination) ([]byte, error) {
	id, err := uuid.Parse(value.OperationID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || id.String() != value.OperationID ||
		len(value.AuthID) == 0 || len(value.AuthID) > 200 || !utf8.ValidString(value.AuthID) ||
		value.AccountRevision < 2 || value.TerminatedAt.IsZero() || value.TerminatedAt.Year() < 1970 || value.TerminatedAt.Year() > 9999 {
		return nil, errors.New("invalid termination ledger record")
	}
	encoded, err := json.Marshal(record{1, value.AuthID, value.AccountRevision,
		value.TerminatedAt.UTC().Format(time.RFC3339Nano), value.OperationID})
	return append(encoded, '\n'), err
}

func (l *Ledger) read(path string) (domain.Termination, []byte, error) {
	var empty domain.Termination
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxRecordBytes {
		return empty, nil, errors.New("invalid termination ledger file")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, nil, err
	}
	defer f.Close()
	encoded, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil || len(encoded) > maxRecordBytes {
		return empty, nil, errors.New("cannot read termination ledger record")
	}
	var r record
	if err := json.Unmarshal(encoded, &r); err != nil {
		return empty, nil, errors.New("corrupt termination ledger JSON")
	}
	at, err := time.Parse(time.RFC3339Nano, r.TerminatedAt)
	if err != nil {
		return empty, nil, errors.New("invalid termination time")
	}
	value := domain.Termination{AuthID: r.AuthID, AccountRevision: r.AccountRevision, TerminatedAt: at, OperationID: r.OperationID}
	want, err := canonical(value)
	if err != nil || r.Version != 1 || !bytes.Equal(encoded, want) || filepath.Base(path) != r.OperationID+".json" {
		return empty, nil, errors.New("noncanonical termination ledger record")
	}
	return value, encoded, nil
}

func (l *Ledger) syncDirectory() error {
	dir, err := os.Open(l.directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (l *Ledger) Store(ctx context.Context, value domain.Termination) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := canonical(value)
	if err != nil {
		return err
	}
	reservations, err := l.Reservations(ctx, value.OperationID)
	if err != nil {
		return err
	}
	if reservations.AuthID != value.AuthID || reservations.Handle != nil && reservations.Handle.ClaimedAt.After(value.TerminatedAt) {
		return errors.New("termination namespace reservations mismatch")
	}
	path := filepath.Join(l.directory, value.OperationID+".json")
	return l.publish(ctx, path, encoded, func(path string) ([]byte, error) { _, encoded, err := l.read(path); return encoded, err })
}

func (l *Ledger) publish(ctx context.Context, path string, encoded []byte, read func(string) ([]byte, error)) error {
	tmp, err := os.CreateTemp(l.directory, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(encoded); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A hard link publishes the fully synced inode atomically without replacing
	// an earlier record. A crash can leave a .pending file, never partial JSON.
	if err = os.Link(tmp.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := read(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, encoded) {
			return errors.New("conflicting termination ledger record")
		}
		// The original call may have crashed before fsync of the directory.
		f, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		err = f.Sync()
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return l.syncDirectory()
}

func (l *Ledger) Records(ctx context.Context) ([]domain.Termination, error) {
	entries, err := os.ReadDir(l.directory)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Termination, 0, len(entries))
	seen := make(map[string]domain.Termination)
	keyOwners := make(map[string]string)
	handleOwners := make(map[string]string)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(entry.Name(), ".pending-") {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return nil, errors.New("invalid pending ledger file")
			}
			continue // Unacknowledged files are recovered from Mongo's durable outbox.
		}
		if strings.HasSuffix(entry.Name(), reservationsSuffix) {
			if _, _, err := l.readReservations(filepath.Join(l.directory, entry.Name())); err != nil {
				return nil, err
			}
			continue
		}
		value, _, err := l.read(filepath.Join(l.directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("termination ledger verification failed: %w", err)
		}
		reservations, err := l.Reservations(ctx, value.OperationID)
		if err != nil || reservations.AuthID != value.AuthID || reservations.Handle != nil && reservations.Handle.ClaimedAt.After(value.TerminatedAt) {
			return nil, errors.New("termination namespace reservations missing or inconsistent")
		}
		if previous, ok := seen[value.AuthID]; ok && previous.OperationID != value.OperationID {
			return nil, errors.New("multiple terminal operations for one account")
		}
		for _, fingerprint := range reservations.Fingerprints {
			key := string(fingerprint)
			if previous, ok := keyOwners[key]; ok && previous != value.AuthID {
				return nil, errors.New("conflicting permanent credential occupancy")
			}
			keyOwners[key] = value.AuthID
		}
		if reservations.Handle != nil {
			handle := reservations.Handle.DeveloperHandle
			if previous, ok := handleOwners[handle]; ok && previous != value.AuthID {
				return nil, errors.New("conflicting permanent handle occupancy")
			}
			handleOwners[handle] = value.AuthID
		}
		seen[value.AuthID] = value
		result = append(result, value)
	}
	return result, nil
}
