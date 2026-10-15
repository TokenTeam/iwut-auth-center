package usecase

import (
	"context"
	"errors"
	"math"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

const applicationUserStorageAudience = "iwut-auth-center"

var storageKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateStorageKeys(keys []string) error {
	if len(keys) == 0 || len(keys) > 64 {
		return d.ErrRequest
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if !storageKeyPattern.MatchString(key) {
			return d.ErrRequest
		}
		if _, ok := seen[key]; ok {
			return d.ErrRequest
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (s *Service) storageAccess(ctx context.Context, raw, scope string, fn func(port.Tx, d.Family) error) error {
	return s.transaction(ctx, func(tx port.Tx) error {
		a, f, _, _, scopes, _, err := s.access(ctx, tx, raw)
		if err != nil {
			return err
		}
		if !d.Contains(a.Audiences, applicationUserStorageAudience) || !d.Contains(scopes, scope) {
			return d.ErrInsufficient
		}
		if err = fn(tx, f); err != nil {
			return err
		}
		return nil
	})
}

func (s *Service) BatchGetApplicationUserStorage(ctx context.Context, raw string, keys []string) (d.StorageSnapshot, error) {
	var out d.StorageSnapshot
	if err := validateStorageKeys(keys); err != nil {
		return out, err
	}
	err := s.storageAccess(ctx, raw, "storage.read", func(tx port.Tx, family d.Family) error {
		out.ClientID = family.ClientID
		namespace, err := tx.ApplicationUserStorage(family.AuthID, family.ApplicationID, family.Channel)
		if errors.Is(err, d.ErrNotFound) {
			out.MissingKeys = append([]string(nil), keys...)
			sort.Strings(out.MissingKeys)
			return nil
		}
		if err != nil {
			return err
		}
		if err = validateStoredNamespace(namespace, family); err != nil {
			return err
		}
		values := make(map[string]string, len(namespace.Entries))
		for _, entry := range namespace.Entries {
			values[entry.Key] = entry.Value
		}
		for _, key := range keys {
			if value, ok := values[key]; ok {
				out.Entries = append(out.Entries, d.StorageEntry{Key: key, Value: value})
			} else {
				out.MissingKeys = append(out.MissingKeys, key)
			}
		}
		sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Key < out.Entries[j].Key })
		sort.Strings(out.MissingKeys)
		out.Revision, out.UpdatedAt = namespace.Revision, namespace.UpdatedAt
		return nil
	})
	if err != nil {
		return d.StorageSnapshot{}, err
	}
	return out, nil
}

func (s *Service) MutateApplicationUserStorage(ctx context.Context, raw string, expectedRevision int64, mutations []d.StorageMutation) (d.StorageMutationResult, error) {
	var out d.StorageMutationResult
	if expectedRevision < 0 || len(mutations) == 0 || len(mutations) > 64 {
		return out, d.ErrRequest
	}
	keys := make([]string, len(mutations))
	for i, mutation := range mutations {
		keys[i] = mutation.Key
		if mutation.Action != "PUT" && mutation.Action != "DELETE" || mutation.Action == "DELETE" && mutation.Value != "" || mutation.Action == "PUT" && (!utf8.ValidString(mutation.Value) || len([]byte(mutation.Value)) > 8*1024) {
			return out, d.ErrRequest
		}
	}
	if err := validateStorageKeys(keys); err != nil {
		return out, err
	}
	err := s.storageAccess(ctx, raw, "storage.write", func(tx port.Tx, family d.Family) error {
		out.ClientID = family.ClientID
		namespace, err := tx.ApplicationUserStorage(family.AuthID, family.ApplicationID, family.Channel)
		if errors.Is(err, d.ErrNotFound) {
			namespace = d.StorageNamespace{AuthID: family.AuthID, ApplicationID: family.ApplicationID, Channel: family.Channel}
		} else if err != nil {
			return err
		} else if err = validateStoredNamespace(namespace, family); err != nil {
			return err
		}
		if namespace.Revision != expectedRevision {
			return d.StorageConflict{MinimumRevision: namespace.Revision}
		}
		values := make(map[string]string, len(namespace.Entries))
		for _, entry := range namespace.Entries {
			values[entry.Key] = entry.Value
		}
		changed := false
		for _, mutation := range mutations {
			switch mutation.Action {
			case "PUT":
				if old, ok := values[mutation.Key]; !ok || old != mutation.Value {
					values[mutation.Key] = mutation.Value
					changed = true
				}
			case "DELETE":
				if _, ok := values[mutation.Key]; ok {
					delete(values, mutation.Key)
					changed = true
				}
			}
		}
		if !changed {
			out = d.StorageMutationResult{ClientID: family.ClientID, Revision: namespace.Revision, UpdatedAt: namespace.UpdatedAt}
			return nil
		}
		if namespace.Revision == math.MaxInt64 {
			return d.ErrStorageConflict
		}
		if len(values) > 128 {
			return d.ErrStorageLimit
		}
		entries := make([]d.StorageEntry, 0, len(values))
		total := 0
		for key, value := range values {
			total += len(key) + len([]byte(value))
			entries = append(entries, d.StorageEntry{Key: key, Value: value})
		}
		if total > 64*1024 {
			return d.ErrStorageLimit
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
		namespace.Entries = entries
		namespace.Revision++
		namespace.UpdatedAt = s.now().UTC().Truncate(time.Millisecond)
		if err = tx.SaveApplicationUserStorage(expectedRevision, namespace); err != nil {
			if errors.Is(err, d.ErrStorageConflict) {
				return d.StorageConflict{MinimumRevision: expectedRevision + 1}
			}
			return err
		}
		out = d.StorageMutationResult{ClientID: family.ClientID, Revision: namespace.Revision, UpdatedAt: namespace.UpdatedAt, Changed: true}
		return nil
	})
	if err != nil {
		return d.StorageMutationResult{}, err
	}
	return out, nil
}

func validateStoredNamespace(namespace d.StorageNamespace, family d.Family) error {
	if namespace.AuthID != family.AuthID || namespace.ApplicationID != family.ApplicationID || namespace.Channel != family.Channel || namespace.Revision <= 0 || namespace.UpdatedAt.IsZero() || len(namespace.Entries) > 128 {
		return d.ErrUnavailable
	}
	total := 0
	previous := ""
	for i, entry := range namespace.Entries {
		if !storageKeyPattern.MatchString(entry.Key) || !utf8.ValidString(entry.Value) || len([]byte(entry.Value)) > 8*1024 || i > 0 && entry.Key <= previous {
			return d.ErrUnavailable
		}
		previous = entry.Key
		total += len(entry.Key) + len([]byte(entry.Value))
	}
	if total > 64*1024 {
		return d.ErrUnavailable
	}
	return nil
}
