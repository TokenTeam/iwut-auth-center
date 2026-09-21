package domain

import (
	"errors"
	"sort"
	"time"
)

var ErrInvalidScopeCatalogSnapshot = errors.New("invalid scope catalog snapshot")

type ScopeDefinition struct {
	name        string
	requestable bool
}

func NewScopeDefinition(name string, requestable bool) (ScopeDefinition, error) {
	if name == "" {
		return ScopeDefinition{}, ErrInvalidScopeCatalogSnapshot
	}
	return ScopeDefinition{name: name, requestable: requestable}, nil
}

func (definition ScopeDefinition) Name() string {
	return definition.name
}

func (definition ScopeDefinition) Requestable() bool {
	return definition.requestable
}

type Snapshot struct {
	revision    int64
	generatedAt time.Time
	scopes      []ScopeDefinition
}

func NewSnapshot(revision int64, generatedAt time.Time, scopes []ScopeDefinition) (Snapshot, error) {
	if revision <= 0 || generatedAt.IsZero() {
		return Snapshot{}, ErrInvalidScopeCatalogSnapshot
	}

	copied := append([]ScopeDefinition(nil), scopes...)
	seen := make(map[string]struct{}, len(copied))
	for _, definition := range copied {
		if definition.name == "" {
			return Snapshot{}, ErrInvalidScopeCatalogSnapshot
		}
		if _, exists := seen[definition.name]; exists {
			return Snapshot{}, ErrInvalidScopeCatalogSnapshot
		}
		seen[definition.name] = struct{}{}
	}
	sort.Slice(copied, func(left, right int) bool {
		return copied[left].name < copied[right].name
	})

	return Snapshot{
		revision:    revision,
		generatedAt: generatedAt.UTC(),
		scopes:      copied,
	}, nil
}

func (snapshot Snapshot) Revision() int64 {
	return snapshot.revision
}

func (snapshot Snapshot) GeneratedAt() time.Time {
	return snapshot.generatedAt
}

func (snapshot Snapshot) Scopes() []ScopeDefinition {
	return append([]ScopeDefinition(nil), snapshot.scopes...)
}
