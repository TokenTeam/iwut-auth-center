package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
	"time"
)

// ConsentPresentation records definitions prepared for one specific consent
// page, never user profile values. Only explicit confirmation copies it to audit.
type ConsentPresentation struct {
	ID, Digest  string
	Definitions []Scope
	PreparedAt  time.Time
}

// RequestedDefinitionsDigest is independent of catalog revision and ordering.
// Length-prefixed fields include ProfileValueType even though it is excluded
// from JSON. Thus unrelated catalog changes cannot invalidate a consent page.
func RequestedDefinitionsDigest(definitions []Scope) string {
	ordered := append([]Scope(nil), definitions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	h := sha256.New()
	writePresentationField(h, "iwut-consent-definitions-v1")
	for _, s := range ordered {
		for _, field := range []string{s.Name, s.Label, s.Description, s.Kind, s.Audience, s.ProfileField, s.ProfileValueType} {
			writePresentationField(h, field)
		}
		if s.Enabled {
			writePresentationField(h, "true")
		} else {
			writePresentationField(h, "false")
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writePresentationField(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	h.Write(length[:])
	h.Write([]byte(value))
}

func (p ConsentPresentation) Valid(requested []string) bool {
	if p.ID == "" || p.PreparedAt.IsZero() || len(p.Definitions) != len(requested) || !ValidScopes(requested) {
		return false
	}
	names := make([]string, 0, len(p.Definitions))
	for _, definition := range p.Definitions {
		if definition.Label == "" || definition.Description == "" || !definition.Enabled || !definition.ValidMetadata() {
			return false
		}
		names = append(names, definition.Name)
	}
	return ValidScopes(names) && Subset(requested, names) && p.Digest == RequestedDefinitionsDigest(p.Definitions)
}
