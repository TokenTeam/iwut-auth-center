package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
)

type AssociationKey struct {
	Version         string
	Encrypt, Lookup []byte
}
type Association struct {
	Current  AssociationKey
	Previous *AssociationKey
}

// LoadAssociation requires explicit key material and never includes values in errors.
func LoadAssociation(lookup LookupEnv) (Association, error) {
	if lookup == nil {
		return Association{}, ErrInvalidConfiguration
	}
	read := func(prefix string) (AssociationKey, error) {
		v, _ := lookup(prefix + "KEY_VERSION")
		enc, _ := lookup(prefix + "ENCRYPT_KEY")
		look, _ := lookup(prefix + "LOOKUP_KEY")
		e, err1 := base64.StdEncoding.Strict().DecodeString(enc)
		l, err2 := base64.StdEncoding.Strict().DecodeString(look)
		if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(v) || err1 != nil || err2 != nil || len(e) != 32 || len(l) != 32 || base64.StdEncoding.EncodeToString(e) != enc || base64.StdEncoding.EncodeToString(l) != look || bytes.Equal(e, l) {
			return AssociationKey{}, fmt.Errorf("%w: invalid association key group", ErrInvalidConfiguration)
		}
		return AssociationKey{v, e, l}, nil
	}
	c, err := read("AUTH_ASSOC_")
	if err != nil {
		return Association{}, err
	}
	a := Association{Current: c}
	present := false
	for _, s := range []string{"KEY_VERSION", "ENCRYPT_KEY", "LOOKUP_KEY"} {
		if _, ok := lookup("AUTH_ASSOC_PREVIOUS_" + s); ok {
			present = true
		}
	}
	if present {
		p, err := read("AUTH_ASSOC_PREVIOUS_")
		if err != nil {
			return Association{}, err
		}
		if p.Version == c.Version || bytes.Equal(p.Encrypt, c.Encrypt) || bytes.Equal(p.Lookup, c.Lookup) || bytes.Equal(p.Encrypt, c.Lookup) || bytes.Equal(p.Lookup, c.Encrypt) {
			return Association{}, fmt.Errorf("%w: association keys must be independent", ErrInvalidConfiguration)
		}
		a.Previous = &p
	}
	return a, nil
}
