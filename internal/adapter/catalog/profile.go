package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/profile/domain"
)

type ProfileCatalog struct{ data []byte }

func NewProfileCatalog(c config.ProfileConfig) (*ProfileCatalog, error) {
	p := &ProfileCatalog{data: append([]byte{}, c.JSON...)}
	if _, e := p.Snapshot(context.Background()); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *ProfileCatalog) Snapshot(context.Context) ([]domain.Definition, error) {
	var envelope struct {
		Definitions *[]domain.Definition `json:"definitions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(p.data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Definitions == nil {
		return nil, domain.ErrCatalog
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, domain.ErrCatalog
	}
	defs := *envelope.Definitions
	if domain.ValidateDefinitions(defs) != nil {
		return nil, domain.ErrCatalog
	}
	return defs, nil
}
