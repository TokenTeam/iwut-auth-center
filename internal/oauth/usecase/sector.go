package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"net/url"
	"time"
)

func (s *Service) ensureSector(ctx context.Context, tx port.Tx, rt d.Runtime) error {
	sector, err := tx.Sector(rt.Client.ApplicationID)
	if missing(err) {
		sector = d.Sector{ID: s.crypto.ID(), ApplicationID: rt.Client.ApplicationID}
		sector.Hostname = sector.ID + "." + s.cfg.SectorSuffix
		if err = tx.SaveSector(sector); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	snap, err := s.app.Redirects(ctx, rt.Client.ApplicationID)
	if err != nil {
		return err
	}
	if snap.ApplicationID != rt.Client.ApplicationID || !d.Subset(rt.Redirects, snap.URIs) || !snapshotFresh(snap, s.now()) {
		return d.ErrUnavailable
	}
	for _, e := range snap.Entries {
		if e.Channel == rt.Client.Channel && e.Major == rt.Major && e.VersionID == rt.VersionID && e.PublicationRevision == rt.PublicationRevision {
			origins := []string{}
			for _, uri := range rt.Redirects {
				u, e := url.Parse(uri)
				if e != nil {
					return d.ErrUnavailable
				}
				origins = append(origins, u.Scheme+"://"+u.Host)
			}
			return tx.SaveRegistration(d.Registration{ClientID: rt.Client.ID, ApplicationID: rt.Client.ApplicationID, SectorID: sector.ID, SectorURI: "https://" + sector.Hostname + "/redirect-uris.json", Type: rt.Client.Type, Major: rt.Major, Origins: d.Union(origins)})
		}
	}
	return d.ErrConflict
}

func snapshotFresh(x d.RedirectSnapshot, now time.Time) bool {
	return !x.ObservedAt.After(now) && x.ValidUntil.After(now) && x.ValidUntil.Sub(x.ObservedAt) > 0 && x.ValidUntil.Sub(x.ObservedAt) <= 5*time.Second
}
func (s *Service) SectorRedirects(ctx context.Context, host string) ([]string, error) {
	var uris []string
	err := s.transaction(ctx, func(tx port.Tx) error {
		sector, err := tx.SectorByHost(host)
		if err != nil {
			return err
		}
		snap, err := s.app.Redirects(ctx, sector.ApplicationID)
		if err != nil {
			return err
		}
		if snap.ApplicationID != sector.ApplicationID || !snapshotFresh(snap, s.now()) {
			return d.ErrUnavailable
		}
		uris = snap.URIs
		return nil
	})
	if err != nil {
		return nil, err
	}
	if uris == nil {
		uris = []string{}
	}
	return uris, nil
}
