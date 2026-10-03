// Package oauthclock consumes a short-lived observation produced by the host's
// trusted time monitor. Missing, stale or out-of-bound observations stop signing.
package oauthclock

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

type Observation struct {
	ObservedAt   time.Time `json:"observedAt"`
	OffsetMillis int64     `json:"offsetMillis"`
}

func Healthy(path string) bool {
	if path == "" {
		return false
	}
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1024))
	dec.DisallowUnknownFields()
	var o struct {
		ObservedAt   time.Time `json:"observedAt"`
		OffsetMillis *int64    `json:"offsetMillis"`
	}
	if dec.Decode(&o) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return false
	}
	age := time.Since(o.ObservedAt)
	return o.OffsetMillis != nil && age >= 0 && age <= 10*time.Second && *o.OffsetMillis >= -1000 && *o.OffsetMillis <= 1000
}
