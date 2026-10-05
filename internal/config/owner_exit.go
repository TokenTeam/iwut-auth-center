package config

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

type OwnerExit struct {
	AppTarget                                 string `json:"appTarget"`
	AppServerName                             string `json:"appServerName"`
	AppCAFile                                 string `json:"appCaFile"`
	AppPlaintextLoopback                      bool   `json:"appPlaintextLoopback"`
	ServiceKeyID                              string `json:"serviceKeyId"`
	ServiceKeyFile                            string `json:"serviceKeyFile"`
	AppServiceID                              string `json:"appServiceId"`
	WithdrawalEnabled                         bool   `json:"-"`
	ReadPerMinute, WritePerMinute, MaxBuckets int    `json:"-"`
}

func loadOwnerExit(lookup LookupEnv, user *UserEndpoints, callers []ServiceCallerRegistration) (*OwnerExit, error) {
	enabled := false
	if raw, ok := lookup("AUTH_DEVELOPER_WITHDRAWAL_ENABLED"); ok {
		var e error
		enabled, e = strconv.ParseBool(raw)
		if e != nil {
			return nil, ErrInvalidConfiguration
		}
	}
	path, ok := lookup("AUTH_OWNER_EXIT_CONFIG_FILE")
	if !ok {
		if enabled {
			return nil, ErrInvalidConfiguration
		}
		return nil, nil
	}
	if strings.TrimSpace(path) == "" || user == nil {
		return nil, ErrInvalidConfiguration
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrInvalidConfiguration
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	c := OwnerExit{AppServiceID: "app-center", WithdrawalEnabled: enabled, ReadPerMinute: 60, WritePerMinute: 10, MaxBuckets: 4096}
	if dec.Decode(&c) != nil || dec.Decode(&struct{}{}) != io.EOF || c.AppTarget == "" || c.ServiceKeyID == "" || c.ServiceKeyFile == "" || c.AppServiceID == "" {
		return nil, ErrInvalidConfiguration
	}
	found := false
	for _, caller := range callers {
		if caller.ServiceID == c.AppServiceID && caller.Status == "ACTIVE" {
			for _, permission := range caller.Permissions {
				if permission == "auth.account-owner-exit.read" {
					found = true
				}
			}
		}
	}
	if !found {
		return nil, ErrInvalidConfiguration
	}
	for name, dst := range map[string]*int{"AUTH_DEVELOPER_WITHDRAWAL_READ_PER_MINUTE": &c.ReadPerMinute, "AUTH_DEVELOPER_WITHDRAWAL_WRITE_PER_MINUTE": &c.WritePerMinute, "AUTH_DEVELOPER_WITHDRAWAL_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(name); ok {
			v, e := strconv.Atoi(raw)
			if e != nil || v < 1 || v > 1000000 {
				return nil, ErrInvalidConfiguration
			}
			*dst = v
		}
	}
	return &c, nil
}
