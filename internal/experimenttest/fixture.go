// Package experimenttest provides a local, deterministic target for engineering tests.
package experimenttest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/securityexperiment"
)

const Canary = "owned-fixture-private-value-87ce9812"

type Target struct {
	Server      *httptest.Server
	Calls       atomic.Int32
	Fixed       atomic.Bool
	Expired     atomic.Bool
	BeforeProbe func()
}

func New(t *testing.T) (*Target, securityexperiment.Spec) {
	t.Helper()
	t.Setenv("ARTEX_EXPERIMENT_FIXTURE_OWNER", "Bearer fixture-owner-123456")
	t.Setenv("ARTEX_EXPERIMENT_FIXTURE_OTHER", "Bearer fixture-other-789012")
	target := &Target{}
	target.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target.Calls.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "read only", 405)
			return
		}
		owner := r.Header.Get("Authorization") == "Bearer fixture-owner-123456"
		other := r.Header.Get("Authorization") == "Bearer fixture-other-789012"
		if !owner && (!other || target.Expired.Load()) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/me" {
			if owner {
				fmt.Fprint(w, `{"principal":"owner","tenant":"one"}`)
			} else {
				fmt.Fprint(w, `{"principal":"other","tenant":"two"}`)
			}
			return
		}
		if r.URL.Path != "/objects/owned" {
			http.NotFound(w, r)
			return
		}
		if !owner && target.BeforeProbe != nil {
			target.BeforeProbe()
		}
		if !owner && target.Fixed.Load() {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"denied"}`)
			return
		}
		fmt.Fprintf(w, `{"object":"owned","owner":"owner","private":%q}`, Canary)
	}))
	t.Cleanup(target.Server.Close)
	hash := sha256.Sum256([]byte(Canary))
	return target, securityexperiment.Spec{
		Name: "owner/other isolation", PolicySource: "engineering fixture policy: a different tenant cannot read the owner's private canary", Origin: target.Server.URL,
		IdentityPath: "/me", PrincipalPointer: "/principal", TenantPointer: "/tenant", ResourcePath: "/objects/owned", ObjectID: "owned", ObjectPointer: "/object", OwnerPointer: "/owner", ProtectedPointer: "/private", ProtectedValueSHA256: hex.EncodeToString(hash[:]),
		Owner: securityexperiment.Actor{PrincipalID: "owner", TenantID: "one", Header: "Authorization", CredentialEnv: "ARTEX_EXPERIMENT_FIXTURE_OWNER"},
		Other: securityexperiment.Actor{PrincipalID: "other", TenantID: "two", Header: "Authorization", CredentialEnv: "ARTEX_EXPERIMENT_FIXTURE_OTHER"},
	}
}
