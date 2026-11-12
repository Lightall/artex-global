package securityexperiment

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuditReflectedCanaryIsNotDiscovery(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner := r.Header.Get("Authorization") == "Bearer owner-fixture-token"
		if r.URL.Path == "/me" {
			if owner {
				w.Write([]byte(`{"id":"alice","tenant":"one"}`))
			} else {
				w.Write([]byte(`{"id":"bob","tenant":"two"}`))
			}
			return
		}
		if owner {
			w.Write([]byte(`{"id":"42","owner":"alice","private":"` + fixtureValue + `"}`))
			return
		}
		w.Write([]byte(`{"echo":"` + r.URL.Query().Get("search") + `"}`))
	}))
	defer target.Close()
	spec := fixtureSpec(target.URL)
	encoded := ""
	for _, b := range []byte(fixtureValue) {
		encoded += fmt.Sprintf("%%%02x", b)
	}
	for _, value := range []string{url.QueryEscape(fixtureValue), encoded} {
		candidate := spec
		candidate.ResourcePath += "?search=" + value
		got := fixtureRunner().Run(t.Context(), candidate)
		if got.Verdict != PreconditionFailed && got.Verdict != Inconclusive {
			t.Fatalf("reflected caller input was treated as discovery: %s", got.Verdict)
		}
	}
}

func TestAuditRedactedProofCannotBePublishedAsViolation(t *testing.T) {
	private := "owner-fixture-token-plus-private-canary"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner := strings.Contains(r.Header.Get("Authorization"), "owner-fixture-token")
		if r.URL.Path == "/me" {
			if owner {
				w.Write([]byte(`{"id":"alice","tenant":"one"}`))
			} else {
				w.Write([]byte(`{"id":"bob","tenant":"two"}`))
			}
			return
		}
		w.Write([]byte(`{"id":"42","owner":"alice","private":"` + private + `"}`))
	}))
	defer target.Close()
	spec := fixtureSpec(target.URL)
	spec.ProtectedValueSHA256 = digest([]byte(private))
	got := fixtureRunner().Run(t.Context(), spec)
	if got.Verdict != Inconclusive || len(got.Observations) != 10 {
		t.Fatalf("redaction-damaged proof must remain unknown after the real probes: %s (%d observations)", got.Verdict, len(got.Observations))
	}
}
