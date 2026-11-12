package securityexperiment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureValue = "private-owned-fixture-8b417c"

func fixtureSpec(origin string) Spec {
	return Spec{Name: "attachment isolation", PolicySource: "fixture policy: only owner may read the protected field", Origin: origin,
		IdentityPath: "/me", PrincipalPointer: "/id", TenantPointer: "/tenant", ResourcePath: "/objects/42",
		ObjectID: "42", ObjectPointer: "/id", OwnerPointer: "/owner", ProtectedPointer: "/private", ProtectedValueSHA256: digest([]byte(fixtureValue)),
		Owner: Actor{PrincipalID: "alice", TenantID: "one", Header: "Authorization", CredentialEnv: "FIXTURE_OWNER"},
		Other: Actor{PrincipalID: "bob", TenantID: "two", Header: "Authorization", CredentialEnv: "FIXTURE_OTHER"}}
}

func fixtureRunner() Runner {
	return Runner{LookupEnv: func(key string) (string, bool) {
		return map[string]string{"FIXTURE_OWNER": "Bearer owner-fixture-token", "FIXTURE_OTHER": "Bearer other-fixture-token"}[key], true
	}}
}

func TestIdentityIsolationOutcomes(t *testing.T) {
	for _, mode := range []string{"vulnerable", "fixed", "hidden", "expired", "wrong_principal", "wrong_tenant", "no_baseline", "wrong_object", "wrong_owner", "short_marker", "ambiguous", "server_error", "redirect", "truncated", "invalid_json", "session_expires", "changing_state", "flaky", "denial_leaks", "truncated_probe", "denial_embedded_leak", "opaque_denial"} {
		t.Run(mode, func(t *testing.T) {
			var calls, probes, baselines, otherIdentities atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.Method != http.MethodGet {
					t.Errorf("non-GET: %s", req.Method)
				}
				isOwner := req.Header.Get("Authorization") == "Bearer owner-fixture-token"
				w.Header().Set("Content-Type", "application/json")
				if req.URL.Path == "/me" {
					if isOwner {
						w.Write([]byte(`{"id":"alice","tenant":"one"}`))
						return
					}
					n := otherIdentities.Add(1)
					switch mode {
					case "expired":
						w.WriteHeader(401)
						return
					case "wrong_principal":
						w.Write([]byte(`{"id":"charlie","tenant":"two"}`))
						return
					case "wrong_tenant":
						w.Write([]byte(`{"id":"bob","tenant":"one"}`))
						return
					case "session_expires":
						if n >= 2 {
							w.WriteHeader(401)
							return
						}
					}
					w.Write([]byte(`{"id":"bob","tenant":"two"}`))
					return
				}
				if isOwner {
					n := baselines.Add(1)
					switch mode {
					case "no_baseline":
						w.WriteHeader(403)
						return
					case "wrong_object":
						w.Write([]byte(`{"id":"99","owner":"alice","private":"` + fixtureValue + `"}`))
						return
					case "wrong_owner":
						w.Write([]byte(`{"id":"42","owner":"bob","private":"` + fixtureValue + `"}`))
						return
					case "short_marker":
						w.Write([]byte(`{"id":"42","owner":"alice","private":"ok"}`))
						return
					case "truncated":
						w.Write([]byte(strings.Repeat("x", MaxBodyBytes+1)))
						return
					case "invalid_json":
						w.Write([]byte(`{"id":"42"} trailing`))
						return
					case "changing_state":
						if n == 2 {
							w.Write([]byte(`{"id":"42","owner":"alice","private":"changed-fixture-value"}`))
							return
						}
					}
				} else {
					n := probes.Add(1)
					switch mode {
					case "fixed":
						w.WriteHeader(403)
						w.Write([]byte(`{"error":"denied"}`))
						return
					case "hidden":
						w.WriteHeader(404)
						w.Write([]byte(`{}`))
						return
					case "ambiguous":
						w.Write([]byte(`{"data":[]}`))
						return
					case "server_error":
						w.WriteHeader(500)
						return
					case "redirect":
						w.Header().Set("Location", "/elsewhere")
						w.WriteHeader(302)
						return
					case "flaky":
						if n == 2 {
							w.WriteHeader(403)
							return
						}
					case "denial_leaks":
						w.WriteHeader(403)
						w.Write([]byte(`{"error":{"leak":"` + fixtureValue + `"}}`))
						return
					case "denial_embedded_leak":
						w.WriteHeader(403)
						w.Write([]byte(`{"error":"the private value was ` + fixtureValue + `"}`))
						return
					case "opaque_denial":
						w.WriteHeader(403)
						w.Write([]byte("opaque unexpected content " + fixtureValue))
						return
					case "truncated_probe":
						w.Write([]byte(strings.Repeat("x", MaxBodyBytes+1)))
						return
					}
				}
				w.Write([]byte(`{"id":"42","owner":"alice","private":"` + fixtureValue + `"}`))
			}))
			defer srv.Close()
			result := fixtureRunner().Run(t.Context(), fixtureSpec(srv.URL))
			want := Inconclusive
			switch mode {
			case "vulnerable", "denial_leaks", "denial_embedded_leak":
				want = ViolationObserved
			case "fixed", "hidden":
				want = NotReproduced
			case "expired", "wrong_principal", "wrong_tenant", "no_baseline", "wrong_object", "wrong_owner", "short_marker", "truncated", "invalid_json", "session_expires":
				want = PreconditionFailed
			}
			if result.Verdict != want {
				t.Fatalf("got %s want %s: %s", result.Verdict, want, result.Reason)
			}
			if calls.Load() > 10 {
				t.Fatalf("unbounded requests: %d", calls.Load())
			}
			if want == ViolationObserved || want == NotReproduced {
				if calls.Load() != 10 || probes.Load() != 2 {
					t.Fatalf("missing repetition: %d calls %d probes", calls.Load(), probes.Load())
				}
			}
			if want == ViolationObserved {
				if err := VerifyViolation(fixtureSpec(srv.URL), result); err != nil {
					t.Fatalf("persisted proof cannot be reverified: %v", err)
				}
				bad := result
				bad.Observations = append([]Observation(nil), result.Observations...)
				bad.Observations[3].Body = base64.StdEncoding.EncodeToString([]byte(`{"not":"the evidence"}`))
				if VerifyViolation(fixtureSpec(srv.URL), bad) == nil {
					t.Fatal("modified response body accepted")
				}
				bad.Observations[3] = result.Observations[3]
				bad.Observations[3].PrincipalID = "someone-else"
				if VerifyViolation(fixtureSpec(srv.URL), bad) == nil {
					t.Fatal("wrong identity binding accepted")
				}
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "fixture-token") {
				t.Fatal("credentials entered evidence")
			}
			for _, observation := range result.Observations {
				if observation.Status != 0 && observation.SHA256 == "" {
					t.Fatal("missing response hash")
				}
				body, err := base64.StdEncoding.DecodeString(observation.Body)
				if err != nil || strings.Contains(string(body), "fixture-token") {
					t.Fatal("invalid or credential-bearing evidence")
				}
			}
		})
	}
}

func TestCredentialRedactionPreservesEvidenceIntegrity(t *testing.T) {
	secret := "a-secret-with-\"quotes-and-unicode-密"
	body, _ := json.Marshal(map[string]any{"nested": []any{map[string]any{"credential": secret}}, "public": "unchanged"})
	clean, changed := redactBody(body, []string{secret})
	if !changed || containsScalar(clean, secret) || !containsScalar(clean, "unchanged") {
		t.Fatalf("JSON credential redaction failed: %s", clean)
	}
	unicodeEcho := []byte(`{"echo":"\u0074\u006f\u006b\u0065\u006e-private-123"}`)
	clean, changed = redactBody(unicodeEcho, []string{"token-private-123"})
	if !changed || containsScalar(clean, "token-private-123") {
		t.Fatal("Unicode-encoded credential persisted")
	}
	untouched := []byte("{ \"public\" : 123 }")
	clean, changed = redactBody(untouched, []string{secret})
	if changed || string(clean) != string(untouched) {
		t.Fatal("ordinary evidence bytes were changed")
	}
}

func TestRunnerRejectsInvalidConfigurationBeforeRequests(t *testing.T) {
	for _, mutate := range []func(*Spec){
		func(s *Spec) { s.PolicySource = "" },
		func(s *Spec) { s.ProtectedValueSHA256 = "" },
		func(s *Spec) { s.Origin = "file:///tmp/secret" },
		func(s *Spec) { s.Origin = "http://user:secret@localhost" },
		func(s *Spec) { s.ResourcePath = "//elsewhere.invalid/object" },
		func(s *Spec) { s.ResourcePath = "https://elsewhere.invalid/object" },
		func(s *Spec) { s.ResourcePath = "/\r\nX-Foo: bar" },
		func(s *Spec) { s.ResourcePath = "/\\elsewhere" },
		func(s *Spec) { s.Other.PrincipalID = s.Owner.PrincipalID },
		func(s *Spec) { s.Other.CredentialEnv = s.Owner.CredentialEnv },
		func(s *Spec) { s.Other.Header = "Host" },
		func(s *Spec) { s.ProtectedPointer = "/bad~pointer" },
		func(s *Spec) { s.TenantPointer = "" },
	} {
		spec := fixtureSpec("http://localhost")
		mutate(&spec)
		result := fixtureRunner().Run(t.Context(), spec)
		if result.Verdict != PreconditionFailed || len(result.Observations) != 0 {
			t.Fatalf("invalid spec executed: %+v", result)
		}
	}
}

func TestRedirectCannotForwardCredentials(t *testing.T) {
	var external atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { external.Add(1) }))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer target.Close()
	result := fixtureRunner().Run(t.Context(), fixtureSpec(target.URL))
	if external.Load() != 0 || result.Verdict != PreconditionFailed {
		t.Fatalf("redirect followed: %+v", result)
	}
}

func TestTimeoutCancellationMissingCredentialsAndRedaction(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	runner := fixtureRunner()
	runner.Timeout = 20 * time.Millisecond
	started := time.Now()
	if got := runner.Run(t.Context(), fixtureSpec(slow.URL)); got.Verdict != PreconditionFailed || time.Since(started) > time.Second {
		t.Fatalf("timeout failed: %+v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := runner.Run(ctx, fixtureSpec(slow.URL)); got.Verdict != PreconditionFailed {
		t.Fatalf("cancellation failed: %+v", got)
	}
	runner.LookupEnv = func(string) (string, bool) { return "", false }
	if got := runner.Run(t.Context(), fixtureSpec(slow.URL)); len(got.Observations) != 0 || got.Verdict != PreconditionFailed {
		t.Fatal("missing credentials sent a request")
	}
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"echo":"` + r.Header.Get("Authorization") + `"}`))
	}))
	defer echo.Close()
	got := fixtureRunner().Run(t.Context(), fixtureSpec(echo.URL))
	body, _ := base64.StdEncoding.DecodeString(got.Observations[0].Body)
	if strings.Contains(string(body), "owner-fixture-token") || !got.Observations[0].Redacted {
		t.Fatal("echoed credentials persisted")
	}
}
