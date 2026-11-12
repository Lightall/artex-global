// Package securityexperiment executes bounded, operator-configured security tests.
// It does not invoke models or infer authorization policy from target responses.
package securityexperiment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	ViolationObserved  = "violation_observed"
	NotReproduced      = "not_reproduced"
	PreconditionFailed = "precondition_failed"
	Inconclusive       = "inconclusive"
	MaxBodyBytes       = 64 << 10
)

// Actor contains references to credentials, never their values. The environment
// variable supplies the complete Authorization or Cookie header at execution.
type Actor struct {
	PrincipalID   string `json:"principal_id"`
	TenantID      string `json:"tenant_id,omitempty"`
	Header        string `json:"header"`
	CredentialEnv string `json:"credential_env"`
}

// Spec is immutable operator input. PolicySource identifies the authority for
// denying the other actor access; a model-authored hypothesis is not that authority.
type Spec struct {
	Name                 string `json:"name"`
	PolicySource         string `json:"policy_source"`
	Origin               string `json:"origin"`
	IdentityPath         string `json:"identity_path"`
	PrincipalPointer     string `json:"principal_pointer"`
	TenantPointer        string `json:"tenant_pointer,omitempty"`
	ResourcePath         string `json:"resource_path"`
	ObjectID             string `json:"object_id"`
	ObjectPointer        string `json:"object_pointer"`
	OwnerPointer         string `json:"owner_pointer"`
	ProtectedPointer     string `json:"protected_pointer"`
	ProtectedValueSHA256 string `json:"protected_value_sha256"`
	Owner                Actor  `json:"owner"`
	Other                Actor  `json:"other"`
}

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

func (s Spec) Validate() error {
	if strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.PolicySource) == "" || s.ObjectID == "" {
		return errors.New("name, policy_source and object_id are required")
	}
	if b, err := hex.DecodeString(s.ProtectedValueSHA256); err != nil || len(b) != sha256.Size || strings.ToLower(s.ProtectedValueSHA256) != s.ProtectedValueSHA256 {
		return errors.New("protected_value_sha256 must identify an operator-known private scalar or canary")
	}
	u, err := url.Parse(s.Origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("origin must be one explicit HTTP(S) origin without credentials, path or query")
	}
	for _, p := range []string{s.IdentityPath, s.ResourcePath} {
		if _, err := requestURL(s.Origin, p); err != nil {
			return err
		}
	}
	for _, p := range []string{s.PrincipalPointer, s.ObjectPointer, s.OwnerPointer, s.ProtectedPointer} {
		if !validPointer(p) {
			return errors.New("explicit JSON pointers are required")
		}
	}
	if s.Owner.PrincipalID == "" || s.Other.PrincipalID == "" || s.Owner.PrincipalID == s.Other.PrincipalID {
		return errors.New("two distinct, explicit principals are required")
	}
	if s.TenantPointer != "" {
		if !validPointer(s.TenantPointer) || s.Owner.TenantID == "" || s.Other.TenantID == "" {
			return errors.New("tenant verification requires a pointer and both tenant IDs")
		}
	} else if s.Owner.TenantID != "" || s.Other.TenantID != "" {
		return errors.New("tenant IDs require tenant_pointer")
	}
	for _, a := range []Actor{s.Owner, s.Other} {
		if (a.Header != "Authorization" && a.Header != "Cookie") || !envName.MatchString(a.CredentialEnv) {
			return errors.New("each actor requires an Authorization/Cookie header and a credential environment reference")
		}
	}
	if s.Owner.CredentialEnv == s.Other.CredentialEnv {
		return errors.New("actors must use separate credential references")
	}
	return nil
}

func validPointer(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 256 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' {
			if i+1 == len(p) || (p[i+1] != '0' && p[i+1] != '1') {
				return false
			}
			i++
		}
	}
	return true
}

func requestURL(origin, path string) (string, error) {
	u, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(path, "\r\n\\") {
		return "", errors.New("request paths must be origin-relative and cannot redirect credentials to another origin")
	}
	return strings.TrimSuffix(origin, "/") + path, nil
}

func (s Spec) Fingerprint() string {
	b, _ := json.Marshal(s)
	return digest(b)
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Observation preserves the original response hash and a bounded body. Credential
// values echoed by a target are redacted before persistence; that fact is explicit.
type Observation struct {
	Stage        string    `json:"stage"`
	PrincipalID  string    `json:"principal_id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	URL          string    `json:"url"`
	Status       int       `json:"status"`
	Body         string    `json:"body_base64"`
	SHA256       string    `json:"sha256"`
	StoredSHA256 string    `json:"stored_sha256"`
	Redacted     bool      `json:"redacted,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"`
	Error        string    `json:"error,omitempty"`
	At           time.Time `json:"at"`
}

type Result struct {
	SpecFingerprint string        `json:"spec_fingerprint"`
	Verdict         string        `json:"verdict"`
	Reason          string        `json:"reason"`
	Observations    []Observation `json:"observations"`
}

// Runner uses its own client: no ambient proxy, cookie jar, retries, redirects or
// disabled TLS verification. All requests are GETs to the operator's exact origin.
type Runner struct {
	LookupEnv func(string) (string, bool)
	Timeout   time.Duration
}

func (r Runner) Run(ctx context.Context, spec Spec) Result {
	out := Result{SpecFingerprint: spec.Fingerprint(), Verdict: Inconclusive, Observations: []Observation{}}
	if err := spec.Validate(); err != nil {
		out.Verdict, out.Reason = PreconditionFailed, err.Error()
		return out
	}
	lookup := r.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	owner, okA := lookup(spec.Owner.CredentialEnv)
	other, okB := lookup(spec.Other.CredentialEnv)
	if !okA || !okB || strings.TrimSpace(owner) == "" || strings.TrimSpace(other) == "" || owner == other || strings.ContainsAny(owner+other, "\r\n") {
		out.Verdict, out.Reason = PreconditionFailed, "distinct credential values are unavailable or invalid"
		return out
	}
	timeout := r.Timeout
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	secrets := []string{owner, other}
	for _, v := range []string{owner, other} {
		if strings.HasPrefix(v, "Bearer ") {
			secrets = append(secrets, strings.TrimPrefix(v, "Bearer "))
		}
	}
	for _, pair := range []struct {
		actor Actor
		value string
	}{{spec.Owner, owner}, {spec.Other, other}} {
		if pair.actor.Header == "Cookie" {
			for _, cookie := range strings.Split(pair.value, ";") {
				if parts := strings.SplitN(cookie, "=", 2); len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
					secrets = append(secrets, strings.TrimSpace(parts[1]))
				}
			}
		}
	}
	read := func(stage, path string, actor Actor, credential string) (Observation, []byte) {
		target, _ := requestURL(spec.Origin, path)
		o := Observation{Stage: stage, PrincipalID: actor.PrincipalID, TenantID: actor.TenantID, URL: target, At: time.Now().UTC()}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			o.Error = "invalid_request"
			out.Observations = append(out.Observations, o)
			return o, nil
		}
		req.Header.Set(actor.Header, credential)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-cache")
		resp, err := client.Do(req)
		if err != nil {
			o.Error = "request_failed" // Transport errors may contain credential-bearing URLs.
			out.Observations = append(out.Observations, o)
			return o, nil
		}
		defer resp.Body.Close()
		o.Status = resp.StatusCode
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
		o.Truncated = len(body) > MaxBodyBytes
		if o.Truncated {
			body = body[:MaxBodyBytes]
		}
		if err != nil {
			o.Error = "body_read_failed"
		}
		o.SHA256 = digest(body)
		storedBody, redacted := redactBody(body, secrets)
		o.Redacted = redacted
		if o.Truncated {
			storedBody = nil
		}
		o.Body = base64.StdEncoding.EncodeToString(storedBody)
		o.StoredSHA256 = digest(storedBody)
		out.Observations = append(out.Observations, o)
		return o, body
	}
	identity := func(stage string, actor Actor, credential string) bool {
		o, body := read(stage, spec.IdentityPath, actor, credential)
		principal, ok := scalarAt(body, spec.PrincipalPointer)
		if !complete(o) || o.Status < 200 || o.Status >= 300 || !ok || principal != actor.PrincipalID {
			return false
		}
		if spec.TenantPointer != "" {
			tenant, ok := scalarAt(body, spec.TenantPointer)
			return ok && tenant == actor.TenantID
		}
		return true
	}
	var firstVerdict, protected string
	for round := 1; round <= 2; round++ {
		prefix := fmt.Sprintf("round_%d/", round)
		if !identity(prefix+"owner_identity", spec.Owner, owner) || !identity(prefix+"other_identity", spec.Other, other) {
			out.Verdict, out.Reason = PreconditionFailed, "principal or tenant could not be verified"
			return out
		}
		baseline, body := read(prefix+"owner_baseline", spec.ResourcePath, spec.Owner, owner)
		objectID, objectOK := scalarAt(body, spec.ObjectPointer)
		ownerID, ownerOK := scalarAt(body, spec.OwnerPointer)
		value, valueOK := scalarAt(body, spec.ProtectedPointer)
		if !complete(baseline) || baseline.Status < 200 || baseline.Status >= 300 || !objectOK || objectID != spec.ObjectID || !ownerOK || ownerID != spec.Owner.PrincipalID || !valueOK || len(value) < 8 {
			out.Verdict, out.Reason = PreconditionFailed, "normal access, resource ownership or a distinctive protected scalar could not be verified"
			return out
		}
		if round == 1 {
			protected = value
		} else if value != protected {
			out.Reason = "protected value changed between independent repetitions"
			return out
		}
		if digest([]byte(value)) != spec.ProtectedValueSHA256 {
			out.Verdict, out.Reason = PreconditionFailed, "normal access did not return the operator-known private scalar"
			return out
		}
		if reflectedInput(spec, value, other) {
			out.Verdict, out.Reason = PreconditionFailed, "the purported private value is already present in the testing request or credential"
			return out
		}
		probe, probeBody := read(prefix+"other_probe", spec.ResourcePath, spec.Other, other)
		if !complete(probe) {
			out.Reason = "test response was unavailable or incomplete"
			return out
		}
		if !identity(prefix+"other_identity_after", spec.Other, other) {
			out.Verdict, out.Reason = PreconditionFailed, "the testing identity expired or changed during the test"
			return out
		}
		verdict := Inconclusive
		if containsScalar(probeBody, protected) {
			verdict = ViolationObserved
		} else if probe.Status == http.StatusForbidden || probe.Status == http.StatusNotFound {
			if _, ok := decode(probeBody); ok || len(bytes.TrimSpace(probeBody)) == 0 {
				verdict = NotReproduced
			}
		}
		if verdict == Inconclusive {
			out.Reason = "response does not establish disclosure or an explicit denial"
			return out
		}
		if round == 1 {
			firstVerdict = verdict
		} else if verdict != firstVerdict {
			out.Reason = "independent repetitions disagree"
			return out
		}
	}
	out.Verdict = firstVerdict
	if firstVerdict == ViolationObserved {
		out.Reason = "a verified different principal received the owner's protected scalar in two repetitions"
		if err := VerifyViolation(spec, out); err != nil {
			out.Verdict, out.Reason = Inconclusive, "persisted response evidence cannot establish the violation: "+err.Error()
		}
	} else {
		out.Reason = "two valid tests were denied; this conclusion applies only to the configured identities, object and state"
	}
	return out
}

// VerifyViolation rechecks persisted observations rather than trusting a verdict
// string. It is intentionally separate from the live request loop and is used at
// the goal-completion boundary, including after process restart or archive restore.
func VerifyViolation(spec Spec, result Result) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if result.Verdict != ViolationObserved || result.SpecFingerprint != spec.Fingerprint() || len(result.Observations) != 10 {
		return errors.New("a complete repeated violation with the current configuration is required")
	}
	bodies := make([][]byte, 10)
	for i, o := range result.Observations {
		body, err := base64.StdEncoding.DecodeString(o.Body)
		if err != nil || !complete(o) || digest(body) != o.StoredSHA256 || (!o.Redacted && digest(body) != o.SHA256) || o.At.IsZero() {
			return errors.New("response evidence is incomplete or its stored bytes do not match its hash")
		}
		bodies[i] = body
	}
	checkIdentity := func(index int, actor Actor) bool {
		id, ok := scalarAt(bodies[index], spec.PrincipalPointer)
		if !ok || id != actor.PrincipalID || result.Observations[index].Status < 200 || result.Observations[index].Status >= 300 {
			return false
		}
		if spec.TenantPointer != "" {
			tenant, ok := scalarAt(bodies[index], spec.TenantPointer)
			return ok && tenant == actor.TenantID
		}
		return true
	}
	for round := 0; round < 2; round++ {
		base := round * 5
		stages := []string{"owner_identity", "other_identity", "owner_baseline", "other_probe", "other_identity_after"}
		for offset, stage := range stages {
			o := result.Observations[base+offset]
			actor, path := spec.Other, spec.IdentityPath
			if offset == 0 || offset == 2 {
				actor = spec.Owner
			}
			if offset == 2 || offset == 3 {
				path = spec.ResourcePath
			}
			target, _ := requestURL(spec.Origin, path)
			if o.Stage != fmt.Sprintf("round_%d/%s", round+1, stage) || o.PrincipalID != actor.PrincipalID || o.TenantID != actor.TenantID || o.URL != target {
				return errors.New("response evidence is bound to a different stage, identity or target")
			}
		}
		if !checkIdentity(base, spec.Owner) || !checkIdentity(base+1, spec.Other) || !checkIdentity(base+4, spec.Other) {
			return errors.New("persisted identity evidence does not meet the preconditions")
		}
		id, okID := scalarAt(bodies[base+2], spec.ObjectPointer)
		owner, okOwner := scalarAt(bodies[base+2], spec.OwnerPointer)
		value, okValue := scalarAt(bodies[base+2], spec.ProtectedPointer)
		status := result.Observations[base+2].Status
		if status < 200 || status >= 300 || !okID || id != spec.ObjectID || !okOwner || owner != spec.Owner.PrincipalID || !okValue || len(value) < 8 || digest([]byte(value)) != spec.ProtectedValueSHA256 || !containsScalar(bodies[base+3], value) {
			return errors.New("persisted baseline or disclosure does not prove the configured property violation")
		}
		if reflectedInput(spec, value, "") {
			return errors.New("the purported private value was supplied in the testing URL")
		}
	}
	return nil
}

func reflectedInput(spec Spec, value, credential string) bool {
	if strings.Contains(credential, value) {
		return true
	}
	for _, part := range []string{spec.Origin, spec.ResourcePath, spec.IdentityPath} {
		if strings.Contains(part, value) {
			return true
		}
		if decoded, err := url.QueryUnescape(part); err == nil && strings.Contains(decoded, value) {
			return true
		}
	}
	return false
}

func complete(o Observation) bool {
	return o.Error == "" && !o.Truncated && o.Status >= 200 && o.Status < 500 && (o.Status < 300 || o.Status >= 400)
}

func decode(body []byte) (any, bool) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, false
	}
	var extra any
	return v, d.Decode(&extra) == io.EOF
}

func scalarAt(body []byte, pointer string) (string, bool) {
	v, ok := decode(body)
	if !ok {
		return "", false
	}
	for _, key := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		key = strings.ReplaceAll(strings.ReplaceAll(key, "~1", "/"), "~0", "~")
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		v = m[key]
	}
	switch x := v.(type) {
	case string:
		return x, x != ""
	case json.Number:
		return string(x), true
	}
	return "", false
}

func containsScalar(body []byte, value string) bool {
	v, ok := decode(body)
	if !ok {
		return false
	}
	var visit func(any) bool
	visit = func(v any) bool {
		switch x := v.(type) {
		case string:
			return strings.Contains(x, value)
		case json.Number:
			return string(x) == value
		case []any:
			for _, child := range x {
				if visit(child) {
					return true
				}
			}
		case map[string]any:
			for _, child := range x {
				if visit(child) {
					return true
				}
			}
		}
		return false
	}
	return visit(v)
}

func redactBody(body []byte, secrets []string) ([]byte, bool) {
	redacted := false
	replace := func(s string) string {
		for _, secret := range secrets {
			if secret != "" && strings.Contains(s, secret) {
				s = strings.ReplaceAll(s, secret, "[credential redacted]")
				redacted = true
			}
		}
		return s
	}
	// Decode JSON first so escaped or Unicode-encoded echoes are also redacted.
	if value, ok := decode(body); ok {
		var clean func(any) any
		clean = func(v any) any {
			switch x := v.(type) {
			case string:
				return replace(x)
			case []any:
				for i, child := range x {
					x[i] = clean(child)
				}
			case map[string]any:
				out := make(map[string]any, len(x))
				for key, child := range x {
					out[replace(key)] = clean(child)
				}
				return out
			}
			return v
		}
		value = clean(value)
		if redacted {
			out, _ := json.Marshal(value)
			return out, true
		}
		return body, false
	}
	out := replace(string(body))
	return []byte(out), redacted
}
