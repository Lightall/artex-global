// Package verification executes bounded, operator-configured local HTTP experiments.
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxBody = 64 << 10

type Actor struct {
	ID              string          `json:"id"`
	Token           string          `json:"token"`
	IdentityURL     string          `json:"identity_url"`
	IdentityPointer string          `json:"identity_pointer"`
	LoginURL        string          `json:"login_url"`
	LoginBody       json.RawMessage `json:"login_body"`
	TokenPointer    string          `json:"token_pointer"`
}

// Case is installed by the operator; model tools accept only its ID, never its oracle.
type Case struct {
	ID             string  `json:"id"`
	RuleSource     string  `json:"rule_source"`
	URL            string  `json:"url"`
	ObjectID       string  `json:"object_id"`
	ObjectPointer  string  `json:"object_pointer"`
	OwnerPointer   string  `json:"owner_pointer"`
	PrivatePointer string  `json:"private_pointer"`
	ValuePointer   string  `json:"value_pointer"`
	DenialPointer  string  `json:"denial_pointer"`
	DenialValue    string  `json:"denial_value"`
	AssetIDs       []int64 `json:"asset_ids,omitempty"`
	Owner          Actor   `json:"owner"`
	Other          Actor   `json:"other"`
}

type Config struct {
	Cases            []Case `json:"cases"`
	RequiredFindings int    `json:"required_findings"`
	MaxRequests      int    `json:"max_requests"`
}

type Auth map[string]string

// Observation is host-created and persisted in full; summaries do not expose bodies.
type Observation struct {
	Phase       string    `json:"phase"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	ActorID     string    `json:"actor_id"`
	Credential  string    `json:"credential_sha256,omitempty"`
	Status      int       `json:"status"`
	ContentType string    `json:"content_type"`
	Body        []byte    `json:"body"`
	BodyHash    string    `json:"body_sha256"`
	Error       string    `json:"error,omitempty"`
	At          time.Time `json:"at"`
}

func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func BodyHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func LocalURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return errors.New("MVP requires a literal loopback http URL")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("MVP only connects to literal loopback addresses")
	}
	return nil
}

func (c Config) Validate() error {
	if len(c.Cases) == 0 || len(c.Cases) > 10 || c.RequiredFindings < 1 || c.MaxRequests < 5 || c.MaxRequests > 200 {
		return errors.New("require 1..10 cases, required_findings >= 1 and max_requests 5..200")
	}
	seen := map[string]bool{}
	for _, item := range c.Cases {
		if item.ID == "" || seen[item.ID] || item.RuleSource == "" || item.ObjectID == "" || item.Owner.ID == "" || item.Other.ID == "" || item.Owner.ID == item.Other.ID {
			return errors.New("case requires unique ID, rule source, object and two distinct actors")
		}
		seen[item.ID] = true
		for _, p := range []string{item.ObjectPointer, item.OwnerPointer, item.PrivatePointer, item.ValuePointer, item.DenialPointer, item.Owner.IdentityPointer, item.Other.IdentityPointer} {
			if !strings.HasPrefix(p, "/") {
				return errors.New("oracle paths must be JSON pointers")
			}
		}
		if item.DenialValue == "" {
			return errors.New("explicit denial predicate required")
		}
		for _, raw := range []string{item.URL, item.Owner.IdentityURL, item.Other.IdentityURL} {
			if err := LocalURL(raw); err != nil {
				return err
			}
		}
		for _, a := range []Actor{item.Owner, item.Other} {
			if a.LoginURL != "" {
				if err := LocalURL(a.LoginURL); err != nil {
					return err
				}
				if !json.Valid(a.LoginBody) || !strings.HasPrefix(a.TokenPointer, "/") {
					return errors.New("refresh requires a JSON login body and token pointer")
				}
			}
		}
	}
	return nil
}

func (c Config) Find(id string) (Case, error) {
	for _, item := range c.Cases {
		if item.ID == id {
			return item, nil
		}
	}
	return Case{}, errors.New("unknown operator-configured case")
}

func scalar(body []byte, pointer string) (string, bool) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return "", false
	}
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		v, ok = m[strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")]
		if !ok {
			return "", false
		}
	}
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return fmt.Sprint(x), true
	case float64:
		return fmt.Sprint(x), true
	}
	return "", false
}

func ValidObservations(obs []Observation) bool {
	for _, o := range obs {
		if len(o.Body) > MaxBody || o.BodyHash != BodyHash(o.Body) || o.At.IsZero() {
			return false
		}
	}
	return true
}

func identity(o Observation, a Actor) bool {
	id, ok := scalar(o.Body, a.IdentityPointer)
	return o.Error == "" && o.Status == 200 && o.URL == a.IdentityURL && o.ActorID == a.ID && ok && id == a.ID
}

// Evaluate distinguishes an explicit, valid negative from a failed prerequisite.
func Evaluate(c Case, obs []Observation) (string, string) {
	if !ValidObservations(obs) {
		return "inconclusive", "invalid_receipt"
	}
	if len(obs) < 1 || !identity(obs[0], c.Owner) {
		return "inconclusive", "owner_identity_invalid"
	}
	if len(obs) < 2 || !identity(obs[1], c.Other) {
		return "inconclusive", "other_identity_invalid"
	}
	if len(obs) != 5 {
		return "inconclusive", "incomplete_experiment"
	}
	for i, phase := range []string{"owner_identity", "other_identity", "baseline", "probe", "repeat"} {
		if obs[i].Phase != phase || obs[i].Method != "GET" || obs[i].Error != "" {
			return "inconclusive", "incomplete_experiment"
		}
	}
	base := obs[2]
	id, idOK := scalar(base.Body, c.ObjectPointer)
	owner, ownerOK := scalar(base.Body, c.OwnerPointer)
	private, privateOK := scalar(base.Body, c.PrivatePointer)
	value, valueOK := scalar(base.Body, c.ValuePointer)
	if base.URL != c.URL || base.ActorID != c.Owner.ID || base.Credential != obs[0].Credential || base.Status != 200 || !idOK || id != c.ObjectID || !ownerOK || owner != c.Owner.ID || !privateOK || private != "true" || !valueOK || value == "" {
		return "inconclusive", "baseline_invalid"
	}
	positive, negative := 0, 0
	for _, o := range obs[3:] {
		if o.URL != c.URL || o.ActorID != c.Other.ID || o.Credential != obs[1].Credential {
			return "inconclusive", "probe_identity_mismatch"
		}
		if o.Status == 401 || o.Status == 429 || o.Status >= 500 {
			return "inconclusive", "probe_unavailable"
		}
		gotID, _ := scalar(o.Body, c.ObjectPointer)
		gotOwner, _ := scalar(o.Body, c.OwnerPointer)
		gotValue, _ := scalar(o.Body, c.ValuePointer)
		if o.Status == 200 && gotID == c.ObjectID && gotOwner == c.Owner.ID && gotValue == value {
			positive++
		} else if denial, ok := scalar(o.Body, c.DenialPointer); ok && denial == c.DenialValue && gotValue == "" {
			negative++
		}
	}
	if positive == 2 {
		return "reproduced", "private_object_read_by_other_actor_twice"
	}
	if negative == 2 {
		return "not_reproduced", "explicit_denial_with_valid_baseline"
	}
	return "inconclusive", "response_not_decisive"
}

type Runner struct{ Reserve func(context.Context) error }

func (r Runner) request(ctx context.Context, phase, rawURL, method string, a Actor, token string, body []byte) Observation {
	o := Observation{Phase: phase, URL: rawURL, Method: method, ActorID: a.ID, Credential: BodyHash([]byte(token)), At: time.Now().UTC()}
	finish := func(err error) Observation {
		if err != nil {
			o.Error = err.Error()
		}
		o.BodyHash = BodyHash(o.Body)
		return o
	}
	if err := LocalURL(rawURL); err != nil {
		return finish(err)
	}
	if r.Reserve != nil {
		if err := r.Reserve(ctx); err != nil {
			return finish(err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return finish(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return finish(err)
	}
	defer resp.Body.Close()
	o.Status, o.ContentType = resp.StatusCode, resp.Header.Get("Content-Type")
	o.Body, err = io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if len(o.Body) > MaxBody {
		o.Body = o.Body[:MaxBody]
		err = errors.New("response body exceeds verification limit")
	}
	return finish(err)
}

func token(a Actor, auth Auth, name string) string {
	if v := auth[name]; v != "" {
		return v
	}
	return a.Token
}

func (r Runner) Run(ctx context.Context, c Case, auth Auth) []Observation {
	ownerToken, otherToken := token(c.Owner, auth, "owner"), token(c.Other, auth, "other")
	obs := []Observation{r.request(ctx, "owner_identity", c.Owner.IdentityURL, "GET", c.Owner, ownerToken, nil)}
	if !identity(obs[0], c.Owner) {
		return obs
	}
	obs = append(obs, r.request(ctx, "other_identity", c.Other.IdentityURL, "GET", c.Other, otherToken, nil))
	if !identity(obs[1], c.Other) {
		return obs
	}
	obs = append(obs, r.request(ctx, "baseline", c.URL, "GET", c.Owner, ownerToken, nil))
	for _, phase := range []string{"probe", "repeat"} {
		obs = append(obs, r.request(ctx, phase, c.URL, "GET", c.Other, otherToken, nil))
	}
	return obs
}

func (r Runner) Refresh(ctx context.Context, c Case) ([]Observation, Auth, error) {
	auth := Auth{}
	var obs []Observation
	for i, a := range []Actor{c.Owner, c.Other} {
		name := []string{"owner", "other"}[i]
		if a.LoginURL == "" {
			return obs, nil, errors.New("operator did not configure credential refresh")
		}
		login := r.request(ctx, "login_"+name, a.LoginURL, "POST", a, "", a.LoginBody)
		obs = append(obs, login)
		fresh, ok := scalar(login.Body, a.TokenPointer)
		if login.Error != "" || login.Status != 200 || !ok || fresh == "" {
			return obs, nil, errors.New("login did not return a valid token")
		}
		check := r.request(ctx, name+"_identity", a.IdentityURL, "GET", a, fresh, nil)
		obs = append(obs, check)
		if !identity(check, a) {
			return obs, nil, errors.New("refreshed identity did not match the configured actor")
		}
		auth[name] = fresh
	}
	return obs, auth, nil
}

// RefreshedAuth derives credentials from complete host receipts, never model text.
func RefreshedAuth(c Case, obs []Observation) (Auth, error) {
	if len(obs) != 4 || !ValidObservations(obs) {
		return nil, errors.New("incomplete refresh receipts")
	}
	auth := Auth{}
	for i, a := range []Actor{c.Owner, c.Other} {
		name := []string{"owner", "other"}[i]
		login, check := obs[i*2], obs[i*2+1]
		fresh, ok := scalar(login.Body, a.TokenPointer)
		if login.Phase != "login_"+name || login.URL != a.LoginURL || login.Method != "POST" || login.Status != 200 || login.Error != "" || !ok || fresh == "" || check.Phase != name+"_identity" || !identity(check, a) || check.Credential != BodyHash([]byte(fresh)) {
			return nil, errors.New("invalid refreshed identity receipts")
		}
		auth[name] = fresh
	}
	return auth, nil
}
