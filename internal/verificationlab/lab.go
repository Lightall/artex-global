// Package verificationlab is a deliberately vulnerable, loopback-only test fixture.
package verificationlab

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/verification"
)

type Options struct {
	Mode    string
	Expired bool
}
type Request struct {
	Path   string `json:"path"`
	Actor  string `json:"actor"`
	Status int    `json:"status"`
}
type Lab struct {
	Server   *httptest.Server
	Case     verification.Case
	Marker   string
	mu       sync.Mutex
	requests []Request
	probes   int
}

func New(opts Options) *Lab {
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	suffix := hex.EncodeToString(nonce)
	l := &Lab{Marker: "private-marker-" + suffix}
	owner, other := "owner-"+suffix, "other-"+suffix
	tokens := map[string]string{"token-owner-" + suffix: owner, "token-other-" + suffix: other}
	object := "object-" + suffix
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		actor := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		status := 200
		reply := func(code int, body any) {
			status = code
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(body)
		}
		defer func() { l.requests = append(l.requests, Request{r.URL.Path, actor, status}) }()
		if r.URL.Path == "/login" {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["password"] != "fixture-only" || (in["username"] != owner && in["username"] != other) {
				reply(401, map[string]any{"error": "bad_login"})
				return
			}
			name := "other"
			if in["username"] == owner {
				name = "owner"
			}
			reply(200, map[string]any{"token": "token-" + name + "-" + suffix})
			return
		}
		if actor == "" {
			if opts.Mode == "login200" {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("<html>Sign in</html>"))
				return
			}
			reply(401, map[string]any{"error": "expired"})
			return
		}
		if r.URL.Path == "/me" {
			reply(200, map[string]any{"id": actor})
			return
		}
		if r.URL.Path != "/objects/"+object {
			reply(404, map[string]any{"error": "not_found"})
			return
		}
		if opts.Mode == "cancel" {
			<-r.Context().Done()
			return
		}
		if opts.Mode == "oversize" {
			_, _ = w.Write([]byte(strings.Repeat("x", verification.MaxBody+2)))
			return
		}
		if actor == other {
			l.probes++
			switch opts.Mode {
			case "fixed":
				reply(403, map[string]any{"error": "forbidden"})
				return
			case "business_denial":
				reply(200, map[string]any{"error": "forbidden"})
				return
			case "waf":
				status = 403
				w.WriteHeader(403)
				_, _ = w.Write([]byte("<html>WAF challenge</html>"))
				return
			case "inconsistent":
				if l.probes > 1 {
					reply(403, map[string]any{"error": "forbidden"})
					return
				}
			case "wrong_object":
				reply(200, map[string]any{"id": "another-object", "owner_id": owner, "private": true, "secret": l.Marker})
				return
			}
		}
		reply(200, map[string]any{"id": object, "owner_id": owner, "private": opts.Mode != "public", "secret": l.Marker})
	}))
	actor := func(id, name string) verification.Actor {
		body, _ := json.Marshal(map[string]string{"username": id, "password": "fixture-only"})
		return verification.Actor{ID: id, Token: "token-" + name + "-" + suffix, IdentityURL: l.Server.URL + "/me", IdentityPointer: "/id", LoginURL: l.Server.URL + "/login", LoginBody: body, TokenPointer: "/token"}
	}
	l.Case = verification.Case{ID: "private-read", RuleSource: "operator fixture contract: objects are private and owner-readable", URL: l.Server.URL + "/objects/" + object, ObjectID: object, ObjectPointer: "/id", OwnerPointer: "/owner_id", PrivatePointer: "/private", ValuePointer: "/secret", DenialPointer: "/error", DenialValue: "forbidden", Owner: actor(owner, "owner"), Other: actor(other, "other")}
	if opts.Expired {
		l.Case.Owner.Token = "expired-fixture-token"
	}
	return l
}

func (l *Lab) Close() { l.Server.Close() }
func (l *Lab) Requests() []Request {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Request(nil), l.requests...)
}
