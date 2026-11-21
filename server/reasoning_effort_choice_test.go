package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestReasoningEffortChoicePersistsAndRebuildsProvider(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan map[string]any, 1)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fixture","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer mock.Close()
	var id int64
	defer func() {
		if id > 0 {
			m.pg.DeleteProfile(id)
		}
	}()
	for _, effort := range []string{"max", "high", "low", "medium", "xhigh", ""} {
		body, _ := json.Marshal(map[string]any{"id": id, "name": "reasoning-choice-fixture", "format": "openai", "base_url": mock.URL, "model": "fixture", "api_key": "fixture-key", "reasoning_effort": effort, "streaming": false})
		r := httptest.NewRequest(http.MethodPost, "/api/llm/profiles", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("save=%d body=%s", w.Code, w.Body.String())
		}
		var saved struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
			t.Fatal(err)
		}
		id = saved.ID
		profile, err := m.pg.ProfileByID(id)
		if err != nil || profile.ReasoningEffort != effort {
			t.Fatalf("persisted effort=%+v err=%v", profile, err)
		}
		provider, cfg, ok := s.providerForProfile(id)
		if !ok || cfg.ReasoningEffort != effort {
			t.Fatalf("cached provider effort=%q expected %q", cfg.ReasoningEffort, effort)
		}
		_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("local fixture")}}}, MaxTokens: 16})
		if err != nil {
			t.Fatal(err)
		}
		wire := <-received
		value, present := wire["reasoning_effort"]
		if effort == "" {
			if present {
				t.Fatalf("unspecified effort was transmitted: %v", value)
			}
		} else if value != effort {
			t.Fatalf("wire effort=%v expected %s", value, effort)
		}
	}
}
