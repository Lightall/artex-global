package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDomainScopePreviewUsesCreationResolver(t *testing.T) {
	s := new(Server)
	for _, tc := range []struct {
		input  string
		status int
	}{
		{"A.TEST.\nb.test\na.test", http.StatusOK},
		{"a.test\n*.outside.test", http.StatusBadRequest},
		{"", http.StatusBadRequest},
	} {
		body, _ := json.Marshal(map[string]string{"domains": tc.input})
		r := httptest.NewRequest(http.MethodPost, "/api/task-domain-scope/preview", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.previewTaskDomainScope(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d response=%s", w.Code, w.Body.String())
		}
		if w.Code == http.StatusOK {
			var response struct {
				Domains        []string
				InterceptRules []struct{ Pattern string } `json:"intercept_rules"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || strings.Join(response.Domains, "\n") != "a.test\nb.test" || len(response.InterceptRules) != 2 {
				t.Fatalf("preview=%+v err=%v", response, err)
			}
		}
	}
}

func TestDomainScopeHTTPCreatePersistsAllDomainsWithoutModels(t *testing.T) {
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
	body := []byte(`{"description":"A.TEST.\nb.test\na.test","goal":"inspect synthetic domain scope","domain_scope_enabled":true,"intercept_rules":[{"enabled":true,"action":"allow","kind":"exact_domain","pattern":"stale.test"}]}`)
	r := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(created.ID, DeleteTaskOptions{})
	task, ok := m.Task(created.ID)
	if !ok || task.Description != "a.test\nb.test" {
		t.Fatalf("task=%+v", task)
	}
	taskID, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := m.pg.Assets().ListTaskInterceptRules(taskID)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	for _, rule := range rules {
		if rule.Pattern == "stale.test" || !strings.Contains(task.Description, rule.Pattern) {
			t.Fatalf("stale or misbound rule=%+v", rule)
		}
	}
	var seeds int
	if err := m.pg.QueryRow("SELECT count(*) FROM assets WHERE $1=ANY(task_ids) AND url IN ('https://a.test', 'https://b.test')", taskID).Scan(&seeds); err != nil || seeds != 2 {
		t.Fatalf("seeded domains=%d err=%v", seeds, err)
	}
	var before int
	if err := m.pg.QueryRow("SELECT count(*) FROM tasks").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "a.test\n*.outside.test"} {
		body, _ := json.Marshal(map[string]any{"description": invalid, "goal": "goal", "domain_scope_enabled": true})
		req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid list created a task: %d %s", rec.Code, rec.Body.String())
		}
	}
	var after int
	if err := m.pg.QueryRow("SELECT count(*) FROM tasks").Scan(&after); err != nil || before != after {
		t.Fatalf("invalid HTTP create wrote a task: before=%d after=%d err=%v", before, after, err)
	}
}
