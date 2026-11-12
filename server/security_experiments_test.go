package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
)

func TestSecurityExperimentAuthenticatedAPIZeroModelCalls(t *testing.T) {
	for _, key := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		t.Setenv(key, "")
	}
	ctx, cancel := context.WithCancel(t.Context())
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("experiment API test requires PostgreSQL: %v", err)
	}
	defer m.Close()
	defer cancel()
	// Exercise the real mux and auth without booting unrelated tasks restored
	// by other tests. This operation does not require a model runtime at all.
	s := &Server{ctx: ctx, m: m, engine: NewEngine(m), jwtKey: []byte("local-engineering-fixture-key-32bytes")}
	h := s.Handler()
	passwordHash, err := s.cachedPassHash()
	if err != nil {
		t.Fatal(err)
	}
	token, err := signJWT(s.signingKey(passwordHash))
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("operator experiment API", "find isolation violation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(taskID)
	goal, err := task.Store.AddGoal(map[string]any{"text": "find isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	target, spec := experimenttest.New(t)
	path := "/api/tasks/" + task.ID + "/security-experiments"
	do := func(method, path string, body any, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	var before, after int
	if err := m.pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1`, task.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"goal_id": goal, "spec": spec}
	if got := do(http.MethodPost, path, input, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated config: %d %s", got.Code, got.Body.String())
	}
	if got := do(http.MethodPost, path, map[string]any{"goal_id": goal, "spec": spec, "invented_authority": true}, true); got.Code != 400 {
		t.Fatalf("unknown configuration fields accepted: %d", got.Code)
	}
	created := do(http.MethodPost, path, input, true)
	if created.Code != 201 {
		t.Fatalf("case creation: %d %s", created.Code, created.Body.String())
	}
	var c struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &c); err != nil || c.ID == "" {
		t.Fatalf("case id: %s %v", created.Body.String(), err)
	}
	if target.Calls.Load() != 0 {
		t.Fatal("configuration or reading caused network execution")
	}
	if listed := do(http.MethodGet, path, nil, true); listed.Code != 200 {
		t.Fatalf("list: %s", listed.Body.String())
	}
	if got := do(http.MethodPost, path+"/"+c.ID+"/run", nil, false); got.Code != http.StatusUnauthorized || target.Calls.Load() != 0 {
		t.Fatal("unauthorized request triggered target probes")
	}
	result := do(http.MethodPost, path+"/"+c.ID+"/run", nil, true)
	if result.Code != 200 {
		t.Fatalf("run: %d %s", result.Code, result.Body.String())
	}
	var run struct {
		ID     string                    `json:"id"`
		Result securityexperiment.Result `json:"result"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.Result.Verdict != securityexperiment.ViolationObserved || target.Calls.Load() != 10 {
		t.Fatalf("API discovery: %+v", run)
	}
	read := do(http.MethodGet, "/api/tasks/"+task.ID+"/security-experiment-runs/"+run.ID, nil, true)
	if read.Code != 200 {
		t.Fatalf("evidence read: %s", read.Body.String())
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1`, task.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("model activity occurred: before=%d after=%d", before, after)
	}
	if s.engine.ActiveLLMCalls(task.ID) != 0 {
		t.Fatal("model runtime was started by the experiment API")
	}
	if target.Calls.Load() != 10 {
		t.Fatal("evidence read replayed traffic")
	}
	// Reconfiguration invalidates both persisted and live completion without
	// starting a model runtime. Unknown is not displayed as a completed task.
	runID, _ := strconv.ParseInt(run.ID, 10, 64)
	if _, err := task.Store.RecordFinding(ctx, db.RecordFindingInput{TaskID: taskID, ExperimentEvidenceID: runID, VulnClass: "BOLA", Severity: "high", Summary: "API verified discovery"}); err != nil {
		t.Fatal(err)
	}
	if err := task.Store.ProveGoal(goal, runID); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if got := do(http.MethodPost, path, input, true); got.Code != http.StatusCreated {
		t.Fatalf("case replacement: %d %s", got.Code, got.Body.String())
	}
	lifecycle := task.lifecycleSnapshot()
	if lifecycle.Status == "done" || lifecycle.CompletedAt != 0 || !lifecycle.Paused || s.deriveTaskStatus(task) != "paused" {
		t.Fatalf("operator reconfiguration retained completed UI state: %+v", lifecycle)
	}
	if s.engine.ActiveLLMCalls(task.ID) != 0 || target.Calls.Load() != 10 {
		t.Fatal("case replacement started models or replayed probes")
	}
}
