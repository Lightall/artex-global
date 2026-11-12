package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/internal/verificationlab"
	"github.com/Autumn-27/artex/verification"
	"github.com/Autumn-27/norma/llm"
)

type verificationFixture struct {
	s      *Server
	task   *Task
	lab    *verificationlab.Lab
	intent int64
	cfg    verification.Config
	ctx    context.Context
}

func newVerificationFixture(t *testing.T, opts verificationlab.Options) *verificationFixture {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	task, err := m.CreateTask("local HTTP verification acceptance", "Confirm one reproducible IDOR", nil, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true})
	})
	if _, err = task.Store.AddNode(db.KindGoal, map[string]any{"text": "Confirm one reproduced IDOR"}, 5, "open", "fixture", nil); err != nil {
		t.Fatal(err)
	}
	lab := verificationlab.New(opts)
	t.Cleanup(func() { cancel(); lab.Close() })
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	asset, err := m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: lab.Case.URL, TaskID: id})
	if err != nil {
		t.Fatal(err)
	}
	lab.Case.AssetIDs = []int64{asset}
	cfg := verification.Config{Cases: []verification.Case{lab.Case}, RequiredFindings: 1, MaxRequests: 30}
	// Configure through the same authenticated API available to the operator.
	b, _ := json.Marshal(cfg)
	req := httptest.NewRequest("PUT", "/api/tasks/"+task.ID+"/verification", bytes.NewReader(b))
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("config API: %d %s", rec.Code, rec.Body.String())
	}
	intent, err := task.Store.AddIntent(map[string]any{"summary": "initial configured HTTP experiment", "asset_ids": lab.Case.AssetIDs}, 5, lab.Case.AssetIDs, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	return &verificationFixture{s, task, lab, intent, cfg, ctx}
}

func (f *verificationFixture) workerContext(t *testing.T) context.Context {
	t.Helper()
	if err := f.task.Store.SetNodeState(f.intent, "running"); err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(f.task.ID, 10, 64)
	return agent.WithRunInfo(f.ctx, agent.RunInfo{TaskID: id, ExplorationID: f.task.ExpID, IntentID: f.intent})
}

func callVerificationTool(t *testing.T, f *verificationFixture, ctx context.Context, name string, in any) (string, bool) {
	t.Helper()
	b, _ := json.Marshal(in)
	for _, tool := range f.s.httpVerificationTools() {
		if tool.Name() == name {
			r, err := tool.Call(ctx, b, nil)
			if err != nil {
				t.Fatal(err)
			}
			return r.Flatten(), r.IsError
		}
	}
	t.Fatal("missing tool " + name)
	return "", true
}

func runAttempt(t *testing.T, f *verificationFixture, ctx context.Context, tool string) *db.TestAttempt {
	t.Helper()
	raw, bad := callVerificationTool(t, f, ctx, tool, map[string]any{"case_id": f.lab.Case.ID})
	if bad {
		t.Fatal(raw)
	}
	var a db.TestAttempt
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func TestVerificationAdmissionAndCompletion(t *testing.T) {
	f := newVerificationFixture(t, verificationlab.Options{})
	ctx := f.workerContext(t)
	pg := f.s.m.pg
	tid, _ := strconv.ParseInt(f.task.ID, 10, 64)
	base := db.RecordFindingInput{TaskID: tid, ExplorationID: f.task.ExpID, IntentID: f.intent, VulnClass: "IDOR", Severity: "high", Summary: "private object disclosure", AssetIDs: f.lab.Case.AssetIDs}
	candidate, err := f.s.evidenceStore().Record(ctx, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.VerificationStatus != "candidate" {
		t.Fatal(candidate)
	}
	if err = pg.CheckVerificationCompletion(ctx, tid); err == nil {
		t.Fatal("candidate completed the goal")
	}
	if err = f.s.m.SetTaskStatus(f.task.ID, "done"); err == nil {
		t.Fatal("manager bypassed verification criterion")
	}
	if _, err = f.s.m.SetTaskStatusGuarded(f.task.ID, "done"); err == nil {
		t.Fatal("guarded manager bypassed criterion")
	}
	// Both model-facing completion tools must refuse an unverified fact/finding.
	goals, e := f.task.Store.ListByKind(db.KindGoal, 10)
	if e != nil {
		t.Fatal(e)
	}
	ts := agent.NewToolSet(f.task.Store, "planner")
	for _, tool := range ts.PlannerTools() {
		if tool.Name() == "prove_goal" || tool.Name() == "goal_met" {
			input, _ := json.Marshal(map[string]any{"goal_id": goals[0].ID, "evidence_id": candidate.NodeID, "reason": "unsupported completion"})
			result, e := tool.Call(ctx, input, nil)
			if e != nil || !result.IsError {
				t.Fatalf("completion tool %s accepted candidate: %v %s", tool.Name(), e, result.Flatten())
			}
		}
	}
	attempt := runAttempt(t, f, ctx, "run_http_case")
	if attempt.Verdict != "reproduced" {
		t.Fatal(attempt)
	}
	base.AttemptID, base.VerificationCaseID = attempt.ID, f.lab.Case.ID
	for _, tc := range []string{"forged", "wrong_case", "wrong_assets", "wrong_class", "wrong_intent", "wrong_task", "missing_storage"} {
		t.Run(tc, func(t *testing.T) {
			in := base
			switch tc {
			case "forged":
				in.AttemptID += 999999
			case "wrong_case":
				in.VerificationCaseID = "another"
			case "wrong_assets":
				in.AssetIDs = nil
			case "wrong_class":
				in.VulnClass = "SQLi"
			case "wrong_intent":
				in.IntentID = 0
			case "wrong_task":
				other, e := pg.CreateTask("foreign", "foreign", nil, 0, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer pg.DeleteTask(other.ID)
				in.TaskID = other.ID
				in.ExplorationID = other.ExplorationID
				in.IntentID = 0
			}
			var e error
			if tc == "missing_storage" {
				_, e = f.task.Store.RecordFinding(ctx, in)
			} else {
				_, e = f.s.evidenceStore().Record(ctx, in, nil)
			}
			if e == nil {
				t.Fatal("unqualified proof accepted")
			}
		})
	}
	t.Run("evidence_write_failure", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "not-a-directory")
		if e := os.WriteFile(blocked, []byte("fixture"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := evidence.New(pg, nil, blocked).Record(ctx, base, nil); e == nil {
			t.Fatal("failed durable write promoted finding")
		}
		var count int
		if e := pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, tid).Scan(&count); e != nil || count != 1 {
			t.Fatalf("failed write left a partial finding: %d %v", count, e)
		}
	})
	verified, err := f.s.evidenceStore().Record(ctx, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verified.VerificationStatus != "reproduced" || len(verified.Traffic.Bindings) != 5 {
		t.Fatalf("proofs not bound: %+v", verified)
	}
	finding, err := pg.GetFinding(verified.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != db.FindingPending || finding.VerificationStatus != "reproduced" {
		t.Fatal("verification changed remediation state")
	}
	if err = pg.CheckVerificationCompletion(ctx, tid); err != nil {
		t.Fatal(err)
	}
	if err = f.task.Store.CheckVerificationEvidence(candidate.NodeID); err == nil {
		t.Fatal("correct counter accepted the wrong proof edge")
	}
	if err = f.task.Store.CheckVerificationEvidence(verified.NodeID); err != nil {
		t.Fatal(err)
	}
	// Tampering or a changed target version must invalidate completion as well as promotion.
	if _, err = pg.Exec(`UPDATE test_attempts SET observations=jsonb_set(observations,'{3,body}','"Zm9yZ2Vk"') WHERE id=$1`, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err = pg.CheckVerificationCompletion(ctx, tid); err == nil {
		t.Fatal("tampered proof still counted")
	}
	view, err := pg.VerificationOverview(ctx, tid)
	if err != nil || view["reproduced_count"] != 0 {
		t.Fatalf("overview trusted corrupted proof: %v %v", view, err)
	}
	base.AttemptID = runAttempt(t, f, ctx, "run_http_case").ID
	if _, err = f.s.evidenceStore().Record(ctx, base, nil); err != nil {
		t.Fatal(err)
	}
	changed := f.cfg
	changed.Cases = append([]verification.Case{}, f.cfg.Cases...)
	changed.Cases[0].ObjectID = "changed-object"
	if err = pg.SetHTTPVerificationConfig(ctx, tid, changed); err != nil {
		t.Fatal(err)
	}
	if err = pg.CheckVerificationCompletion(ctx, tid); err == nil {
		t.Fatal("stale version completed goal")
	}
}

func TestVerificationUpgradePreservesUserConfiguration(t *testing.T) {
	f := newVerificationFixture(t, verificationlab.Options{})
	pg := f.s.m.pg
	report, err := pg.GetTool("report_finding")
	if err != nil {
		t.Fatal(err)
	}
	run, err := pg.GetTool("run_http_case")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`UPDATE tools SET description=$2,schema=$3,enabled=$4,agents=$5 WHERE key=$1`, report.Key, report.Description, report.Schema, report.Enabled, mustToolJSON(report.Agents))
		_, _ = pg.Exec(`UPDATE tools SET enabled=$2,agents=$3 WHERE key=$1`, run.Key, run.Enabled, mustToolJSON(run.Agents))
	})
	if _, err = pg.Exec(`UPDATE tools SET description='operator custom description',schema=(schema #- '{properties,attempt_id}') #- '{properties,verification_case_id}' WHERE key='report_finding'`); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE tools SET enabled=false,agents='["planner"]' WHERE key='run_http_case'`); err != nil {
		t.Fatal(err)
	}
	if err = f.s.seedHTTPVerificationTools(); err != nil {
		t.Fatal(err)
	}
	after, err := pg.GetTool("report_finding")
	if err != nil {
		t.Fatal(err)
	}
	if after.Description != "operator custom description" || !bytes.Contains(after.Schema, []byte("attempt_id")) {
		t.Fatal("additive migration lost custom description or new property")
	}
	afterRun, err := pg.GetTool("run_http_case")
	if err != nil {
		t.Fatal(err)
	}
	if afterRun.Enabled || fmt.Sprint(afterRun.Agents) != "[planner]" {
		t.Fatal("seed re-enabled or rebound a user-configured tool")
	}
}

func mustToolJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestVerificationNegativeAndRecoveryBoundaries(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{{"fixed", "not_reproduced"}, {"business_denial", "not_reproduced"}, {"waf", "inconclusive"}, {"public", "inconclusive"}, {"inconsistent", "inconclusive"}} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newVerificationFixture(t, verificationlab.Options{Mode: tc.mode})
			a := runAttempt(t, f, f.workerContext(t), "run_http_case")
			if a.Verdict != tc.want {
				t.Fatalf("got %+v", a)
			}
			if err := f.task.Store.CheckVerificationCompletion(); err == nil {
				t.Fatal("non-positive completed task")
			}
		})
	}
	t.Run("attempt_and_request_budget", func(t *testing.T) {
		f := newVerificationFixture(t, verificationlab.Options{Expired: true})
		ctx := f.workerContext(t)
		runAttempt(t, f, ctx, "run_http_case")
		runAttempt(t, f, ctx, "run_http_case")
		if _, bad := callVerificationTool(t, f, ctx, "run_http_case", map[string]any{"case_id": f.lab.Case.ID}); !bad {
			t.Fatal("attempt budget bypassed")
		}
		tid, _ := strconv.ParseInt(f.task.ID, 10, 64)
		if _, e := f.s.m.pg.Exec(`UPDATE tasks SET verification_requests=30 WHERE id=$1`, tid); e != nil {
			t.Fatal(e)
		}
		before := len(f.lab.Requests())
		a := runAttempt(t, f, ctx, "refresh_http_case_auth")
		if a.State != "failed" || len(f.lab.Requests()) != before {
			t.Fatal("request budget escaped")
		}
	})
	t.Run("interrupted_and_restart", func(t *testing.T) {
		f := newVerificationFixture(t, verificationlab.Options{})
		ctx := f.workerContext(t)
		tid, _ := strconv.ParseInt(f.task.ID, 10, 64)
		a, _, _, e := f.s.m.pg.StartHTTPAttempt(ctx, tid, f.intent, f.lab.Case.ID, "verify")
		if e != nil {
			t.Fatal(e)
		}
		f.s.m.pg.AbortHTTPAttempt(a.ID, nil, "interrupted")
		a, e = f.s.m.pg.GetTestAttempt(ctx, a.ID)
		if e != nil || a.State != "failed" || a.Verdict != "inconclusive" {
			t.Fatalf("%+v %v", a, e)
		}
		a, _, _, e = f.s.m.pg.StartHTTPAttempt(ctx, tid, f.intent, f.lab.Case.ID, "verify")
		if e != nil {
			t.Fatal(e)
		}
		if e = f.s.m.pg.RecoverVerificationAttempts(ctx); e != nil {
			t.Fatal(e)
		}
		a, e = f.s.m.pg.GetTestAttempt(ctx, a.ID)
		if e != nil || a.Reason != "service_restarted" {
			t.Fatalf("%+v %v", a, e)
		}
	})
}

// fixedVerificationProvider executes scripted decisions through the actual SDK loop.
// It has no HTTP model transport, credentials, or natural-language inference.
type fixedVerificationProvider struct {
	mu    sync.Mutex
	calls int
	next  func(llm.CompletionRequest) (string, any, error)
}

func (p *fixedVerificationProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	name, in, err := p.next(req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if name == "" {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture turn complete")}}, "end_turn", llm.Usage{}, nil
	}
	found := false
	for _, tool := range req.Tools {
		if tool.Name == name {
			found = true
		}
	}
	if !found {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("tool %s not visible through normal assembly", name)
	}
	b, _ := json.Marshal(in)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: fmt.Sprintf("fixture-%d", p.calls), Name: name, Input: b}}}, "tool_use", llm.Usage{}, nil
}
func (p *fixedVerificationProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		y(llm.StreamEvent{}, errors.New("unexpected streaming call in zero-model fixture"))
	}
}

func latestVerificationReply(req llm.CompletionRequest) (string, string, bool) {
	names := map[string]string{}
	for _, m := range req.Messages {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolUse {
				names[b.ID] = b.Name
			}
		}
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		for _, b := range req.Messages[i].Content {
			if b.Type == llm.BlockToolResult {
				var text strings.Builder
				for _, c := range b.Content {
					text.WriteString(c.Text)
				}
				return names[b.ToolUseID], text.String(), b.IsError
			}
		}
	}
	return "", "", false
}

func TestVerificationExpiredLoginEngineEndToEnd(t *testing.T) {
	f := newVerificationFixture(t, verificationlab.Options{Expired: true})
	tid, _ := strconv.ParseInt(f.task.ID, 10, 64)
	wprov := &fixedVerificationProvider{}
	wprov.next = func(req llm.CompletionRequest) (string, any, error) {
		name, raw, bad := latestVerificationReply(req)
		if bad {
			return "", nil, fmt.Errorf("worker tool failed: %s", raw)
		}
		switch name {
		case "":
			if strings.Contains(strings.Join(req.System, "\n"), "recover-prerequisites") {
				return "refresh_http_case_auth", map[string]any{"case_id": f.lab.Case.ID}, nil
			}
			return "run_http_case", map[string]any{"case_id": f.lab.Case.ID}, nil
		case "refresh_http_case_auth":
			var a db.TestAttempt
			if e := json.Unmarshal([]byte(raw), &a); e != nil || a.Reason != "credentials_refreshed" {
				return "", nil, fmt.Errorf("refresh failed: %s", raw)
			}
			return "run_http_case", map[string]any{"case_id": f.lab.Case.ID}, nil
		case "run_http_case":
			var a db.TestAttempt
			if e := json.Unmarshal([]byte(raw), &a); e != nil {
				return "", nil, e
			}
			if a.Verdict == "inconclusive" {
				if a.Reason != "owner_identity_invalid" {
					return "", nil, fmt.Errorf("unexpected prerequisite: %s", raw)
				}
				return "", nil, nil
			}
			if a.Verdict != "reproduced" {
				return "", nil, fmt.Errorf("not reproduced: %s", raw)
			}
			return "report_finding", map[string]any{"vulnclass": "IDOR", "severity": "high", "summary": "Another authenticated user can read the private object", "intent_id": a.IntentID, "asset_ids": f.lab.Case.AssetIDs, "evidence": "Real baseline/probe/repeat observations are bound to the experiment receipt.", "attempt_id": a.ID, "verification_case_id": a.CaseID}, nil
		case "report_finding":
			if !strings.Contains(raw, "reproduced") {
				return "", nil, fmt.Errorf("finding did not retain verification: %s", raw)
			}
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("unexpected worker result %s", name)
	}
	repairIssued := false
	ppr := &fixedVerificationProvider{}
	ppr.next = func(req llm.CompletionRequest) (string, any, error) {
		name, raw, bad := latestVerificationReply(req)
		if bad {
			return "", nil, fmt.Errorf("planner tool failed: %s", raw)
		}
		if name != "" {
			return "", nil, nil
		}
		input := ""
		for _, m := range req.Messages {
			if m.Role == llm.RoleUser {
				input += m.Text()
			}
		}
		marker := strings.Index(input, "【本轮态势")
		if marker < 0 {
			return "", nil, errors.New("planner did not receive prefetched overview")
		}
		rest := input[marker:]
		start := strings.Index(rest, "{")
		var ov map[string]any
		if e := json.NewDecoder(strings.NewReader(rest[start:])).Decode(&ov); e != nil {
			return "", nil, e
		}
		v, ok := ov["verification"].(map[string]any)
		if !ok {
			return "", nil, errors.New("verification overview missing")
		}
		if v["reproduced_count"].(float64) >= 1 {
			goals := ov["goals"].([]any)
			findings := ov["finding_list"].([]any)
			if len(findings) == 0 {
				return "", nil, errors.New("reproduction did not reach finding list")
			}
			return "prove_goal", map[string]any{"goal_id": goals[0].(map[string]any)["id"], "evidence_id": findings[0].(map[string]any)["id"], "reason": "One host-verified private-object disclosure satisfies the configured criterion"}, nil
		}
		if !repairIssued && strings.Contains(input, "owner_identity_invalid") {
			repairIssued = true
			return "add_intent", map[string]any{"summary": "recover-prerequisites: refresh configured identities then rerun case " + f.lab.Case.ID, "asset_ids": f.lab.Case.AssetIDs}, nil
		}
		return "", nil, nil
	}
	dir := t.TempDir()
	worker := agent.NewWorker(wprov, "fixed-fixture", dir, nil, 100000, 12)
	worker.SetNonStreaming(func() bool { return true })
	worker.SetFindingRecorder(f.s.evidenceStore())
	planner := agent.NewPlanner(ppr, "fixed-fixture", dir, nil, 100000, 8)
	planner.SetNonStreaming(func() bool { return true })
	planner.SetFindingRecorder(f.s.evidenceStore())
	f.s.engine.SetReadiness(func() bool { return true })
	f.s.engine.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return planner, worker })
	f.s.engine.Run(f.ctx, f.task)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f.task.lifecycleSnapshot().Status == "done" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f.task.lifecycleSnapshot().Status != "done" {
		t.Fatalf("engine did not complete: planner=%d worker=%d", ppr.calls, wprov.calls)
	}
	if !repairIssued {
		t.Fatal("planner never consumed the failed prerequisite")
	}
	rows, err := f.s.m.pg.Query(`SELECT id FROM test_attempts WHERE task_id=$1 ORDER BY id`, tid)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var receipts []map[string]any
	var sequence []string
	for _, id := range ids {
		a, e := f.s.m.pg.GetTestAttempt(t.Context(), id)
		if e != nil {
			t.Fatal(e)
		}
		sequence = append(sequence, a.Kind+":"+a.Verdict+":"+a.Reason)
		receipts = append(receipts, map[string]any{"attempt": a, "observations": a.Observations})
	}
	if len(sequence) != 3 || !strings.Contains(sequence[0], "owner_identity_invalid") || !strings.Contains(sequence[1], "credentials_refreshed") || !strings.Contains(sequence[2], "reproduced:private_object_read_by_other_actor_twice") {
		t.Fatalf("wrong experiment history: %v", sequence)
	}
	if len(f.lab.Requests()) != 10 {
		t.Fatalf("expected 10 real local HTTP requests, got %d", len(f.lab.Requests()))
	}
	findings, err := f.s.m.pg.ListFindings(50)
	if err != nil {
		t.Fatal(err)
	}
	var mine []*db.DBFinding
	for _, finding := range findings {
		if finding.TaskID != nil && *finding.TaskID == tid {
			mine = append(mine, finding)
		}
	}
	if len(mine) != 1 || mine[0].VerificationStatus != "reproduced" || mine[0].Status != db.FindingPending || mine[0].TrafficCount != 5 {
		t.Fatalf("wrong final finding state: %+v", mine)
	}
	evidence := map[string]any{"scope": "zero-model-cost scripted engine integration; not natural model validation", "model_http_calls": 0, "planner_fixture_turns": ppr.calls, "worker_fixture_turns": wprov.calls, "sequence": sequence, "task_status": f.task.lifecycleSnapshot().Status, "local_http_requests": f.lab.Requests(), "receipts": receipts, "finding": mine[0]}
	if dest := os.Getenv("ARTEX_MVP_EVIDENCE_DIR"); dest != "" {
		if err = os.MkdirAll(dest, 0700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(evidence, "", "  ")
		if err = os.WriteFile(filepath.Join(dest, "expired-login-e2e.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("PASS: %v; %d real local requests; model HTTP calls=0; finding=%d proofs=%d", sequence, len(f.lab.Requests()), mine[0].ID, mine[0].TrafficCount)
}
