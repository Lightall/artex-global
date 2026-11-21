package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestReviewRuleReadFailurePreventsAssetInsert(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("allowed.scope-review.test", "goal", db.TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	toolset := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	toolset.SetAssetStore(d.Assets(), d.Companies())
	toolset.SetTaskID(task.ID)
	if _, err := d.Exec(`ALTER TABLE task_intercept_rules RENAME TO review_unreadable_task_intercept_rules`); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`ALTER TABLE review_unreadable_task_intercept_rules RENAME TO task_intercept_rules`)
	if _, err := d.Exec(`DELETE FROM assets WHERE url='https://outside.scope-review.test/read-error'`); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = d.QueryRow(`SELECT count(*) FROM assets WHERE url='https://outside.scope-review.test/read-error'`).Scan(&before)
	in, _ := json.Marshal(map[string]any{"assets": []any{map[string]any{"type": "service", "url": "https://outside.scope-review.test/read-error"}}})
	result, err := toolset.insertAssets().Call(context.Background(), in, nil)
	var after int
	_ = d.QueryRow(`SELECT count(*) FROM assets WHERE url='https://outside.scope-review.test/read-error'`).Scan(&after)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("scope read failed but an asset was written: %s", result.Flatten())
	}
}

func TestReviewAllDomainsReachPlannerAndWorkerSystemRequests(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("a.scope-review.test\nb.scope-review.test", "fixture goal", db.TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := d.Exploration(task.ExplorationID)
	var lock sync.Mutex
	var requests []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		lock.Lock()
		requests = append(requests, body)
		lock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fixture","choices":[{"message":{"role":"assistant","content":"fixture finished"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()
	cfg := ConfigFrom("openai", "fixture", server.URL, "fixture-key", "")
	cfg.ReasoningEffort = "max"
	provider, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	prior := PromptOverride
	PromptOverride = func(string) (string, bool) { return "Custom role without scope variables", true }
	defer func() { PromptOverride = prior }()
	planner := NewPlanner(provider, "fixture", t.TempDir(), nil, 200000, 1)
	planner.SetNonStreaming(func() bool { return true })
	planner.SetConstraintInject(func() bool { return false })
	if _, _, err := planner.Plan(context.Background(), task.ID, d.Assets(), ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intentID, err := ts.AddIntent(map[string]any{"summary": "fixture intent with no domain text"}, 5, nil, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 200000, 1)
	worker.SetNonStreaming(func() bool { return true })
	worker.SetConstraintInject(func() bool { return false })
	if _, _, err := worker.Execute(context.Background(), "fixture", task.ID, d.Assets(), ts, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	defer lock.Unlock()
	if len(requests) < 2 {
		t.Fatalf("missing planner/worker requests: %d", len(requests))
	}
	for _, request := range requests {
		var system string
		for _, item := range request["messages"].([]any) {
			message := item.(map[string]any)
			if message["role"] == "system" {
				raw, _ := json.Marshal(message["content"])
				system += string(raw)
			}
		}
		for _, domain := range []string{"a.scope-review.test", "b.scope-review.test"} {
			if !strings.Contains(system, domain) {
				t.Fatalf("domain %s missing from actual system request: %s", domain, system)
			}
		}
		if request["reasoning_effort"] != "max" {
			t.Fatalf("effort was changed: %+v", request["reasoning_effort"])
		}
		tools, _ := json.Marshal(request["tools"])
		if !strings.Contains(string(tools), `"Bash"`) {
			t.Fatal("accepted Bash capability was removed")
		}
	}
}

func TestReviewWorkerRechecksAnchorsBeforeCallingProvider(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("allowed.scope-review.test", "goal", db.TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	outside, err := d.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://outside.scope-review.test/worker"})
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(task.ExplorationID)
	intentID, err := ts.AddIntent(map[string]any{"summary": "stale fixture intent", "asset_ids": []int64{outside}}, 5, []int64{outside}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		calls++
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}}
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 200000, 1)
	_, _, err = worker.Execute(context.Background(), "fixture", task.ID, d.Assets(), ts, intent, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "scope") || calls != 0 {
		t.Fatalf("out-of-scope intent executed: error=%v provider_calls=%d", err, calls)
	}
}

func TestReviewInvalidAssetIDsCannotBecomeUnanchored(t *testing.T) {
	for _, raw := range []string{`["bad"]`, `[null]`, `[0]`, `[-1]`, `[1.5]`, `["7",false]`} {
		var ids []json.RawMessage
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			t.Fatal(err)
		}
		if _, err := NewToolSet(nil, "fixture").addOneIntent(intentItem{Summary: "fixture", AssetIDs: ids}); err == nil {
			t.Fatalf("invalid IDs silently dropped: %s", raw)
		}
		intent := &db.Node{ID: 1, Payload: json.RawMessage(`{"asset_ids":` + raw + `}`)}
		if _, err := intentAssetIDs(intent); err == nil {
			t.Fatalf("invalid worker anchors silently dropped: %s", raw)
		}
	}
	ids, err := intentAssetIDs(&db.Node{ID: 1, Payload: json.RawMessage(`{"asset_ids":["7",8]}`)})
	if err != nil || len(ids) != 2 || ids[0] != 7 || ids[1] != 8 {
		t.Fatalf("legacy string IDs lost: %v %v", ids, err)
	}
}

func TestReviewMalformedIntentToolInputDoesNotWrite(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("allowed.scope-review.test", "goal", db.TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	toolset := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	toolset.SetAssetStore(d.Assets(), d.Companies())
	toolset.SetTaskID(task.ID)
	for _, raw := range []string{
		`{"summary":"fixture","asset_ids":"7"}`,
		`{"summary":"fixture","asset_ids":{}}`,
		`{"intents":[{"summary":"fixture","asset_ids":true}]}`,
	} {
		if _, err := toolset.addIntent().Call(context.Background(), json.RawMessage(raw), nil); err != nil {
			continue
		}
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'`, task.ExplorationID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("malformed asset_ids became an unanchored intent: %s", raw)
		}
	}
}
