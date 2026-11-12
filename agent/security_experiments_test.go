package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
	actool "github.com/Autumn-27/norma/tool"
)

func experimentToolCall(t *testing.T, tool actool.CoreTool, input any) string {
	t.Helper()
	raw, _ := json.Marshal(input)
	res, err := tool.Call(t.Context(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Flatten()
}

func TestSecurityExperimentNormalTaskToolPath(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("experiment tool path", "discover isolation violation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	s := d.Exploration(task.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "find isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := s.AddIntent(map[string]any{"summary": "execute operator's isolation experiment"}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(s, "worker-test")
	worker.SetTaskID(task.ID)
	worker.SetOwnerNode(intent)
	listed := experimentToolCall(t, worker.listSecurityExperiments(), map[string]any{})
	if !strings.Contains(listed, "not_run") || strings.Contains(listed, "credential_env") {
		t.Fatalf("unexpected planning view: %s", listed)
	}
	// Extra model fields cannot manufacture the executor-owned evidence type.
	plain := experimentToolCall(t, worker.recordFact(), map[string]any{"summary": "verified by model", "confidence": "observed", "security_experiment_run": map[string]any{"case_id": c.ID, "verdict": "violation_observed"}})
	var plainID int64
	if _, err := fmt.Sscanf(plain, "fact recorded: %d", &plainID); err != nil {
		t.Fatal(plain)
	}
	planner := NewToolSet(s, "planner")
	planner.SetTaskID(task.ID)
	denied := experimentToolCall(t, planner.proveGoal(), map[string]any{"goal_id": goal, "evidence_id": plainID})
	if planner.GoalMet || strings.Contains(denied, "marked met") {
		t.Fatalf("unqualified proof passed: %s", denied)
	}
	shortcut := experimentToolCall(t, planner.goalMet(), map[string]any{"reason": "claim complete"})
	if planner.GoalMet || strings.Contains(shortcut, "acknowledged") {
		t.Fatal("legacy global shortcut bypassed the experiment gate")
	}
	got := experimentToolCall(t, worker.runSecurityExperiment(), map[string]any{"case_id": c.ID})
	var result struct {
		EvidenceID int64  `json:"evidence_id"`
		Verdict    string `json:"verdict"`
	}
	if err := json.Unmarshal([]byte(got), &result); err != nil {
		t.Fatalf("tool result: %s (%v)", got, err)
	}
	if result.Verdict != securityexperiment.ViolationObserved || result.EvidenceID == 0 {
		t.Fatalf("useful discovery failed: %s", got)
	}
	trace := experimentToolCall(t, worker.getSecurityExperiment(), map[string]any{"evidence_id": result.EvidenceID})
	if !strings.Contains(trace, "body_base64") || !strings.Contains(trace, "spec_fingerprint") {
		t.Fatal("full evidence unavailable through normal tool")
	}
	overview := planner.graphOverviewData()
	if overview["security_experiments"] == nil {
		t.Fatal("experiment result absent from planner's actual work view")
	}
	reported := experimentToolCall(t, worker.addFinding(), map[string]any{"vulnclass": "BOLA", "severity": "high", "summary": "verified identity isolation violation", "experiment_evidence_id": result.EvidenceID, "intent_id": intent})
	if !strings.HasPrefix(reported, "finding recorded:") || !strings.Contains(reported, "experiment_verified") {
		t.Fatalf("discovery did not reach finding registration: %s", reported)
	}
	accepted := experimentToolCall(t, planner.proveGoal(), map[string]any{"goal_id": goal, "evidence_id": result.EvidenceID})
	if !planner.GoalMet || !strings.Contains(accepted, "marked met") {
		t.Fatalf("qualified evidence rejected: %s", accepted)
	}
	if worker.Writes().Facts != 2 {
		t.Fatalf("new results not counted for settlement: %+v", worker.Writes())
	}
}

func TestSecurityExperimentToolCatalogAndNilContexts(t *testing.T) {
	want := map[string]string{"list_security_experiments": "planner", "run_security_experiment": "worker", "get_security_experiment": "planner"}
	for _, seed := range BuiltinToolSeeds() {
		if role, ok := want[seed.Key]; ok {
			found := false
			for _, bound := range seed.Agents {
				if bound == role {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s not bound to %s", seed.Key, role)
			}
			delete(want, seed.Key)
		}
		if strings.Contains(seed.Key, "configure_security_experiment") {
			t.Fatal("model can configure its own policy")
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing tools: %v", want)
	}
	ts := NewToolSet(nil, "")
	for _, tool := range []actool.CoreTool{ts.listSecurityExperiments(), ts.runSecurityExperiment(), ts.getSecurityExperiment()} {
		got := experimentToolCall(t, tool, map[string]any{"case_id": 1, "evidence_id": 1})
		if !strings.Contains(got, "任务上下文") {
			t.Fatalf("nil context not refused: %s", got)
		}
	}
}
