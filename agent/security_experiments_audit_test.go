package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/experimenttest"
	actool "github.com/Autumn-27/norma/tool"
)

func TestAuditFindingCannotBypassUnknownExperiment(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("audit finding gate", "discover isolation violation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	s := d.Exploration(task.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "discover isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	target, spec := experimenttest.New(t)
	target.Expired.Store(true)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(s, "worker")
	worker.SetTaskID(task.ID)
	for _, proof := range []int64{0, run.ID} {
		got := experimentToolCall(t, worker.addFinding(), map[string]any{"vulnclass": "BOLA", "severity": "high", "summary": "model says verified", "experiment_evidence_id": proof})
		if strings.HasPrefix(got, "finding recorded:") {
			t.Fatalf("unknown bypassed report_finding gate: %s", got)
		}
	}
}

func TestAuditOldSchemasKeepExperimentEvidenceParameter(t *testing.T) {
	oldResolve, oldAugment, oldPolicy := ToolResolve, ToolAugment, FindingTrafficBindingEnabled
	t.Cleanup(func() { ToolResolve, ToolAugment, FindingTrafficBindingEnabled = oldResolve, oldAugment, oldPolicy })
	ToolAugment = nil
	FindingTrafficBindingEnabled = func() bool { return false }
	worker := NewToolSet(nil, "worker")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		return []actool.CoreTool{DecorateTool(base[0], "CUSTOM", obj(map[string]any{"summary": str("old schema")}))}
	}
	tools, _, cleanup := AugmentTools(t.Context(), "worker", []actool.CoreTool{worker.addFinding()})
	cleanup()
	raw, _ := json.Marshal(tools[0].InputSchema())
	if !strings.Contains(string(raw), "experiment_evidence_id") || !strings.HasPrefix(tools[0].Description(), "CUSTOM") {
		t.Fatal("persisted schema hid evidence parameter or custom configuration was replaced")
	}
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	tools, _, cleanup = AugmentTools(t.Context(), "worker", []actool.CoreTool{worker.addFinding()})
	cleanup()
	if len(tools) != 0 {
		t.Fatal("schema upgrade reintroduced a disabled tool")
	}
}

func TestAuditFindingBindsActualExperimentEvidence(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("audit discovery chain", "discover isolation violation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	s := d.Exploration(task.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "discover isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(s, "worker")
	worker.SetTaskID(task.ID)
	got := experimentToolCall(t, worker.addFinding(), map[string]any{"vulnclass": "RCE", "name": "fabricated RCE", "severity": "high", "summary": "fabricated RCE", "evidence": "model-authored text", "experiment_evidence_id": run.ID})
	parts := strings.SplitN(got, "\n", 2)
	if len(parts) != 2 {
		t.Fatalf("valid discovery could not be recorded: %s", got)
	}
	var f struct {
		NodeID string `json:"finding_node_id"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &f); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListByKind("finding", 10)
	if err != nil || len(findings) != 1 {
		t.Fatalf("finding record missing: %v %v", findings, err)
	}
	var payload struct {
		RunID int64 `json:"experiment_evidence_id"`
	}
	json.Unmarshal(findings[0].Payload, &payload)
	if payload.RunID != run.ID {
		t.Fatal("finding dropped the executor-owned evidence binding")
	}
	findingID, err := d.FindingIDByNodeID(findings[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetFinding(findingID)
	if err != nil || stored.VulnClass != "BOLA" || stored.Name != spec.Name || strings.Contains(stored.Summary, "fabricated RCE") {
		t.Fatal("valid isolation evidence was used to promote an unrelated model-authored vulnerability claim")
	}
	if stored.VerificationStatus != "experiment_verified" || stored.VerificationAttemptID != 0 {
		t.Fatal("experiment proof was confused with the separate HTTP attempt namespace")
	}
}
