package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
)

// This deterministic workflow uses the real, persisted tool assembly and report
// writers. It does not simulate or evaluate a model choosing the tool sequence.
func TestAuditSecurityExperimentDiscoveryToReporterAndCompletion(t *testing.T) {
	oldAugment, oldResolve, oldPolicy := agent.ToolAugment, agent.ToolResolve, agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolAugment, agent.ToolResolve, agent.FindingTrafficBindingEnabled = oldAugment, oldResolve, oldPolicy
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := &Server{ctx: ctx, m: m, engine: NewEngine(m)}
	wireTools(m.pg, nil)
	s.seedOrchestrationTools()
	s.seedReporterAgent()
	wireAgentAugment(m.pg, t.TempDir(), s.hostTools)
	task, err := m.CreateTask("deterministic discovery workflow", "find isolation violation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer m.pg.DeleteTask(taskID)
	goal, err := task.Store.AddGoal(map[string]any{"text": "find isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.AddIntent(map[string]any{"summary": "verify operator experiment"}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	target, spec := experimenttest.New(t)
	c, err := task.Store.CreateSecurityExperimentCase(ctx, taskID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	worker := agent.NewToolSet(task.Store, "worker")
	worker.SetTaskID(taskID)
	worker.SetOwnerNode(intent)
	notices := 0
	worker.SetNotifyFinding(func(int64, string) { notices++ })
	tools, _, cleanup := agent.AugmentTools(ctx, "worker", worker.WorkerTools())
	defer cleanup()
	if err := m.SetTaskStatus(task.ID, "done"); err == nil {
		t.Fatal("manager completed unknown experiment")
	}
	result := workflowCall(t, ctx, workflowTool(t, tools, "run_security_experiment"), map[string]any{"case_id": c.ID}, false)
	var runResult struct {
		ID int64 `json:"evidence_id"`
	}
	if err := json.Unmarshal([]byte(result), &runResult); err != nil || runResult.ID == 0 {
		t.Fatal(result, err)
	}
	reported := workflowCall(t, ctx, workflowTool(t, tools, "report_finding"), map[string]any{"experiment_evidence_id": runResult.ID, "intent_id": intent, "vulnclass": "BOLA", "severity": "high", "summary": "observed isolation violation", "evidence": "MODEL TEXT MUST NOT REPLACE EXECUTOR EVIDENCE"}, false)
	var f db.RecordedFinding
	if err := json.Unmarshal([]byte(strings.SplitN(reported, "\n", 2)[1]), &f); err != nil {
		t.Fatal(err)
	}
	if notices != 1 || f.ExperimentEvidenceID != runResult.ID {
		t.Fatal("normal finding notification or proof binding missing")
	}
	triggers, err := m.pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	triggered := false
	for _, trigger := range triggers {
		if trigger.Enabled && trigger.OnToolCall && contains(trigger.ToolNames, "report_finding") {
			triggered = true
		}
	}
	if !triggered {
		t.Fatal("report_finding is not connected to the normal reporter trigger")
	}
	reporterTools, _, closeReporter := agent.AugmentTools(ctx, "reporter", nil)
	defer closeReporter()
	detail := workflowCall(t, ctx, workflowTool(t, reporterTools, "get_task_node_detail"), map[string]any{"task_id": task.ID, "id": f.NodeID}, false)
	var node struct {
		Payload struct {
			Evidence struct {
				POC string `json:"poc"`
			} `json:"evidence"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(detail), &node); err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		Case db.SecurityExperimentCase `json:"case"`
		Run  db.SecurityExperimentRun  `json:"run"`
	}
	if err := json.Unmarshal([]byte(node.Payload.Evidence.POC), &evidence); err != nil {
		t.Fatalf("reporter did not receive executor evidence: %v", err)
	}
	if err := securityexperiment.VerifyViolation(evidence.Case.Spec, evidence.Run.Result); err != nil || evidence.Run.ID != runResult.ID {
		t.Fatalf("reporter input cannot substantiate the discovery: %v", err)
	}
	if strings.Contains(detail, "MODEL TEXT MUST NOT") || strings.Contains(detail, os.Getenv(spec.Owner.CredentialEnv)) || strings.Contains(detail, os.Getenv(spec.Other.CredentialEnv)) {
		t.Fatal("reporter received substituted evidence or raw credentials")
	}
	list := workflowCall(t, ctx, s.toolListTaskFindings(), map[string]any{"task_id": task.ID}, false)
	if !strings.Contains(list, fmt.Sprint(f.FindingID)) || !strings.Contains(list, "experiment_evidence_id") {
		t.Fatal("discovery missing from ordinary findings list")
	}
	report := fmt.Sprintf("## Local isolation violation\n\nExecutor run %d verified two owner baselines and two other-identity disclosures. Scope: the configured object and identities. Human triage is pending.", evidence.Run.ID)
	workflowCall(t, ctx, workflowTool(t, reporterTools, "update_finding_report"), map[string]any{"finding_id": f.NodeID, "report": report}, false)
	stored, err := m.pg.GetFinding(f.FindingID)
	if err != nil || stored.Report != report || stored.Status != db.FindingPending || stored.Evidence != node.Payload.Evidence.POC {
		t.Fatalf("ordinary report storage or separate triage boundary failed: %v", err)
	}
	planner := agent.NewToolSet(task.Store, "planner")
	planner.SetTaskID(taskID)
	plannerTools, _, closePlanner := agent.AugmentTools(ctx, "planner", planner.PlannerTools())
	defer closePlanner()
	workflowCall(t, ctx, workflowTool(t, plannerTools, "prove_goal"), map[string]any{"goal_id": goal, "evidence_id": f.NodeID}, false)
	if !planner.GoalMet {
		t.Fatal("registered, verified discovery did not complete the goal")
	}
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	// A later unknown must invalidate completion, even with a stale planner flag.
	target.Expired.Store(true)
	unknown := workflowCall(t, ctx, workflowTool(t, tools, "run_security_experiment"), map[string]any{"case_id": c.ID}, false)
	lifecycle := task.lifecycleSnapshot()
	if lifecycle.Status == "done" || lifecycle.CompletedAt != 0 || !lifecycle.Paused || s.resolvedTaskStatus(task) != "paused" {
		t.Fatal("worker experiment reopened persisted state but UI/runtime still published completion")
	}
	if err := json.Unmarshal([]byte(unknown), &runResult); err != nil {
		t.Fatal(err)
	}
	workflowCall(t, ctx, workflowTool(t, tools, "report_finding"), map[string]any{"experiment_evidence_id": runResult.ID, "vulnclass": "BOLA", "severity": "high", "summary": "unknown must not pass"}, true)
	if err := m.SetTaskStatus(task.ID, "done"); err == nil {
		t.Fatal("stale planner completion overrode new unknown")
	}
	if notices != 1 || target.Calls.Load() != 12 || s.engine.ActiveLLMCalls(task.ID) != 0 {
		t.Fatal("unknown wrote/announced a finding, replayed probes, or started models")
	}
	var calls int
	if err := m.pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1`, task.ID).Scan(&calls); err != nil || calls != 0 {
		t.Fatalf("model use occurred: %d %v", calls, err)
	}
}
