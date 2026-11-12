package db

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
)

func TestAuditGoalEditPreservesProofRequirement(t *testing.T) {
	_, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateGoalPayload(goal, "changed business requirement", ""); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(goal)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		CaseID int64 `json:"security_experiment_case_id"`
	}
	json.Unmarshal(n.Payload, &p)
	if p.CaseID != c.ID {
		t.Fatal("normal goal editing erased the experiment proof requirement")
	}
	plain, err := s.AddNode(KindFact, map[string]any{"summary": "model assertion"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ProveGoal(goal, plain); err == nil {
		t.Fatal("edited goal accepted an unverified fact")
	}
}

func TestAuditRuntimeRefreshFailureDoesNotProbeOrPass(t *testing.T) {
	_, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	s.SetExperimentStateObserver(func() error { return errors.New("runtime lifecycle unavailable") })
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err == nil || run == nil || run.ID == 0 || target.Calls.Load() != 0 {
		t.Fatal("failed lifecycle refresh did not preserve the durable unknown without probing")
	}
	if err := s.ProveGoal(goal, run.ID); err == nil {
		t.Fatal("unsettled observer failure completed the goal")
	}
	items, err := s.SecurityExperiments()
	if err != nil || len(items) != 1 || items[0]["verdict"] != "running" {
		t.Fatalf("unsettled start lost its explicit unknown: %v %v", items, err)
	}
}

func TestAuditCompletionSerializesWithReplacement(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	registerExperimentFinding(t, task, s, run.ID)
	if err := s.ProveGoal(goal, run.ID); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var replaceErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, replaceErr = s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = d.SetStatus(task.ID, "done") // Either ordering is valid; final state is not done.
	}()
	close(start)
	wg.Wait()
	if replaceErr != nil {
		t.Fatal(replaceErr)
	}
	row, err := d.GetTask(task.ID)
	if err != nil || row.Status == "done" || row.CompletedAt != nil {
		t.Fatalf("concurrent stale completion overrode a replacement case: %+v %v", row, err)
	}
	node, err := s.GetNode(goal)
	if err != nil || node.State != "open" {
		t.Fatalf("replacement goal is not open: %+v %v", node, err)
	}
}

func TestAuditGoalAggregationDoesNotSampleFirstThousand(t *testing.T) {
	d, _, s, _ := experimentDB(t)
	if _, err := d.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) SELECT $1,'goal','{"text":"completed legacy goal"}','met','human' FROM generate_series(1,1001)`, s.ID()); err != nil {
		t.Fatal(err)
	}
	met, count, err := s.AllGoalsMet()
	if err != nil || met || count != 1002 {
		t.Fatalf("goal aggregation lost the open goal: met=%v count=%d error=%v", met, count, err)
	}
}

func TestAuditUnknownCannotCompleteTask(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	if _, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec); err != nil {
		t.Fatal(err)
	}
	if err := d.SetStatus(task.ID, "done"); err == nil {
		t.Fatal("the final task-status writer accepted unknown experiment evidence")
	}
	if won, err := d.SetTerminalStatusGuarded(task.ID, "done"); err == nil && won {
		t.Fatal("guarded task completion bypassed the experiment proof")
	}
}

func TestAuditGoalProofRequiresRegisteredFinding(t *testing.T) {
	_, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ProveGoal(goal, run.ID); err == nil {
		t.Fatal("discovery goal completed while no finding was registered")
	}
}

func TestAuditSharedFindingWritersCannotOptOut(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	if _, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddNode(KindFinding, map[string]any{"summary": "unchecked"}, 9, "confirmed", "worker", nil); err == nil {
		t.Fatal("generic graph writer bypassed the finding gate")
	}
	fact, err := s.AddNode(KindFact, map[string]any{"summary": "ordinary fact"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][2]int64{{task.ID, 0}, {0, fact}, {task.ID, fact}} {
		if _, err := d.AddFinding(ids[0], ids[1], "BOLA", "unchecked", "high", "model assertion", "no proof", "worker", nil); err == nil {
			t.Fatalf("legacy standalone writer bypassed gate: %v", ids)
		}
	}
	if _, err := s.RecordFinding(t.Context(), RecordFindingInput{ExplorationID: s.ID(), Severity: "high", Summary: "task ID omitted"}); err == nil {
		t.Fatal("omitting task ID bypassed the shared gate")
	}
	if err := s.SetNodeState(goal, "met"); err == nil {
		t.Fatal("generic goal state writer bypassed proof")
	}
}

func TestAuditCompletionRechecksEvidenceAndReopens(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := registerExperimentFinding(t, task, s, run.ID)
	retry := registerExperimentFinding(t, task, s, run.ID)
	if retry.FindingID != f.FindingID || retry.NodeID != f.NodeID {
		t.Fatal("retry duplicated the same experiment discovery")
	}
	if err := s.ProveGoal(goal, f.NodeID); err != nil {
		t.Fatal(err)
	}
	if won, err := d.SetTerminalStatusGuarded(task.ID, "done"); err != nil || !won {
		t.Fatalf("valid discovery failed final completion: %v %v", won, err)
	}
	target.Expired.Store(true)
	unknown, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil || unknown.Result.Verdict != securityexperiment.PreconditionFailed {
		t.Fatalf("unknown control: %v %v", unknown, err)
	}
	row, err := d.GetTask(task.ID)
	if err != nil || row.Status == "done" || row.CompletedAt != nil || !row.Paused {
		t.Fatalf("new unknown retained completed task state: %+v %v", row, err)
	}
	if err := d.SetStatus(task.ID, "done"); err == nil {
		t.Fatal("stale completion flag overrode the new unknown")
	}
	// Emulate an old persisted/cache state: the final boundary must still verify
	// the actual current run, rather than trusting a goal's state label.
	if _, err := d.Exec(`UPDATE exploration_nodes SET state='met' WHERE id=$1`, goal); err != nil {
		t.Fatal(err)
	}
	if err := d.SetStatus(task.ID, "done"); err == nil {
		t.Fatal("state label alone passed final evidence validation")
	}
	if _, err := s.RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExperimentEvidenceID: run.ID}); err == nil {
		t.Fatal("old finding evidence bypassed newer unknown")
	}
}

func TestAuditPlanningViewDoesNotPublishStaleOrMissingProof(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertUnknown := func() {
		t.Helper()
		items, err := s.SecurityExperiments()
		if err != nil || len(items) != 1 || items[0]["verdict"] != securityexperiment.Inconclusive {
			t.Fatalf("invalid/missing evidence was hidden or published as positive: %v %v", items, err)
		}
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{security_experiment_run,result,observations,0,stored_sha256}','"broken"') WHERE id=$1`, run.ID); err != nil {
		t.Fatal(err)
	}
	assertUnknown()
	if err := s.UpdateGoalPayload(goal, "changed requirement", ""); err != nil {
		t.Fatal(err)
	}
	assertUnknown()
	if _, err := d.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	assertUnknown()
}

func TestAuditClosedFindingCannotProveOrResurrect(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	_, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := registerExperimentFinding(t, task, s, run.ID)
	if _, err := d.SetFindingStatus(f.FindingID, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	if err := s.ProveGoal(goal, run.ID); err == nil {
		t.Fatal("rejected finding completed discovery goal")
	}
	if _, err := s.RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExperimentEvidenceID: run.ID}); err == nil {
		t.Fatal("retry resurrected a rejected finding")
	}
}
