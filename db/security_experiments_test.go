package db

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
)

func experimentDB(t *testing.T) (*DB, *Task, *ExplorationStore, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("experiment test database unavailable: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	// The archive subsystem expects its empty metering/recording tables to be
	// initialized, as they are during normal server startup. No model is called.
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("security experiment acceptance", "verify isolation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	s := d.Exploration(task.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "demonstrate owner/other isolation violation"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	return d, task, s, goal
}

func registerExperimentFinding(t *testing.T, task *Task, s *ExplorationStore, runID int64) *RecordedFinding {
	t.Helper()
	f, err := s.RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExperimentEvidenceID: runID, VulnClass: "BOLA", Severity: "high", Summary: "observed isolation violation", Worker: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSecurityExperimentDurableExecutionAndGoalGate(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.AddNode(KindFact, map[string]any{"summary": "the model says verified", "confidence": "observed"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ProveGoal(goal, plain); err == nil {
		t.Fatal("model-authored fact completed an experiment goal")
	}
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if run.Result.Verdict != securityexperiment.ViolationObserved || target.Calls.Load() != 10 {
		t.Fatalf("valid discovery failed: %+v", run)
	}
	for _, o := range run.Result.Observations {
		body, err := base64.StdEncoding.DecodeString(o.Body)
		if err != nil || len(body) == 0 {
			t.Fatalf("evidence body unavailable: %v", err)
		}
	}
	// A fresh DB handle reads the actual persisted result, not an in-memory cache.
	d2, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	stored, err := d2.Exploration(task.ExplorationID).SecurityExperimentEvidence(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Result.SpecFingerprint != spec.Fingerprint() || stored.FinishedAt == nil || len(stored.Result.Observations) != 10 {
		t.Fatalf("incomplete durable evidence: %+v", stored)
	}
	registerExperimentFinding(t, task, s, run.ID)
	if err := s.ProveGoal(goal, run.ID); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(goal)
	if n.State != "met" {
		t.Fatal("qualified proof did not complete goal")
	}
	items, err := s.SecurityExperiments()
	if err != nil || len(items) != 1 || items[0]["verdict"] != securityexperiment.ViolationObserved {
		t.Fatalf("planning view: %v %v", items, err)
	}
	// Rebinding explicitly reopens the goal and invalidates the old proof.
	target.Fixed.Store(true)
	c2, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = s.GetNode(goal)
	if n.State != "open" {
		t.Fatal("replacement did not reopen goal")
	}
	if err := s.ProveGoal(goal, run.ID); err == nil {
		t.Fatal("old case proof accepted")
	}
	if _, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0); err == nil {
		t.Fatal("stale case executed")
	}
	fixed, err := s.RunSecurityExperiment(t.Context(), task.ID, c2.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fixed.Result.Verdict != securityexperiment.NotReproduced {
		t.Fatalf("fixed control: %+v", fixed)
	}
	if err := s.ProveGoal(goal, fixed.ID); err == nil {
		t.Fatal("negative outcome completed a discovery goal")
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND origin=$2 AND kind='fact'`, s.ID(), securityExperimentOrigin).Scan(&count); err != nil || count != 2 {
		t.Fatalf("history lost: %d %v", count, err)
	}
}

func TestSecurityExperimentUnknownWrongTaskAndChangedGoal(t *testing.T) {
	_, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	target.Expired.Store(true)
	run, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if run.Result.Verdict != securityexperiment.PreconditionFailed {
		t.Fatalf("expired identity treated as a finding: %+v", run)
	}
	if err := s.ProveGoal(goal, run.ID); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	if _, err := s.RunSecurityExperiment(t.Context(), task.ID+999999, c.ID, 0); err == nil {
		t.Fatal("wrong task accepted")
	}
	if _, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, goal); err == nil {
		t.Fatal("non-intent parent accepted")
	}
	raw, _ := json.Marshal(map[string]any{"security_experiment_run": SecurityExperimentRun{CaseID: c.ID, GoalID: goal, Result: securityexperiment.Result{Verdict: "running"}}})
	var id int64
	if err := s.db.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact',$2,'confirmed',$3) RETURNING id`, s.expID, string(raw), securityExperimentOrigin).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := s.ProveGoal(goal, id); err == nil {
		t.Fatal("interrupted run accepted as completed")
	}
	if _, err := s.db.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{text}','"changed business requirement"') WHERE id=$1`, goal); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0); err == nil {
		t.Fatal("changed goal kept old experiment authority")
	}
	if target.Calls.Load() != 2 {
		t.Fatalf("invalid preconditions caused extra probes: %d", target.Calls.Load())
	}
}

func TestSecurityExperimentLatestEvidenceAndArchiveRestore(t *testing.T) {
	d, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	c, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	positive, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	registerExperimentFinding(t, task, s, positive.ID)
	if err := s.ProveGoal(goal, positive.ID); err != nil {
		t.Fatal(err)
	}
	target.Fixed.Store(true)
	negative, err := s.RunSecurityExperiment(t.Context(), task.ID, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if negative.Result.Verdict != securityexperiment.NotReproduced {
		t.Fatalf("fixed control: %+v", negative)
	}
	n, _ := s.GetNode(goal)
	if n.State != "open" {
		t.Fatal("a fresh test did not reopen the old completed goal")
	}
	if err := s.ProveGoal(goal, positive.ID); err == nil {
		t.Fatal("older positive evidence overrode a newer negative test")
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE id=$1`, archive.ID) })
	claimed, err := d.ClaimTaskArchiveJob(t.Context())
	if err != nil || claimed == nil || claimed.ID != archive.ID {
		t.Fatalf("archive claim: %v %v", claimed, err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/experiment-archive-fixture.tar.zst", "fixture", 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	restored, err := s.SecurityExperimentEvidence(positive.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := securityexperiment.VerifyViolation(spec, restored.Result); err != nil {
		t.Fatalf("archive changed evidence bytes or binding: %v", err)
	}
	if err := s.ProveGoal(goal, positive.ID); err == nil {
		t.Fatal("archive restore discarded the newer contrary evidence")
	}
	if target.Calls.Load() != 20 {
		t.Fatal("restoring or verifying evidence replayed target traffic")
	}
}

func TestSecurityExperimentLateResultCannotProveReboundGoal(t *testing.T) {
	_, task, s, goal := experimentDB(t)
	target, spec := experimenttest.New(t)
	first, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	target.BeforeProbe = func() {
		once.Do(func() {
			close(started)
			select {
			case <-release:
			case <-t.Context().Done():
			}
		})
	}
	type outcome struct {
		run *SecurityExperimentRun
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		run, err := s.RunSecurityExperiment(t.Context(), task.ID, first.ID, 0)
		done <- outcome{run, err}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("experiment did not reach probe")
	}
	second, err := s.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.run == nil || got.run.Result.Verdict != securityexperiment.ViolationObserved {
			t.Fatalf("late run was lost: %+v %v", got.run, got.err)
		}
		if err := s.ProveGoal(goal, got.run.ID); err == nil {
			t.Fatal("late evidence completed the newly rebound goal")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("experiment did not settle")
	}
	items, err := s.SecurityExperiments()
	if err != nil || len(items) != 1 || items[0]["case_id"] != second.ID || items[0]["verdict"] != "not_run" {
		t.Fatalf("current case was overwritten by late evidence: %v %v", items, err)
	}
}
