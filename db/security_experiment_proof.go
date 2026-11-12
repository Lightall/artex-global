package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Autumn-27/artex/securityexperiment"
)

func hasExperimentGoalsTx(tx *sql.Tx, expID int64) (bool, error) {
	var has bool
	err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND payload ? 'security_experiment_case_id')`, expID).Scan(&has)
	return has, err
}

// All proof consumers run under WithEvidenceTx and lock the task before goals.
// A finding ID here is a graph node ID, matching prove_goal's existing contract.
func experimentProofTx(tx *sql.Tx, expID, evidenceID int64) (*SecurityExperimentCase, *SecurityExperimentRun, error) {
	var kind, origin, state string
	var raw []byte
	if err := tx.QueryRow(`SELECT kind,origin,state,payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, evidenceID, expID).Scan(&kind, &origin, &state, &raw); err != nil {
		return nil, nil, err
	}
	if kind == KindFinding {
		var p struct {
			RunID int64 `json:"experiment_evidence_id"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || p.RunID <= 0 {
			return nil, nil, errors.New("finding has no executor-owned experiment evidence")
		}
		evidenceID = p.RunID
		if err := tx.QueryRow(`SELECT kind,origin,state,payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, evidenceID, expID).Scan(&kind, &origin, &state, &raw); err != nil {
			return nil, nil, err
		}
	}
	if kind != KindFact || origin != securityExperimentOrigin || state != "confirmed" {
		return nil, nil, errors.New("proof must be a current executor-owned experiment run")
	}
	var rp struct {
		Run *SecurityExperimentRun `json:"security_experiment_run"`
	}
	if err := json.Unmarshal(raw, &rp); err != nil || rp.Run == nil {
		return nil, nil, errors.New("invalid persisted experiment run")
	}
	run := rp.Run
	run.ID = evidenceID
	if run.FinishedAt == nil {
		return nil, nil, errors.New("experiment has not settled; evidence remains unknown")
	}
	if err := tx.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='hint' AND origin=$3 AND state='active'`, run.CaseID, expID, securityExperimentOrigin).Scan(&raw); err != nil {
		return nil, nil, err
	}
	var cp struct {
		Case *SecurityExperimentCase `json:"security_experiment_case"`
	}
	if err := json.Unmarshal(raw, &cp); err != nil || cp.Case == nil {
		return nil, nil, errors.New("invalid operator experiment case")
	}
	c := cp.Case
	c.ID = run.CaseID
	if c.GoalID != run.GoalID {
		return nil, nil, errors.New("experiment goal/evidence mismatch")
	}
	if err := tx.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, c.GoalID, expID).Scan(&raw); err != nil {
		return nil, nil, err
	}
	var goal struct {
		CaseID int64 `json:"security_experiment_case_id"`
	}
	if err := json.Unmarshal(raw, &goal); err != nil || goal.CaseID != c.ID || goalFingerprint(raw) != c.GoalFingerprint {
		return nil, nil, errors.New("experiment case or goal binding is stale")
	}
	if err := securityexperiment.VerifyViolation(c.Spec, run.Result); err != nil {
		return nil, nil, fmt.Errorf("experiment evidence does not prove a violation: %w", err)
	}
	var latest int64
	if err := tx.QueryRow(`SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND origin=$2 AND payload->'security_experiment_run'->>'case_id'=$3 ORDER BY id DESC LIMIT 1`, expID, securityExperimentOrigin, fmt.Sprint(c.ID)).Scan(&latest); err != nil {
		return nil, nil, err
	}
	if latest != run.ID {
		return nil, nil, errors.New("newer experiment evidence exists; old evidence is not current proof")
	}
	return c, run, nil
}

func registeredExperimentFindingTx(tx *sql.Tx, taskID, expID, runID int64) (*RecordedFinding, error) {
	var out RecordedFinding
	var status string
	err := tx.QueryRow(`SELECT f.id,n.id,COALESCE(f.status,'pending'),f.summary FROM findings f
JOIN exploration_nodes n ON n.id=f.node_id AND n.exploration_id=$1 AND n.kind='finding' AND n.state='confirmed'
WHERE f.task_id=$2 AND n.payload->>'experiment_evidence_id'=$3 ORDER BY f.id LIMIT 1`, expID, taskID, fmt.Sprint(runID)).Scan(&out.FindingID, &out.NodeID, &status, &out.Summary)
	if err != nil {
		return nil, err
	}
	if status != FindingPending && status != FindingInProgress && status != FindingConfirmed {
		return nil, errors.New("registered finding is closed or rejected; it cannot establish current discovery")
	}
	out.ExperimentEvidenceID = runID
	out.VerificationStatus = "experiment_verified"
	return &out, nil
}

func experimentFindingEvidence(c *SecurityExperimentCase, run *SecurityExperimentRun) string {
	// The model's prose is not substituted for executor observations. This full
	// record is also what the existing reporter node-detail tool actually reads.
	raw, _ := json.MarshalIndent(map[string]any{"source": securityExperimentOrigin, "case": c, "run": run}, "", "  ")
	return string(raw)
}

// Final completion is a shared database boundary, not a cached planner flag.
func validateExperimentCompletionTx(tx *sql.Tx, taskID int64) error {
	var expID int64
	if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&expID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Preserve the legacy status writer's no-op for deleted tasks.
		}
		return err
	}
	rows, err := tx.Query(`SELECT id,state FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND payload ? 'security_experiment_case_id' ORDER BY id FOR UPDATE`, expID)
	if err != nil {
		return err
	}
	var goals []int64
	for rows.Next() {
		var id int64
		var state string
		if err := rows.Scan(&id, &state); err != nil {
			rows.Close()
			return err
		}
		if state != "met" {
			rows.Close()
			return errors.New("experiment-bound goal is not proven; task cannot complete")
		}
		goals = append(goals, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, goalID := range goals {
		var runID int64
		if err := tx.QueryRow(`SELECT src_id FROM exploration_edges WHERE exploration_id=$1 AND dst_id=$2 AND rel=$3 ORDER BY src_id DESC LIMIT 1`, expID, goalID, RelProves).Scan(&runID); err != nil {
			return fmt.Errorf("goal %d has no persisted proof: %w", goalID, err)
		}
		c, run, err := experimentProofTx(tx, expID, runID)
		if err != nil {
			return err
		}
		if c.GoalID != goalID {
			return errors.New("task completion proof belongs to another goal")
		}
		if _, err := registeredExperimentFindingTx(tx, taskID, expID, run.ID); err != nil {
			return fmt.Errorf("discovery has not been registered as a finding: %w", err)
		}
	}
	return nil
}

func lockExplorationTaskTx(tx *sql.Tx, expID int64) (int64, error) {
	var taskID int64
	err := tx.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, expID).Scan(&taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return taskID, LockTaskEvidenceTx(tx, taskID)
}

func reopenExperimentTaskTx(tx *sql.Tx, taskID int64) error {
	_, err := tx.Exec(`UPDATE tasks SET status='created',paused=true,completed_at=NULL WHERE id=$1 AND status='done'`, taskID)
	return err
}
