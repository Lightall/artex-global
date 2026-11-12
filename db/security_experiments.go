package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/securityexperiment"
)

const securityExperimentOrigin = "security-experiment"

type SecurityExperimentCase struct {
	ID              int64                   `json:"id,string"`
	GoalID          int64                   `json:"goal_id,string"`
	GoalFingerprint string                  `json:"goal_fingerprint"`
	Spec            securityexperiment.Spec `json:"spec"`
}

type SecurityExperimentRun struct {
	ID         int64                     `json:"id,string"`
	CaseID     int64                     `json:"case_id,string"`
	GoalID     int64                     `json:"goal_id,string"`
	StartedAt  time.Time                 `json:"started_at"`
	FinishedAt *time.Time                `json:"finished_at,omitempty"`
	Result     securityexperiment.Result `json:"result"`
}

func goalFingerprint(payload []byte) string {
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(payload, &p)
	h := sha256.Sum256([]byte(p.Text))
	return hex.EncodeToString(h[:])
}

// CreateSecurityExperimentCase is an operator-only configuration path. Existing
// graph nodes carry cases and immutable run history through ordinary archives.
// Replacing a case reopens its goal; the previous case and evidence remain intact.
func (s *ExplorationStore) CreateSecurityExperimentCase(ctx context.Context, taskID, goalID int64, spec securityexperiment.Spec) (out *SecurityExperimentCase, err error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := s.lockExperimentTask(tx, taskID); err != nil {
			return err
		}
		var config []byte
		if err := tx.QueryRowContext(ctx, `SELECT verification_config FROM tasks WHERE id=$1`, taskID).Scan(&config); err != nil {
			return err
		}
		var existing struct {
			Cases []json.RawMessage `json:"cases"`
		}
		if err := json.Unmarshal(config, &existing); err != nil {
			return err
		}
		if len(existing.Cases) > 0 {
			return errors.New("task already uses HTTP verification; configure security experiments in a separate task")
		}
		var payload []byte
		if err := tx.QueryRowContext(ctx, `SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, goalID, s.expID).Scan(&payload); err != nil {
			return err
		}
		out = &SecurityExperimentCase{GoalID: goalID, GoalFingerprint: goalFingerprint(payload), Spec: spec}
		raw, _ := json.Marshal(map[string]any{"summary": spec.Name, "text": "Operator-configured identity/object isolation experiment", "security_experiment_case": out})
		if err := tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'hint',$2,8,'active',$3) RETURNING id`, s.expID, string(raw), securityExperimentOrigin).Scan(&out.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=jsonb_set(payload,'{security_experiment_case_id}',to_jsonb($1::bigint)),state='open',content_version=content_version+1 WHERE id=$2 AND exploration_id=$3`, out.ID, goalID, s.expID)
		if err != nil {
			return err
		}
		return reopenExperimentTaskTx(tx, taskID)
	})
	if err == nil {
		err = s.notifyExperimentState()
	}
	return
}

func (s *ExplorationStore) lockExperimentTask(tx *sql.Tx, taskID int64) error {
	if taskID <= 0 {
		return errors.New("a concrete task is required")
	}
	if err := LockTaskEvidenceTx(tx, taskID); err != nil {
		return err
	}
	var expID int64
	if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, taskID).Scan(&expID); err != nil {
		return err
	}
	if expID != s.expID {
		return errors.New("experiment task/exploration mismatch")
	}
	return nil
}

func (s *ExplorationStore) SecurityExperimentCase(id int64) (*SecurityExperimentCase, error) {
	n, err := s.GetNode(id)
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != KindHint || n.Origin != securityExperimentOrigin {
		return nil, errors.New("not an operator-configured experiment case in this task")
	}
	var p struct {
		Case *SecurityExperimentCase `json:"security_experiment_case"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil || p.Case == nil {
		return nil, errors.New("invalid experiment case")
	}
	p.Case.ID = n.ID
	if err := p.Case.Spec.Validate(); err != nil {
		return nil, err
	}
	return p.Case, nil
}

func (s *ExplorationStore) SecurityExperimentRun(id int64) (*SecurityExperimentRun, error) {
	n, err := s.GetNode(id)
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != KindFact || n.Origin != securityExperimentOrigin {
		return nil, errors.New("not an executor-owned experiment run in this task")
	}
	var p struct {
		Run *SecurityExperimentRun `json:"security_experiment_run"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil || p.Run == nil {
		return nil, errors.New("invalid experiment run")
	}
	p.Run.ID = n.ID
	return p.Run, nil
}

// SecurityExperiments returns current cases with the latest scoped outcome. It
// never turns "not reproduced" into a statement about the whole asset.
func (s *ExplorationStore) SecurityExperiments() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT g.id,g.payload,c.id,c.payload,r.id,r.payload,r.state FROM exploration_nodes g
LEFT JOIN exploration_nodes c ON c.id::text=g.payload->>'security_experiment_case_id' AND c.exploration_id=g.exploration_id AND c.kind='hint' AND c.origin=$2 AND c.state='active'
LEFT JOIN LATERAL (SELECT id,payload,state FROM exploration_nodes WHERE exploration_id=g.exploration_id AND kind='fact' AND origin=$2 AND payload->'security_experiment_run'->>'case_id'=c.id::text ORDER BY id DESC LIMIT 1) r ON true
WHERE g.exploration_id=$1 AND g.kind='goal' AND g.payload ? 'security_experiment_case_id' ORDER BY g.id`, s.expID, securityExperimentOrigin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var goalID int64
		var goalRaw, caseRaw, runRaw []byte
		var id, runID sql.NullInt64
		var runState sql.NullString
		if err := rows.Scan(&goalID, &goalRaw, &id, &caseRaw, &runID, &runRaw, &runState); err != nil {
			return nil, err
		}
		var cp struct {
			Case *SecurityExperimentCase `json:"security_experiment_case"`
		}
		item := map[string]any{"goal_id": goalID, "verdict": securityexperiment.Inconclusive, "scope": "configured identities, object and observed business state only"}
		if !id.Valid || json.Unmarshal(caseRaw, &cp) != nil || cp.Case == nil {
			item["reason"] = "operator case is missing or unreadable; requirement remains unknown"
			out = append(out, item)
			continue
		}
		c := cp.Case
		item["case_id"], item["name"], item["origin"], item["resource_path"], item["policy_source"] = id.Int64, c.Spec.Name, c.Spec.Origin, c.Spec.ResourcePath, c.Spec.PolicySource
		if c.GoalID != goalID || c.GoalFingerprint != goalFingerprint(goalRaw) || c.Spec.Validate() != nil {
			item["reason"] = "operator case is stale; configure the current goal before using its result"
			out = append(out, item)
			continue
		}
		item["verdict"] = "not_run"
		if runID.Valid {
			var rp struct {
				Run *SecurityExperimentRun `json:"security_experiment_run"`
			}
			item["run_id"] = runID.Int64
			if json.Unmarshal(runRaw, &rp) != nil || rp.Run == nil || rp.Run.CaseID != id.Int64 || rp.Run.GoalID != goalID || runState.String != "confirmed" {
				item["verdict"], item["reason"] = securityexperiment.Inconclusive, "persisted run is missing, invalid or dismissed"
			} else if rp.Run.FinishedAt == nil {
				item["verdict"], item["reason"] = "running", "execution has not durably settled; remains unknown"
			} else {
				item["verdict"], item["reason"] = rp.Run.Result.Verdict, rp.Run.Result.Reason
				if rp.Run.Result.SpecFingerprint != c.Spec.Fingerprint() {
					item["verdict"], item["reason"] = securityexperiment.Inconclusive, "run/configuration fingerprint mismatch"
				} else if rp.Run.Result.Verdict == securityexperiment.ViolationObserved {
					if err := securityexperiment.VerifyViolation(c.Spec, rp.Run.Result); err != nil {
						item["verdict"], item["reason"] = securityexperiment.Inconclusive, "persisted proof failed verification: "+err.Error()
					}
				}
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *ExplorationStore) RunSecurityExperiment(ctx context.Context, taskID, caseID, intentID int64) (*SecurityExperimentRun, error) {
	c, err := s.SecurityExperimentCase(caseID)
	if err != nil {
		return nil, err
	}
	out := &SecurityExperimentRun{CaseID: caseID, GoalID: c.GoalID, StartedAt: time.Now().UTC(), Result: securityexperiment.Result{SpecFingerprint: c.Spec.Fingerprint(), Verdict: "running", Reason: "execution has not completed", Observations: []securityexperiment.Observation{}}}
	payload := func() string {
		confidence := "inferred"
		if out.Result.Verdict == securityexperiment.ViolationObserved || out.Result.Verdict == securityexperiment.NotReproduced {
			confidence = "observed"
		}
		raw, _ := json.Marshal(map[string]any{"summary": c.Spec.Name + ": " + out.Result.Verdict, "detail": out.Result.Reason, "confidence": confidence, "security_experiment_run": out})
		return string(raw)
	}
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := s.lockExperimentTask(tx, taskID); err != nil {
			return err
		}
		if err := s.checkExperimentBindingTx(tx, c); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE exploration_nodes SET state='open',content_version=content_version+1 WHERE id=$1 AND exploration_id=$2 AND state='met'`, c.GoalID, s.expID); err != nil {
			return err
		}
		if err := reopenExperimentTaskTx(tx, taskID); err != nil {
			return err
		}
		if intentID > 0 {
			var ok bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, intentID, s.expID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return errors.New("intent must belong to this task")
			}
		}
		if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'fact',$2,8,'confirmed',$3) RETURNING id`, s.expID, payload(), securityExperimentOrigin).Scan(&out.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, s.expID, out.ID, RelDerivedFrom, caseID); err != nil {
			return err
		}
		if intentID > 0 {
			_, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, s.expID, intentID, RelYields, out.ID)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.notifyExperimentState(); err != nil {
		return out, fmt.Errorf("experiment start was persisted but runtime lifecycle refresh failed: %w", err)
	}
	out.Result = (securityexperiment.Runner{}).Run(ctx, c.Spec)
	finished := time.Now().UTC()
	out.FinishedAt = &finished
	// Cancellation still leaves a durable inconclusive result. Archive/deletion
	// races may prevent settlement, in which case the persisted running row stays unknown.
	settle, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err = s.db.WithEvidenceTx(settle, func(tx *sql.Tx) error {
		if err := s.lockExperimentTask(tx, taskID); err != nil {
			return err
		}
		_, err := tx.ExecContext(settle, `UPDATE exploration_nodes SET payload=$1,content_version=content_version+1 WHERE id=$2 AND exploration_id=$3 AND origin=$4`, payload(), out.ID, s.expID, securityExperimentOrigin)
		return err
	})
	return out, err
}

func (s *ExplorationStore) checkExperimentBindingTx(tx *sql.Tx, c *SecurityExperimentCase) error {
	var raw []byte
	if err := tx.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, c.GoalID, s.expID).Scan(&raw); err != nil {
		return err
	}
	var p struct {
		CaseID int64 `json:"security_experiment_case_id"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if p.CaseID != c.ID || goalFingerprint(raw) != c.GoalFingerprint {
		return errors.New("experiment case is stale; the operator must configure a case for the current goal and conditions")
	}
	return nil
}

// ProveGoal serializes the proof with operator case replacement. Legacy goals
// keep their existing semantics; an experiment-bound goal requires its current,
// executor-owned, completed violation observation AND a registered finding.
func (s *ExplorationStore) ProveGoal(goalID, evidenceID int64) error {
	return s.db.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		taskID, err := lockExplorationTaskTx(tx, s.expID)
		if err != nil {
			return err
		}
		var raw []byte
		if err := tx.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, goalID, s.expID).Scan(&raw); err != nil {
			return err
		}
		var goal map[string]json.RawMessage
		if err := json.Unmarshal(raw, &goal); err != nil {
			return err
		}
		if _, bound := goal["security_experiment_case_id"]; bound {
			c, run, err := experimentProofTx(tx, s.expID, evidenceID)
			if err != nil {
				return err
			}
			if c.GoalID != goalID {
				return errors.New("experiment proof belongs to another goal")
			}
			if _, err := registeredExperimentFindingTx(tx, taskID, s.expID, run.ID); err != nil {
				return fmt.Errorf("report_finding must register this verified experiment before completing the goal: %w", err)
			}
			evidenceID = run.ID // Canonical proof, independent of the caller's node type.
		}
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.expID, evidenceID, RelProves, goalID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE exploration_nodes SET state='met',content_version=content_version+1 WHERE id=$1 AND exploration_id=$2`, goalID, s.expID); err != nil {
			return err
		}
		return nil
	})
}

func (s *ExplorationStore) AllGoalsMet() (bool, int, error) {
	var count, open int
	err := s.db.QueryRow(`SELECT count(*),count(*) FILTER (WHERE state <> 'met') FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal'`, s.expID).Scan(&count, &open)
	return count > 0 && open == 0, count, err
}

func (s *ExplorationStore) HasSecurityExperimentGoals() (bool, error) {
	var ok bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND payload ? 'security_experiment_case_id')`, s.expID).Scan(&ok)
	return ok, err
}

// SecurityExperimentEvidence returns immutable observations for an existing run.
func (s *ExplorationStore) SecurityExperimentEvidence(id int64) (*SecurityExperimentRun, error) {
	run, err := s.SecurityExperimentRun(id)
	if err != nil {
		return nil, fmt.Errorf("experiment evidence: %w", err)
	}
	return run, nil
}
