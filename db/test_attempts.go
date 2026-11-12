package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Autumn-27/artex/verification"
)

type TestAttempt struct {
	ID           int64                      `json:"id,string"`
	TaskID       int64                      `json:"task_id,string"`
	IntentID     int64                      `json:"intent_id,string"`
	CaseID       string                     `json:"case_id"`
	CaseHash     string                     `json:"case_hash"`
	Kind         string                     `json:"kind"`
	State        string                     `json:"state"`
	Verdict      string                     `json:"verdict"`
	Reason       string                     `json:"reason"`
	Observations []verification.Observation `json:"-"`
	ReceiptHash  string                     `json:"receipt_hash"`
}

// SetHTTPVerificationConfig is a host-only operation, never an agent tool.
func (d *DB) SetHTTPVerificationConfig(ctx context.Context, taskID int64, c verification.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}

	b, _ := json.Marshal(c)
	hashes := map[string]string{}
	for _, item := range c.Cases {
		hashes[item.ID] = verification.Digest(item)
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE tasks SET verification_config=$2,verification_auth='{}',verification_requests=0 WHERE id=$1 AND deleted_at IS NULL`, taskID, b)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return errors.New("task not available")
		}
		rows, err := tx.QueryContext(ctx, `UPDATE findings f SET verification_status='candidate' WHERE f.task_id=$1 AND f.verification_status='reproduced' AND NOT EXISTS(SELECT 1 FROM test_attempts a WHERE a.id=f.verification_attempt_id AND a.case_hash=COALESCE($2::jsonb->>a.case_id,'')) RETURNING node_id`, taskID, mustJSON(hashes))
		if err != nil {
			return err
		}
		var nodes []int64
		for rows.Next() {
			var node sql.NullInt64
			if err = rows.Scan(&node); err != nil {
				rows.Close()
				return err
			}
			if node.Valid {
				nodes = append(nodes, node.Int64)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, node := range nodes {
			if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='candidate',payload=jsonb_set(payload,'{verification_status}','"candidate"') WHERE id=$1`, node); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *DB) HTTPVerificationConfig(ctx context.Context, taskID int64) (verification.Config, error) {
	var b []byte
	err := d.QueryRowContext(ctx, `SELECT verification_config FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&b)
	var c verification.Config
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err == nil && len(c.Cases) > 0 {
		err = c.Validate()
	}
	return c, err
}

func (d *DB) StartHTTPAttempt(ctx context.Context, taskID, intentID int64, caseID, kind string) (*TestAttempt, verification.Case, verification.Auth, error) {
	if kind != "verify" && kind != "refresh" {
		return nil, verification.Case{}, nil, errors.New("invalid experiment kind")
	}
	var out *TestAttempt
	var item verification.Case
	var auth verification.Auth
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		var cfgRaw, authRaw []byte
		if err := tx.QueryRowContext(ctx, `SELECT verification_config,verification_auth FROM tasks WHERE id=$1`, taskID).Scan(&cfgRaw, &authRaw); err != nil {
			return err
		}
		var cfg verification.Config
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		var err error
		item, err = cfg.Find(caseID)
		if err != nil {
			return err
		}
		var valid bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1 AND n.id=$2 AND n.kind='intent' AND n.state='running')`, taskID, intentID).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return errors.New("verification requires the current running worker intent")
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM test_attempts WHERE task_id=$1 AND case_id=$2 AND case_hash=$3 AND kind=$4`, taskID, caseID, verification.Digest(item), kind).Scan(&count); err != nil {
			return err
		}
		limit := 2
		if kind == "refresh" {
			limit = 1
		}
		if count >= limit {
			return errors.New("case automatic attempt budget exhausted")
		}
		out = &TestAttempt{TaskID: taskID, IntentID: intentID, CaseID: caseID, CaseHash: verification.Digest(item), Kind: kind, State: "running", Verdict: "inconclusive"}
		if err = tx.QueryRowContext(ctx, `INSERT INTO test_attempts(task_id,intent_id,case_id,case_hash,kind) VALUES($1,$2,$3,$4,$5) RETURNING id`, taskID, intentID, caseID, out.CaseHash, kind).Scan(&out.ID); err != nil {
			return err
		}
		cache := map[string]verification.Auth{}
		if err = json.Unmarshal(authRaw, &cache); err != nil {
			return err
		}
		auth = cache[caseID]
		return nil
	})
	return out, item, auth, err
}

func (d *DB) ReserveVerificationRequest(ctx context.Context, taskID int64, c verification.Case) error {
	res, err := d.ExecContext(ctx, `UPDATE tasks SET verification_requests=verification_requests+1 WHERE id=$1 AND deleted_at IS NULL AND verification_requests < COALESCE((verification_config->>'max_requests')::int,0) AND verification_config->'cases' @> $2::jsonb`, taskID, mustJSON([]verification.Case{c}))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("request budget exhausted or experiment configuration changed")
	}
	return nil
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func scanAttempt(row interface{ Scan(...any) error }) (*TestAttempt, error) {
	a := &TestAttempt{}
	var raw []byte
	err := row.Scan(&a.ID, &a.TaskID, &a.IntentID, &a.CaseID, &a.CaseHash, &a.Kind, &a.State, &a.Verdict, &a.Reason, &raw, &a.ReceiptHash)
	if err == nil {
		err = json.Unmarshal(raw, &a.Observations)
	}
	return a, err
}

const attemptColumns = `id,task_id,intent_id,case_id,case_hash,kind,state,verdict,reason,observations,receipt_hash`

func (d *DB) GetTestAttempt(ctx context.Context, id int64) (*TestAttempt, error) {
	return scanAttempt(d.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM test_attempts WHERE id=$1`, id))
}

func (d *DB) FinishHTTPAttempt(ctx context.Context, id int64, obs []verification.Observation, cause string) (out *TestAttempt, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		a, e := scanAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM test_attempts WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return e
		}
		if a.State != "running" {
			return errors.New("attempt is already terminal")
		}
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT verification_config FROM tasks WHERE id=$1`, a.TaskID).Scan(&raw); e != nil {
			return e
		}
		var cfg verification.Config
		if e = json.Unmarshal(raw, &cfg); e != nil {
			return e
		}
		item, e := cfg.Find(a.CaseID)
		a.State = "completed"
		a.Verdict = "inconclusive"
		a.Reason = cause
		a.Observations = obs
		a.ReceiptHash = verification.Digest(obs)
		if e != nil || verification.Digest(item) != a.CaseHash {
			a.State = "failed"
			a.Reason = "configuration_changed"
		} else if cause != "" || !verification.ValidObservations(obs) {
			a.State = "failed"
			if cause == "" {
				a.Reason = "invalid_receipt"
			}
		} else if a.Kind == "verify" {
			a.Verdict, a.Reason = verification.Evaluate(item, obs)
		} else {
			auth, e := verification.RefreshedAuth(item, obs)
			if e != nil {
				a.State = "failed"
				a.Reason = "refresh_failed"
			} else {
				a.Reason = "credentials_refreshed"
				if _, e = tx.ExecContext(ctx, `UPDATE tasks SET verification_auth=jsonb_set(verification_auth,ARRAY[$2::text],$3::jsonb,true) WHERE id=$1`, a.TaskID, a.CaseID, mustJSON(auth)); e != nil {
					return e
				}
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE test_attempts SET state=$2,verdict=$3,reason=$4,observations=$5,receipt_hash=$6,finished_at=now() WHERE id=$1`, id, a.State, a.Verdict, a.Reason, mustJSON(obs), a.ReceiptHash); e != nil {
			return e
		}
		out = a
		return nil
	})
	return
}

func (d *DB) RecoverVerificationAttempts(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `UPDATE test_attempts SET state='failed',verdict='inconclusive',reason='service_restarted',finished_at=now() WHERE state='running'`)
	return err
}

// VerifiedAttemptTx rechecks current policy and immutable receipts at the write boundary.
func VerifiedAttemptTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput) (*TestAttempt, verification.Case, error) {
	a, err := scanAttempt(tx.QueryRowContext(ctx, `SELECT `+attemptColumns+` FROM test_attempts WHERE id=$1`, in.AttemptID))
	if err != nil {
		return nil, verification.Case{}, err
	}
	if a.TaskID != in.TaskID || a.IntentID != in.IntentID || a.CaseID != in.VerificationCaseID || a.Kind != "verify" || a.State != "completed" || a.Verdict != "reproduced" || a.ReceiptHash != verification.Digest(a.Observations) {
		return nil, verification.Case{}, errors.New("attempt does not provide a completed, task-bound reproduction")
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT verification_config FROM tasks WHERE id=$1`, in.TaskID).Scan(&raw); err != nil {
		return nil, verification.Case{}, err
	}
	var cfg verification.Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return nil, verification.Case{}, err
	}
	if err = cfg.Validate(); err != nil {
		return nil, verification.Case{}, err
	}
	item, err := cfg.Find(a.CaseID)
	if err != nil {
		return nil, item, err
	}
	verdict, _ := verification.Evaluate(item, a.Observations)
	if a.CaseHash != verification.Digest(item) || verdict != "reproduced" || in.VulnClass != "IDOR" || !sameIDs(item.AssetIDs, in.AssetIDs) {
		return nil, item, errors.New("attempt target, assets, class or experiment version does not match")
	}
	return a, item, nil
}

func sameIDs(a, b []int64) bool {
	a = append([]int64{}, a...)
	b = append([]int64{}, b...)
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func (s *ExplorationStore) VerificationOverview() (map[string]any, error) {
	taskID, err := s.TaskID()
	if err != nil {
		return nil, err
	}
	return s.db.VerificationOverview(context.Background(), taskID)
}
func (d *DB) VerificationOverview(ctx context.Context, taskID int64) (map[string]any, error) {
	cfg, err := d.HTTPVerificationConfig(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if len(cfg.Cases) == 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT `+attemptColumns+` FROM test_attempts WHERE task_id=$1 ORDER BY id DESC LIMIT 12`, taskID)
	if err != nil {
		return nil, err
	}
	var attempts []*TestAttempt
	for rows.Next() {
		a, e := scanAttempt(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		attempts = append(attempts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var cases []map[string]any
	for _, c := range cfg.Cases {
		cases = append(cases, map[string]any{"case_id": c.ID, "url": c.URL, "object_id": c.ObjectID, "rule_source": c.RuleSource, "owner_id": c.Owner.ID, "other_id": c.Other.ID})
	}
	var candidates, verified int
	if err = d.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE verification_status='candidate'),count(*) FILTER(WHERE verification_status='reproduced') FROM findings WHERE task_id=$1`, taskID).Scan(&candidates, &verified); err != nil {
		return nil, err
	}
	verified, err = d.currentVerificationCount(ctx, taskID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"cases": cases, "recent_attempts": attempts, "candidate_count": candidates, "reproduced_count": verified, "required_findings": cfg.RequiredFindings}, nil
}

func (s *ExplorationStore) CheckVerificationCompletion() error {
	taskID, err := s.TaskID()
	if err != nil {
		return err
	}
	return s.db.CheckVerificationCompletion(context.Background(), taskID)
}

// CheckVerificationEvidence binds the goal's actual proof edge, not just a counter.
func (s *ExplorationStore) CheckVerificationEvidence(nodeID int64) error {
	ctx := context.Background()
	taskID, err := s.TaskID()
	if err != nil {
		return err
	}
	cfg, err := s.db.HTTPVerificationConfig(ctx, taskID)
	if err != nil || len(cfg.Cases) == 0 {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	in := RecordFindingInput{TaskID: taskID}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT f.verification_attempt_id,f.verification_case_id,f.vulnclass,f.asset_ids,a.intent_id FROM findings f JOIN test_attempts a ON a.id=f.verification_attempt_id WHERE f.node_id=$1 AND f.task_id=$2 AND f.verification_status='reproduced'`, nodeID, taskID).Scan(&in.AttemptID, &in.VerificationCaseID, &in.VulnClass, &raw, &in.IntentID)
	if err != nil {
		return errors.New("goal evidence must itself be a current reproduced finding")
	}
	if err = json.Unmarshal(raw, &in.AssetIDs); err != nil {
		return err
	}
	_, _, err = VerifiedAttemptTx(ctx, tx, in)
	return err
}

func (d *DB) CheckVerificationCompletion(ctx context.Context, taskID int64) error {
	cfg, err := d.HTTPVerificationConfig(ctx, taskID)
	if err != nil {
		return err
	}
	if len(cfg.Cases) == 0 {
		return nil
	}
	count, err := d.currentVerificationCount(ctx, taskID)
	if err != nil {
		return err
	}
	if count < cfg.RequiredFindings {
		return fmt.Errorf("verification criterion unmet: %d/%d current, reproduced cases", count, cfg.RequiredFindings)
	}
	return nil
}

func (d *DB) currentVerificationCount(ctx context.Context, taskID int64) (int, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT f.verification_attempt_id,f.verification_case_id,f.vulnclass,f.asset_ids,a.intent_id FROM findings f JOIN test_attempts a ON a.id=f.verification_attempt_id WHERE f.task_id=$1 AND f.verification_status='reproduced'`, taskID)
	if err != nil {
		return 0, err
	}
	var inputs []RecordFindingInput
	for rows.Next() {
		in := RecordFindingInput{TaskID: taskID}
		var raw []byte
		if err = rows.Scan(&in.AttemptID, &in.VerificationCaseID, &in.VulnClass, &raw, &in.IntentID); err != nil {
			rows.Close()
			return 0, err
		}
		if err = json.Unmarshal(raw, &in.AssetIDs); err != nil {
			rows.Close()
			return 0, err
		}
		inputs = append(inputs, in)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	unique := map[string]bool{}
	for _, in := range inputs {
		_, item, e := VerifiedAttemptTx(ctx, tx, in)
		if e == nil {
			unique[item.RuleSource+"|"+item.URL] = true
		}
	}
	return len(unique), nil
}

// AbortHTTPAttempt seals interrupted calls without promoting any partial observation.
func (d *DB) AbortHTTPAttempt(id int64, obs []verification.Observation, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = d.FinishHTTPAttempt(ctx, id, obs, reason)
}
