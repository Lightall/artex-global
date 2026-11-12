package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securityexperiment"
)

func (s *Server) securityExperimentTask(w http.ResponseWriter, r *http.Request) (*db.ExplorationStore, int64, bool) {
	pg := s.pg(w)
	if pg == nil {
		return nil, 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid task id")
		return nil, 0, false
	}
	task, err := pg.GetTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return nil, 0, false
	}
	if task == nil {
		writeErr(w, 404, "task not found")
		return nil, 0, false
	}
	store := pg.Exploration(task.ExplorationID)
	store.SetExperimentStateObserver(func() error { return s.m.refreshExperimentTaskState(id) })
	return store, id, true
}

func (s *Server) listSecurityExperiments(w http.ResponseWriter, r *http.Request) {
	ts, _, ok := s.securityExperimentTask(w, r)
	if !ok {
		return
	}
	items, err := ts.SecurityExperiments()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"experiments": items})
}

// Configuration is deliberately available only through the authenticated
// operator API, never through an agent tool that can invent its own policy.
func (s *Server) createSecurityExperiment(w http.ResponseWriter, r *http.Request) {
	ts, taskID, ok := s.securityExperimentTask(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var input struct {
		GoalID int64                   `json:"goal_id"`
		Spec   securityexperiment.Spec `json:"spec"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		writeErr(w, 400, "exactly one JSON object is required")
		return
	}
	if input.GoalID <= 0 {
		writeErr(w, 400, "goal_id is required")
		return
	}
	if !s.engine.beginTaskOperation(r.PathValue("id")) {
		writeErr(w, 409, "task is deleting")
		return
	}
	defer s.engine.decInflight(r.PathValue("id"))
	c, err := ts.CreateSecurityExperimentCase(r.Context(), taskID, input.GoalID, input.Spec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// This endpoint provides a model-free execution path for operator verification.
// Starting it requires an explicit request and an already configured case.
func (s *Server) runSecurityExperiment(w http.ResponseWriter, r *http.Request) {
	ts, taskID, ok := s.securityExperimentTask(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("caseID"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid experiment case id")
		return
	}
	if !s.engine.beginTaskOperation(r.PathValue("id")) {
		writeErr(w, 409, "task is deleting")
		return
	}
	defer s.engine.decInflight(r.PathValue("id"))
	run, err := ts.RunSecurityExperiment(r.Context(), taskID, id, 0)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, run)
}

// Refresh lifecycle only; operator experiments never start or resume models.
func (m *Manager) refreshExperimentTaskState(taskID int64) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	row, err := m.pg.GetTask(taskID)
	if err != nil || row == nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tasks[strconv.FormatInt(taskID, 10)]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Status, state.Paused, state.CompletedAt = row.Status, row.Paused, 0
			if row.CompletedAt != nil {
				state.CompletedAt = row.CompletedAt.Unix()
			}
		})
	}
	return nil
}

func (s *Server) getSecurityExperimentRun(w http.ResponseWriter, r *http.Request) {
	ts, _, ok := s.securityExperimentTask(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("runID"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid experiment run id")
		return
	}
	run, err := ts.SecurityExperimentEvidence(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, run)
}
