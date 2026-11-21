package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// previewTaskDomainScope uses the creation-time resolver without saving a task.
func (s *Server) previewTaskDomainScope(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskTemplateRequestBytes)
	var req struct {
		Domains string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	description, rules, err := db.ResolveTaskDomainScope(req.Domains, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domains": strings.Split(description, "\n"), "intercept_rules": rules,
	})
}
