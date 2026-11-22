package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/evidenceaudit"
)

func TestRunReturnsOneForUnsupportedExclusion(t *testing.T) {
	dir := t.TempDir()
	object := evidenceaudit.Object{ID: "branch", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, []evidenceaudit.Excerpt{{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "unsupported", DecisionDisposition: "excluded",
	}})
	observation := writeSourceDocument(t, dir, "observation", "observation", object, []evidenceaudit.Excerpt{{
		Locator: "line:1", Text: "Observed negative branch", Covers: []string{"observed-negative"},
	}})
	input := writeBundle(t, dir, evidenceaudit.Bundle{
		SchemaVersion: evidenceaudit.SchemaVersion,
		Snapshot: evidenceaudit.Snapshot{
			ID: "fixture", CapturedAt: "2026-11-22T12:00:00Z",
		},
		Sources: []evidenceaudit.Source{decision, observation},
		Claims: []evidenceaudit.Claim{{
			ID:                  "unsupported",
			Statement:           "The branch is absent.",
			Object:              object,
			Requirements:        []string{"positive-control"},
			OriginalDisposition: "excluded",
			Disposition:         "excluded",
			PreparedBy:          "author-a",
			Reviewer:            "reviewer-a",
			ReviewedAt:          "2026-11-22T10:00:00Z",
			OriginalDecision:    evidenceaudit.DecisionReference{SourceID: "decision", Locator: "decision:1"},
			Evidence: []evidenceaudit.Evidence{{
				SourceID: "observation", Locator: "line:1",
			}},
		}},
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"result": "invalid"`) || !strings.Contains(stdout.String(), "unsupported_negative_closure") {
		t.Fatalf("output=%s", stdout.String())
	}
}

func TestRunWritesNewPrivateReportWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	object := evidenceaudit.Object{ID: "auth", Version: "fixed"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, []evidenceaudit.Excerpt{{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "control", DecisionDisposition: "excluded",
	}})
	control := writeSourceDocument(t, dir, "control", "control", object, []evidenceaudit.Excerpt{{
		Locator: "line:1", Text: "Same-object negative control", Covers: []string{"same-object-test"},
	}})
	input := writeBundle(t, dir, evidenceaudit.Bundle{
		SchemaVersion: evidenceaudit.SchemaVersion,
		Snapshot: evidenceaudit.Snapshot{
			ID: "fixture", CapturedAt: "2026-11-22T12:00:00Z",
		},
		Sources: []evidenceaudit.Source{decision, control},
		Claims: []evidenceaudit.Claim{{
			ID:                  "control",
			Statement:           "The tested path rejects the operation.",
			Object:              object,
			Requirements:        []string{"same-object-test"},
			OriginalDisposition: "excluded",
			Disposition:         "excluded",
			PreparedBy:          "author-a",
			Reviewer:            "reviewer-a",
			ReviewedAt:          "2026-11-22T10:00:00Z",
			OriginalDecision:    evidenceaudit.DecisionReference{SourceID: "decision", Locator: "decision:1"},
			Evidence: []evidenceaudit.Evidence{{
				SourceID: "control", Locator: "line:1",
			}},
		}},
	})
	output := filepath.Join(filepath.Dir(input), "report.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input, "-output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 600", info.Mode().Perm())
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-input", input, "-output", output}, &stdout, &stderr); code != 2 {
		t.Fatalf("second run code=%d, want 2", code)
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing report was overwritten")
	}
}

func TestRunStrictModeFailsAttention(t *testing.T) {
	dir := t.TempDir()
	firstObject := evidenceaudit.Object{ID: "object-a", Version: "v1"}
	secondObject := evidenceaudit.Object{ID: "object-b", Version: "v1"}
	firstDecision := writeSourceDocument(t, dir, "first-decision", "decision", firstObject, []evidenceaudit.Excerpt{{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "first", DecisionDisposition: "excluded",
	}})
	secondDecision := writeSourceDocument(t, dir, "second-decision", "decision", secondObject, []evidenceaudit.Excerpt{{
		Locator: "decision:1", Text: "Original decision: pending",
		DecisionClaimID: "second", DecisionDisposition: "pending",
	}})
	observation := writeSourceDocument(t, dir, "observation", "observation", firstObject, []evidenceaudit.Excerpt{{
		Locator: "line:1", Text: "First object negative observation",
		Covers: []string{"same-object-test"},
	}})
	input := writeBundle(t, dir, evidenceaudit.Bundle{
		SchemaVersion: evidenceaudit.SchemaVersion,
		Snapshot: evidenceaudit.Snapshot{
			ID: "fixture", CapturedAt: "2026-11-22T12:00:00Z",
		},
		Sources: []evidenceaudit.Source{firstDecision, secondDecision, observation},
		Claims: []evidenceaudit.Claim{
			{
				ID:                  "first",
				Statement:           "The first object is negative.",
				Object:              firstObject,
				Requirements:        []string{"same-object-test"},
				OriginalDisposition: "excluded",
				Disposition:         "excluded",
				PreparedBy:          "author-a",
				Reviewer:            "reviewer-a",
				ReviewedAt:          "2026-11-22T10:00:00Z",
				OriginalDecision:    evidenceaudit.DecisionReference{SourceID: "first-decision", Locator: "decision:1"},
				Evidence: []evidenceaudit.Evidence{{
					SourceID: "observation", Locator: "line:1",
				}},
			},
			{
				ID:                  "second",
				Statement:           "The second object remains pending.",
				Object:              secondObject,
				Requirements:        []string{"same-object-test"},
				OriginalDisposition: "pending",
				Disposition:         "pending",
				ReasonCode:          "coverage-scope-mismatch",
				PreparedBy:          "author-a",
				Reviewer:            "reviewer-a",
				ReviewedAt:          "2026-11-22T10:00:00Z",
				OriginalDecision:    evidenceaudit.DecisionReference{SourceID: "second-decision", Locator: "decision:1"},
				CitedClaimIDs:       []string{"first"},
				Unknown:             "The available observation belongs to another object.",
			},
		},
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input}, &stdout, &stderr); code != 0 {
		t.Fatalf("default code=%d stderr=%s output=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), `"result": "attention"`) {
		t.Fatalf("output=%s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-input", input, "-strict"}, &stdout, &stderr); code != 1 {
		t.Fatalf("strict code=%d stderr=%s output=%s", code, stderr.String(), stdout.String())
	}
}

func writeBundle(t *testing.T, dir string, bundle evidenceaudit.Bundle) string {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSourceDocument(
	t *testing.T,
	dir string,
	id string,
	kind string,
	object evidenceaudit.Object,
	excerpts []evidenceaudit.Excerpt,
) evidenceaudit.Source {
	t.Helper()
	for i := range excerpts {
		if kind == "decision" && excerpts[i].DecisionClaimID == "" {
			excerpts[i].DecisionClaimID = "claim-1"
		}
		sum := sha256.Sum256([]byte(excerpts[i].Text))
		excerpts[i].TextSHA256 = hex.EncodeToString(sum[:])
	}
	document := evidenceaudit.SourceDocument{
		SchemaVersion: evidenceaudit.SourceSchemaVersion,
		SnapshotID:    "fixture",
		Kind:          kind,
		CapturedAt:    "2026-11-22T09:00:00Z",
		ReadableScope: "synthetic source",
		Object:        object,
		Excerpts:      excerpts,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return evidenceaudit.Source{
		ID: id, Path: filepath.Base(path), SHA256: hex.EncodeToString(sum[:]),
	}
}
