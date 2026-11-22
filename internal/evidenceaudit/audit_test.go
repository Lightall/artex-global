package evidenceaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExcludedClaimRequiresDirectCoverage(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "recovery.flow", Version: "pre-fix"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "1746", DecisionDisposition: "excluded",
	})
	observation := writeSourceDocument(t, dir, "observation", "observation", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Observed negative branch", Covers: []string{"observed-negative"},
	})
	claim := validClaim(object, []string{"positive-control"})
	claim.ID = "1746"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "observation", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, observation}, claim), "fixture")
	if report.Result != "invalid" {
		t.Fatalf("result=%s, want invalid", report.Result)
	}
	if !hasIssue(report.Errors, "unsupported_negative_closure") {
		t.Fatalf("errors=%+v", report.Errors)
	}
	if got := report.Claims[0].MissingRequirements; len(got) != 1 || got[0] != "positive-control" {
		t.Fatalf("missing=%v", got)
	}
}

func TestCitedClaimDoesNotInheritCoverage(t *testing.T) {
	dir := t.TempDir()
	admin := Object{ID: "admin.flow", Version: "pre-fix"}
	routes := Object{ID: "management.routes", Version: "pre-fix"}
	adminDecision := writeSourceDocument(t, dir, "admin-decision", "decision", admin, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Admin exclusion",
		DecisionClaimID: "earlier-object", DecisionDisposition: "excluded",
	})
	routesDecision := writeSourceDocument(t, dir, "routes-decision", "decision", routes, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Routes pending",
		DecisionClaimID: "1366", DecisionDisposition: "pending",
	})
	observation := writeSourceDocument(t, dir, "observation", "observation", admin, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Admin negative observation", Covers: []string{"same-object-test"},
	})
	earlier := validClaim(admin, []string{"same-object-test"})
	earlier.ID = "earlier-object"
	earlier.OriginalDecision = DecisionReference{SourceID: "admin-decision", Locator: "decision:1"}
	earlier.Evidence = []Evidence{{SourceID: "observation", Locator: "line:1"}}
	citing := validClaim(routes, []string{"same-object-test"})
	citing.ID = "1366"
	citing.OriginalDisposition = "pending"
	citing.Disposition = "pending"
	citing.ReasonCode = "coverage-scope-mismatch"
	citing.Unknown = "The cited observation belongs to another object."
	citing.OriginalDecision = DecisionReference{SourceID: "routes-decision", Locator: "decision:1"}
	citing.CitedClaimIDs = []string{"earlier-object"}

	report := New(dir).Audit(bundleFixture([]Source{adminDecision, routesDecision, observation}, earlier, citing), "fixture")
	if report.Result != "attention" {
		t.Fatalf("result=%s errors=%+v warnings=%+v", report.Result, report.Errors, report.Warnings)
	}
	if !hasIssue(report.Warnings, "citation_scope_mismatch") {
		t.Fatalf("warnings=%+v", report.Warnings)
	}
	if report.Summary.GapCounts["coverage-scope-mismatch"] != 1 {
		t.Fatalf("gaps=%v", report.Summary.GapCounts)
	}
}

func TestSameObjectDirectEvidencePermitsExclusion(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "auth.flow", Version: "fixed"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Same-object negative control",
		Covers: []string{"same-object-test", "negative-observation"},
	})
	claim := validClaim(object, []string{"same-object-test", "negative-observation"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if report.Result != "pass" {
		t.Fatalf("result=%s errors=%+v warnings=%+v", report.Result, report.Errors, report.Warnings)
	}
	if report.Summary.Excluded != 1 || report.Claims[0].DirectEvidenceCount != 1 {
		t.Fatalf("summary=%+v claim=%+v", report.Summary, report.Claims[0])
	}
}

func TestPendingClaimUsesFixedReasonVocabulary(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "branch", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending",
		DecisionClaimID: "free-form-gap", DecisionDisposition: "pending",
	})
	claim := validClaim(object, []string{"positive-control"})
	claim.ID = "free-form-gap"
	claim.OriginalDisposition = "pending"
	claim.Disposition = "pending"
	claim.ReasonCode = "looked suspicious"
	claim.Unknown = "The test did not exercise the required positive control."
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "reason_code_invalid") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestPendingClaimRequiresSpecificUnknown(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "branch", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending",
		DecisionClaimID: "claim-1", DecisionDisposition: "pending",
	})
	claim := validClaim(object, []string{"positive-control"})
	claim.OriginalDisposition = "pending"
	claim.Disposition = "pending"
	claim.ReasonCode = "missing-precondition"
	claim.Unknown = "   "
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "unknown_missing") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestReviewerMustDifferFromPreparedBy(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.PreparedBy = "same-person"
	claim.Reviewer = "same-person"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "reviewer_not_independent") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestPreparedByIsRequired(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.PreparedBy = ""
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "prepared_by_missing") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestRootCauseRequiresExplicitBoundMapping(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending", DecisionDisposition: "pending",
	})
	mapping := writeSourceDocument(t, dir, "mapping", "mapping", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "mapping:1", Text: "Explicit root-cause mapping",
		RootCauseID: "rc-auth-bypass", MappedClaimID: "claim-1",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDisposition = "pending"
	claim.Disposition = "pending"
	claim.ReasonCode = "insufficient-observation"
	claim.Unknown = "Root-cause mapping exists, but the direct control is incomplete."
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.RootCause = &RootCauseReference{ID: "rc-auth-bypass", SourceID: "mapping", Locator: "mapping:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision, mapping}, claim), "fixture")
	if report.Result != "pass" {
		t.Fatalf("result=%s errors=%+v", report.Result, report.Errors)
	}
}

func TestRootCauseMappingMustMatchClaimAndID(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending", DecisionDisposition: "pending",
	})
	mapping := writeSourceDocument(t, dir, "mapping", "mapping", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "mapping:1", Text: "Mismatched root-cause mapping",
		RootCauseID: "rc-other", MappedClaimID: "different-claim",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDisposition = "pending"
	claim.Disposition = "pending"
	claim.ReasonCode = "insufficient-observation"
	claim.Unknown = "The mapping does not identify this claim."
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.RootCause = &RootCauseReference{ID: "rc-expected", SourceID: "mapping", Locator: "mapping:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision, mapping}, claim), "fixture")
	if !hasIssue(report.Errors, "root_cause_id_mismatch") || !hasIssue(report.Errors, "root_cause_claim_mismatch") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestRootCauseMappingMustMatchObject(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	otherObject := Object{ID: "object-b", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending", DecisionDisposition: "pending",
	})
	mapping := writeSourceDocument(t, dir, "mapping", "mapping", otherObject, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "mapping:1", Text: "Root cause mapped to another object",
		RootCauseID: "rc-auth-bypass", MappedClaimID: "claim-1",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDisposition = "pending"
	claim.Disposition = "pending"
	claim.ReasonCode = "insufficient-observation"
	claim.Unknown = "The root-cause object is not yet reconciled."
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.RootCause = &RootCauseReference{ID: "rc-auth-bypass", SourceID: "mapping", Locator: "mapping:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision, mapping}, claim), "fixture")
	if !hasIssue(report.Errors, "root_cause_object_mismatch") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestEvidenceObjectMismatchIsRejected(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	otherObject := Object{ID: "object-b", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "wrong-object", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", otherObject, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Wrong object control", Covers: []string{"same-object-test"},
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.ID = "wrong-object"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if !hasIssue(report.Errors, "evidence_object_mismatch") || !hasIssue(report.Errors, "unsupported_negative_closure") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestEvidenceLocatorMustExistInSource(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Bound control", Covers: []string{"same-object-test"},
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:999"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if !hasIssue(report.Errors, "evidence_locator_missing") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestEmptyRequirementsCannotPassByOmission(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded",
		DecisionClaimID: "blank-requirement", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, nil)
	claim.ID = "empty-requirements"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "requirements_missing") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestBlankRequirementsCannotPass(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{""})
	claim.ID = "blank-requirement"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "requirement_blank") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestConfirmedClaimRequiresAllRequirements(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: pending",
		DecisionClaimID: "partially-covered-confirmation", DecisionDisposition: "pending",
	})
	observation := writeSourceDocument(t, dir, "observation", "observation", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Confirmed same-object behavior", Covers: []string{"same-object-test"},
	})
	claim := validClaim(object, []string{"same-object-test", "impact-observation"})
	claim.ID = "partially-covered-confirmation"
	claim.OriginalDisposition = "pending"
	claim.Disposition = "confirmed"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "observation", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, observation}, claim), "fixture")
	if !hasIssue(report.Errors, "unsupported_confirmation") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestSourceHashMismatchPropagatesToClaim(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Bound control", Covers: []string{"same-object-test"},
	})
	control.SHA256 = strings.Repeat("0", 64)
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if !hasIssue(report.Errors, "source_unreadable") || !hasIssue(report.Errors, "evidence_source_invalid") {
		t.Fatalf("errors=%+v", report.Errors)
	}
	if report.Summary.InvalidClaims != 1 || report.Claims[0].DirectEvidenceCount != 0 {
		t.Fatalf("summary=%+v claim=%+v", report.Summary, report.Claims[0])
	}
}

func TestDecisionSourceCannotProvideDirectCoverage(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "decision", Locator: "decision:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "decision_cannot_cover") || !hasIssue(report.Errors, "unsupported_negative_closure") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestOriginalDecisionMustMatchBoundSource(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: confirmed", DecisionDisposition: "confirmed",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDisposition = "excluded"
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "original_decision_mismatch") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestOriginalDecisionMustIdentifyCurrentClaim(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision for another claim",
		DecisionClaimID: "different-claim", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}

	report := New(dir).Audit(bundleFixture([]Source{decision}, claim), "fixture")
	if !hasIssue(report.Errors, "original_decision_claim_mismatch") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestEvidenceCapturedAfterReviewIsRejected(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", object, "2026-11-22T11:00:00Z", Excerpt{
		Locator: "line:1", Text: "Future control", Covers: []string{"same-object-test"},
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if !hasIssue(report.Errors, "evidence_after_review") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestSourceSnapshotMustMatchBundle(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	bundle := bundleFixture([]Source{decision}, claim)
	bundle.Snapshot.ID = "different-snapshot"

	report := New(dir).Audit(bundle, "fixture")
	if !hasIssue(report.Errors, "source_unreadable") || !hasIssue(report.Errors, "original_decision_source_invalid") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestReviewAfterSnapshotIsRejected(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	bundle := bundleFixture([]Source{decision}, claim)
	bundle.Snapshot.CapturedAt = "2026-11-22T09:00:00Z"

	report := New(dir).Audit(bundle, "fixture")
	if !hasIssue(report.Errors, "reviewed_after_snapshot") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestExcerptTextHashMismatchRejectsSource(t *testing.T) {
	dir := t.TempDir()
	object := Object{ID: "object-a", Version: "v1"}
	decision := writeSourceDocument(t, dir, "decision", "decision", object, "2026-11-22T08:00:00Z", Excerpt{
		Locator: "decision:1", Text: "Original decision: excluded", DecisionDisposition: "excluded",
	})
	control := writeSourceDocument(t, dir, "control", "control", object, "2026-11-22T09:00:00Z", Excerpt{
		Locator: "line:1", Text: "Bound control", TextSHA256: strings.Repeat("0", 64),
		Covers: []string{"same-object-test"},
	})
	claim := validClaim(object, []string{"same-object-test"})
	claim.OriginalDecision = DecisionReference{SourceID: "decision", Locator: "decision:1"}
	claim.Evidence = []Evidence{{SourceID: "control", Locator: "line:1"}}

	report := New(dir).Audit(bundleFixture([]Source{decision, control}, claim), "fixture")
	if !hasIssue(report.Errors, "source_unreadable") || !hasIssue(report.Errors, "evidence_source_invalid") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestEmptyBundleIsRejected(t *testing.T) {
	bundle := &Bundle{
		SchemaVersion: SchemaVersion,
		Snapshot:      Snapshot{ID: "empty", CapturedAt: "2026-11-22T09:00:00Z"},
	}
	report := New(t.TempDir()).Audit(bundle, "fixture")
	if !hasIssue(report.Errors, "sources_missing") || !hasIssue(report.Errors, "claims_missing") {
		t.Fatalf("errors=%+v", report.Errors)
	}
}

func TestLoadRejectsInputOverLimit(t *testing.T) {
	prefix := []byte(`{"schema_version":"evidence-audit/v2"}`)
	raw := append(prefix, bytes.Repeat([]byte(" "), int(maxInputBytes)+1-len(prefix))...)
	if _, _, err := Load(bytes.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadHashesCompleteInput(t *testing.T) {
	raw := []byte(`{"schema_version":"evidence-audit/v2"}` + "\n")
	_, digest, err := Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest=%s", digest)
	}
}

func bundleFixture(sources []Source, claims ...Claim) *Bundle {
	return &Bundle{
		SchemaVersion: SchemaVersion,
		Snapshot:      Snapshot{ID: "synthetic", CapturedAt: "2026-11-22T12:00:00Z"},
		Sources:       sources,
		Claims:        claims,
	}
}

func validClaim(object Object, requirements []string) Claim {
	return Claim{
		ID:                  "claim-1",
		Statement:           "The tested branch is absent.",
		Object:              object,
		Requirements:        requirements,
		OriginalDisposition: "excluded",
		Disposition:         "excluded",
		PreparedBy:          "author-a",
		Reviewer:            "reviewer-a",
		ReviewedAt:          "2026-11-22T10:00:00Z",
	}
}

func writeSourceDocument(
	t *testing.T,
	dir string,
	id string,
	kind string,
	object Object,
	capturedAt string,
	excerpts ...Excerpt,
) Source {
	t.Helper()
	for i := range excerpts {
		if kind == "decision" && excerpts[i].DecisionClaimID == "" {
			excerpts[i].DecisionClaimID = "claim-1"
		}
		if excerpts[i].TextSHA256 == "" {
			sum := sha256.Sum256([]byte(excerpts[i].Text))
			excerpts[i].TextSHA256 = hex.EncodeToString(sum[:])
		}
	}
	document := SourceDocument{
		SchemaVersion: SourceSchemaVersion,
		SnapshotID:    "synthetic",
		Kind:          kind,
		CapturedAt:    capturedAt,
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
	return Source{ID: id, Path: filepath.Base(path), SHA256: hex.EncodeToString(sum[:])}
}

func hasIssue(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
