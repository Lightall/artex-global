// Package evidenceaudit validates offline security-review decisions against
// their cited evidence. It performs no model or target requests.
package evidenceaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion       = "evidence-audit/v2"
	SourceSchemaVersion = "evidence-source/v1"
	maxInputBytes       = int64(32 << 20)
)

type Bundle struct {
	SchemaVersion string   `json:"schema_version"`
	Snapshot      Snapshot `json:"snapshot"`
	Sources       []Source `json:"sources"`
	Claims        []Claim  `json:"claims"`
}

type Snapshot struct {
	ID         string `json:"id"`
	CapturedAt string `json:"captured_at"`
}

type Source struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type SourceDocument struct {
	SchemaVersion string    `json:"schema_version"`
	SnapshotID    string    `json:"snapshot_id"`
	Kind          string    `json:"kind"`
	CapturedAt    string    `json:"captured_at"`
	ReadableScope string    `json:"readable_scope"`
	Object        Object    `json:"object"`
	Excerpts      []Excerpt `json:"excerpts"`
}

type Excerpt struct {
	Locator             string   `json:"locator"`
	Text                string   `json:"text"`
	TextSHA256          string   `json:"text_sha256"`
	Covers              []string `json:"covers,omitempty"`
	DecisionClaimID     string   `json:"decision_claim_id,omitempty"`
	DecisionDisposition string   `json:"decision_disposition,omitempty"`
	RootCauseID         string   `json:"root_cause_id,omitempty"`
	MappedClaimID       string   `json:"mapped_claim_id,omitempty"`
}

type Object struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Evidence struct {
	SourceID string `json:"source_id"`
	Locator  string `json:"locator"`
}

type DecisionReference struct {
	SourceID string `json:"source_id"`
	Locator  string `json:"locator"`
}

type RootCauseReference struct {
	ID       string `json:"id"`
	SourceID string `json:"source_id"`
	Locator  string `json:"locator"`
}

type Claim struct {
	ID                  string              `json:"id"`
	Statement           string              `json:"statement"`
	Object              Object              `json:"object"`
	Requirements        []string            `json:"requirements"`
	OriginalDisposition string              `json:"original_disposition"`
	Disposition         string              `json:"disposition"`
	ReasonCode          string              `json:"reason_code,omitempty"`
	PreparedBy          string              `json:"prepared_by"`
	Reviewer            string              `json:"reviewer"`
	ReviewedAt          string              `json:"reviewed_at"`
	OriginalDecision    DecisionReference   `json:"original_decision"`
	RootCause           *RootCauseReference `json:"root_cause,omitempty"`
	Evidence            []Evidence          `json:"evidence"`
	CitedClaimIDs       []string            `json:"cited_claim_ids,omitempty"`
	Unknown             string              `json:"unknown,omitempty"`
}

type Issue struct {
	Code     string `json:"code"`
	ClaimID  string `json:"claim_id,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	Message  string `json:"message"`
}

type ClaimResult struct {
	ID                  string   `json:"id"`
	OriginalDisposition string   `json:"original_disposition"`
	Disposition         string   `json:"disposition"`
	ReasonCode          string   `json:"reason_code,omitempty"`
	MissingRequirements []string `json:"missing_requirements"`
	CoveredRequirements []string `json:"covered_requirements"`
	DirectEvidenceCount int      `json:"direct_evidence_count"`
}

type Summary struct {
	Claims        int            `json:"claims"`
	Excluded      int            `json:"excluded"`
	Pending       int            `json:"pending"`
	Confirmed     int            `json:"confirmed"`
	GapCounts     map[string]int `json:"gap_counts"`
	InvalidClaims int            `json:"invalid_claims"`
	Warnings      int            `json:"warnings"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	SnapshotID    string        `json:"snapshot_id"`
	BundleSHA256  string        `json:"bundle_sha256"`
	Result        string        `json:"result"`
	Summary       Summary       `json:"summary"`
	Claims        []ClaimResult `json:"claims"`
	Errors        []Issue       `json:"errors"`
	Warnings      []Issue       `json:"warnings"`
}

type Auditor struct {
	BaseDir string
	Open    func(string) (io.ReadCloser, error)
}

type verifiedSource struct {
	Document SourceDocument
	Excerpts map[string]Excerpt
}

func New(baseDir string) *Auditor {
	return &Auditor{BaseDir: baseDir, Open: func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}}
}

func Load(r io.Reader) (*Bundle, string, error) {
	raw, err := readWithinLimit(r, maxInputBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read bundle: %w", err)
	}
	var bundle Bundle
	if err := decodeStrict(raw, &bundle); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return &bundle, hex.EncodeToString(sum[:]), nil
}

func readWithinLimit(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return raw, nil
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("input contains more than one JSON value")
		}
		return err
	}
	return nil
}

func (a *Auditor) Audit(bundle *Bundle, bundleSHA256 string) Report {
	report := Report{
		SchemaVersion: SchemaVersion,
		BundleSHA256:  bundleSHA256,
		Result:        "pass",
		Errors:        []Issue{},
		Warnings:      []Issue{},
		Claims:        []ClaimResult{},
	}
	report.Summary.GapCounts = map[string]int{}
	if bundle == nil {
		report.Errors = append(report.Errors, Issue{Code: "bundle_missing", Message: "input bundle is missing"})
		report.Result = "invalid"
		report.Summary.InvalidClaims = 1
		return report
	}
	report.SnapshotID = bundle.Snapshot.ID
	a.validateBundle(bundle, &report)
	snapshotTime, snapshotTimeErr := time.Parse(time.RFC3339, bundle.Snapshot.CapturedAt)

	sources := make(map[string]*verifiedSource, len(bundle.Sources))
	invalidSources := make(map[string]bool, len(bundle.Sources))
	for _, source := range bundle.Sources {
		verified, err := a.verifySource(source, bundle.Snapshot.ID, snapshotTime, snapshotTimeErr)
		if err != nil {
			invalidSources[source.ID] = true
			report.Errors = append(report.Errors, Issue{Code: "source_unreadable", SourceID: source.ID, Message: err.Error()})
			continue
		}
		sources[source.ID] = verified
	}
	claims := make(map[string]Claim, len(bundle.Claims))
	for _, claim := range bundle.Claims {
		claims[claim.ID] = claim
	}

	report.Summary.Claims = len(bundle.Claims)
	for _, claim := range bundle.Claims {
		result, errors, warnings := a.validateClaim(claim, sources, invalidSources, claims, snapshotTime, snapshotTimeErr)
		report.Claims = append(report.Claims, result)
		report.Errors = append(report.Errors, errors...)
		report.Warnings = append(report.Warnings, warnings...)
		switch claim.Disposition {
		case "excluded":
			report.Summary.Excluded++
		case "pending":
			report.Summary.Pending++
		case "confirmed":
			report.Summary.Confirmed++
		}
		if claim.Disposition == "pending" {
			reason := claim.ReasonCode
			if reason == "" {
				reason = "unspecified"
			}
			report.Summary.GapCounts[reason]++
		}
		if len(errors) > 0 {
			report.Summary.InvalidClaims++
		}
	}
	report.Summary.Warnings = len(report.Warnings)
	if len(report.Errors) > 0 {
		report.Result = "invalid"
	} else if len(report.Warnings) > 0 {
		report.Result = "attention"
	}
	sort.Slice(report.Errors, func(i, j int) bool {
		if report.Errors[i].ClaimID == report.Errors[j].ClaimID {
			return report.Errors[i].Code < report.Errors[j].Code
		}
		return report.Errors[i].ClaimID < report.Errors[j].ClaimID
	})
	sort.Slice(report.Warnings, func(i, j int) bool {
		if report.Warnings[i].ClaimID == report.Warnings[j].ClaimID {
			return report.Warnings[i].Code < report.Warnings[j].Code
		}
		return report.Warnings[i].ClaimID < report.Warnings[j].ClaimID
	})
	return report
}

func (a *Auditor) validateBundle(bundle *Bundle, report *Report) {
	if bundle.SchemaVersion != SchemaVersion {
		report.Errors = append(report.Errors, Issue{Code: "schema_version", Message: fmt.Sprintf("expected %q, got %q", SchemaVersion, bundle.SchemaVersion)})
	}
	if len(bundle.Sources) == 0 {
		report.Errors = append(report.Errors, Issue{Code: "sources_missing", Message: "bundle must contain at least one source"})
	}
	if len(bundle.Claims) == 0 {
		report.Errors = append(report.Errors, Issue{Code: "claims_missing", Message: "bundle must contain at least one claim"})
	}
	if strings.TrimSpace(bundle.Snapshot.ID) == "" {
		report.Errors = append(report.Errors, Issue{Code: "snapshot_id_missing", Message: "snapshot.id is required"})
	}
	if _, err := time.Parse(time.RFC3339, bundle.Snapshot.CapturedAt); err != nil {
		report.Errors = append(report.Errors, Issue{Code: "snapshot_time", Message: "snapshot.captured_at must be RFC3339"})
	}
	for field, ids := range map[string][]string{
		"source": idsOfSources(bundle.Sources),
		"claim":  idsOfClaims(bundle.Claims),
	} {
		for _, duplicate := range duplicates(ids) {
			report.Errors = append(report.Errors, Issue{Code: field + "_id_duplicate", Message: fmt.Sprintf("duplicate %s id %q", field, duplicate)})
		}
	}
	for _, source := range bundle.Sources {
		if strings.TrimSpace(source.ID) == "" {
			report.Errors = append(report.Errors, Issue{Code: "source_id_missing", Message: "source.id is required"})
			continue
		}
		if strings.TrimSpace(source.Path) == "" {
			report.Errors = append(report.Errors, Issue{Code: "source_path_missing", SourceID: source.ID, Message: "source.path is required"})
		}
		if !validSHA256(source.SHA256) {
			report.Errors = append(report.Errors, Issue{Code: "source_hash", SourceID: source.ID, Message: "source.sha256 must be a lowercase SHA-256"})
		}
	}
}

func (a *Auditor) verifySource(
	source Source,
	snapshotID string,
	snapshotTime time.Time,
	snapshotTimeErr error,
) (*verifiedSource, error) {
	if strings.TrimSpace(source.Path) == "" {
		return nil, errors.New("source.path is required")
	}
	path := source.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.BaseDir, path)
	}
	reader, err := a.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	raw, readErr := readWithinLimit(reader, maxInputBytes)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read source: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close source: %w", closeErr)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != source.SHA256 {
		return nil, fmt.Errorf("source hash mismatch: %s", path)
	}
	var document SourceDocument
	if err := decodeStrict(raw, &document); err != nil {
		return nil, fmt.Errorf("parse source document: %w", err)
	}
	excerpts, err := validateSourceDocument(document, snapshotID, snapshotTime, snapshotTimeErr)
	if err != nil {
		return nil, err
	}
	return &verifiedSource{Document: document, Excerpts: excerpts}, nil
}

func validateSourceDocument(
	document SourceDocument,
	snapshotID string,
	snapshotTime time.Time,
	snapshotTimeErr error,
) (map[string]Excerpt, error) {
	if document.SchemaVersion != SourceSchemaVersion {
		return nil, fmt.Errorf("source schema_version must be %q", SourceSchemaVersion)
	}
	if document.SnapshotID != snapshotID {
		return nil, fmt.Errorf("source.snapshot_id %q does not match bundle snapshot %q", document.SnapshotID, snapshotID)
	}
	if document.Kind != "decision" && document.Kind != "observation" && document.Kind != "control" && document.Kind != "mapping" {
		return nil, errors.New("source.kind must be decision, observation, control or mapping")
	}
	capturedAt, err := time.Parse(time.RFC3339, document.CapturedAt)
	if err != nil {
		return nil, errors.New("source.captured_at must be RFC3339")
	}
	if snapshotTimeErr == nil && capturedAt.After(snapshotTime) {
		return nil, errors.New("source.captured_at must not be after snapshot.captured_at")
	}
	if strings.TrimSpace(document.ReadableScope) == "" {
		return nil, errors.New("source.readable_scope is required")
	}
	if strings.TrimSpace(document.Object.ID) == "" || strings.TrimSpace(document.Object.Version) == "" {
		return nil, errors.New("source.object id and version are required")
	}
	if len(document.Excerpts) == 0 {
		return nil, errors.New("source.excerpts must not be empty")
	}

	excerpts := make(map[string]Excerpt, len(document.Excerpts))
	for _, excerpt := range document.Excerpts {
		if strings.TrimSpace(excerpt.Locator) == "" || excerpt.Locator != strings.TrimSpace(excerpt.Locator) {
			return nil, fmt.Errorf("source excerpt locator %q is missing or padded with whitespace", excerpt.Locator)
		}
		if _, exists := excerpts[excerpt.Locator]; exists {
			return nil, fmt.Errorf("duplicate source excerpt locator %q", excerpt.Locator)
		}
		if strings.TrimSpace(excerpt.Text) == "" {
			return nil, fmt.Errorf("source excerpt %q text is empty", excerpt.Locator)
		}
		if !validSHA256(excerpt.TextSHA256) {
			return nil, fmt.Errorf("source excerpt %q text_sha256 must be a lowercase SHA-256", excerpt.Locator)
		}
		sum := sha256.Sum256([]byte(excerpt.Text))
		if hex.EncodeToString(sum[:]) != excerpt.TextSHA256 {
			return nil, fmt.Errorf("source excerpt %q text hash mismatch", excerpt.Locator)
		}
		switch document.Kind {
		case "decision":
			if strings.TrimSpace(excerpt.DecisionClaimID) == "" || excerpt.DecisionClaimID != strings.TrimSpace(excerpt.DecisionClaimID) {
				return nil, fmt.Errorf("decision excerpt %q requires an unpadded decision_claim_id", excerpt.Locator)
			}
			if !validDisposition(excerpt.DecisionDisposition) {
				return nil, fmt.Errorf("decision excerpt %q requires a valid decision_disposition", excerpt.Locator)
			}
			if len(excerpt.Covers) != 0 {
				return nil, fmt.Errorf("decision excerpt %q must not declare direct evidence coverage", excerpt.Locator)
			}
			if excerpt.RootCauseID != "" || excerpt.MappedClaimID != "" {
				return nil, fmt.Errorf("decision excerpt %q must not contain root-cause mapping metadata", excerpt.Locator)
			}
		case "mapping":
			if strings.TrimSpace(excerpt.RootCauseID) == "" || excerpt.RootCauseID != strings.TrimSpace(excerpt.RootCauseID) {
				return nil, fmt.Errorf("mapping excerpt %q requires an unpadded root_cause_id", excerpt.Locator)
			}
			if strings.TrimSpace(excerpt.MappedClaimID) == "" || excerpt.MappedClaimID != strings.TrimSpace(excerpt.MappedClaimID) {
				return nil, fmt.Errorf("mapping excerpt %q requires an unpadded mapped_claim_id", excerpt.Locator)
			}
			if len(excerpt.Covers) != 0 || excerpt.DecisionClaimID != "" || excerpt.DecisionDisposition != "" {
				return nil, fmt.Errorf("mapping excerpt %q must not contain evidence or decision metadata", excerpt.Locator)
			}
		default:
			if len(excerpt.Covers) == 0 {
				return nil, fmt.Errorf("direct evidence excerpt %q must cover at least one requirement", excerpt.Locator)
			}
			if excerpt.DecisionClaimID != "" || excerpt.DecisionDisposition != "" || excerpt.RootCauseID != "" || excerpt.MappedClaimID != "" {
				return nil, fmt.Errorf("direct evidence excerpt %q must not contain decision or root-cause metadata", excerpt.Locator)
			}
			for _, requirement := range excerpt.Covers {
				if strings.TrimSpace(requirement) == "" || requirement != strings.TrimSpace(requirement) {
					return nil, fmt.Errorf("direct evidence excerpt %q has a blank or padded requirement", excerpt.Locator)
				}
			}
			if duplicate := duplicates(excerpt.Covers); len(duplicate) > 0 {
				return nil, fmt.Errorf("direct evidence excerpt %q repeats requirement %q", excerpt.Locator, duplicate[0])
			}
		}
		excerpts[excerpt.Locator] = excerpt
	}
	return excerpts, nil
}

func (a *Auditor) validateClaim(
	claim Claim,
	sources map[string]*verifiedSource,
	invalidSources map[string]bool,
	claims map[string]Claim,
	snapshotTime time.Time,
	snapshotTimeErr error,
) (ClaimResult, []Issue, []Issue) {
	result := ClaimResult{
		ID:                  claim.ID,
		OriginalDisposition: claim.OriginalDisposition,
		Disposition:         claim.Disposition,
		ReasonCode:          claim.ReasonCode,
		MissingRequirements: []string{},
		CoveredRequirements: []string{},
		DirectEvidenceCount: 0,
	}
	var errors, warnings []Issue
	addError := func(code, message string) {
		errors = append(errors, Issue{Code: code, ClaimID: claim.ID, Message: message})
	}
	addWarning := func(code, message string) {
		warnings = append(warnings, Issue{Code: code, ClaimID: claim.ID, Message: message})
	}

	if strings.TrimSpace(claim.ID) == "" {
		addError("claim_id_missing", "claim.id is required")
	}
	if strings.TrimSpace(claim.Statement) == "" {
		addError("statement_missing", "claim.statement is required")
	}
	if strings.TrimSpace(claim.Object.ID) == "" || strings.TrimSpace(claim.Object.Version) == "" {
		addError("object_binding_missing", "claim.object id and version are required")
	}
	if len(claim.Requirements) == 0 {
		addError("requirements_missing", "at least one evidence requirement is required")
	} else {
		for _, requirement := range claim.Requirements {
			if strings.TrimSpace(requirement) == "" || requirement != strings.TrimSpace(requirement) {
				addError("requirement_blank", "evidence requirements must be non-empty and unpadded")
			}
		}
		for _, duplicate := range duplicates(claim.Requirements) {
			addError("requirement_duplicate", fmt.Sprintf("duplicate evidence requirement %q", duplicate))
		}
	}
	if !validDisposition(claim.OriginalDisposition) {
		addError("original_disposition", "original_disposition must be excluded, pending or confirmed")
	}
	if !validDisposition(claim.Disposition) {
		addError("disposition", "disposition must be excluded, pending or confirmed")
	}
	if claim.Disposition == "pending" && strings.TrimSpace(claim.ReasonCode) == "" {
		addError("reason_code_missing", "pending claims require a reason_code")
	} else if claim.Disposition == "pending" && !validReasonCode(claim.ReasonCode) {
		addError("reason_code_invalid", "pending reason_code is not in the fixed vocabulary")
	}
	if claim.Disposition == "pending" && strings.TrimSpace(claim.Unknown) == "" {
		addError("unknown_missing", "pending claims require a specific unknown explanation")
	}
	if strings.TrimSpace(claim.PreparedBy) == "" {
		addError("prepared_by_missing", "prepared_by is required")
	}
	if strings.TrimSpace(claim.Reviewer) == "" {
		addError("reviewer_missing", "reviewer is required")
	}
	if strings.TrimSpace(claim.PreparedBy) != "" && strings.TrimSpace(claim.PreparedBy) == strings.TrimSpace(claim.Reviewer) {
		addError("reviewer_not_independent", "prepared_by and reviewer must identify different people")
	}
	reviewedTime, reviewedTimeErr := time.Parse(time.RFC3339, claim.ReviewedAt)
	if reviewedTimeErr != nil {
		addError("reviewed_at", "reviewed_at must be RFC3339")
	}
	if reviewedTimeErr == nil && snapshotTimeErr == nil && reviewedTime.After(snapshotTime) {
		addError("reviewed_after_snapshot", "reviewed_at must not be after snapshot.captured_at")
	}
	if strings.TrimSpace(claim.OriginalDecision.SourceID) == "" || strings.TrimSpace(claim.OriginalDecision.Locator) == "" {
		addError("original_decision_missing", "original_decision source_id and locator are required")
	} else {
		source, ok := sources[claim.OriginalDecision.SourceID]
		switch {
		case !ok && invalidSources[claim.OriginalDecision.SourceID]:
			addError("original_decision_source_invalid", fmt.Sprintf("original decision source %q failed validation", claim.OriginalDecision.SourceID))
		case !ok:
			addError("original_decision_source_missing", fmt.Sprintf("original decision source %q does not exist", claim.OriginalDecision.SourceID))
		case source.Document.Kind != "decision":
			addError("original_decision_kind", fmt.Sprintf("original decision source %q is %s, not decision", claim.OriginalDecision.SourceID, source.Document.Kind))
		case source.Document.Object.ID != claim.Object.ID || source.Document.Object.Version != claim.Object.Version:
			addError("original_decision_object_mismatch", fmt.Sprintf("original decision source %q binds %s@%s, not %s@%s", claim.OriginalDecision.SourceID, source.Document.Object.ID, source.Document.Object.Version, claim.Object.ID, claim.Object.Version))
		default:
			excerpt, found := source.Excerpts[claim.OriginalDecision.Locator]
			if !found {
				addError("original_decision_locator_missing", fmt.Sprintf("original decision source %q has no locator %q", claim.OriginalDecision.SourceID, claim.OriginalDecision.Locator))
			} else {
				if excerpt.DecisionDisposition != claim.OriginalDisposition {
					addError("original_decision_mismatch", fmt.Sprintf("original decision excerpt records %q, claim records %q", excerpt.DecisionDisposition, claim.OriginalDisposition))
				}
				if excerpt.DecisionClaimID != claim.ID {
					addError("original_decision_claim_mismatch", fmt.Sprintf("original decision excerpt records claim %q, current claim is %q", excerpt.DecisionClaimID, claim.ID))
				}
				capturedAt, err := time.Parse(time.RFC3339, source.Document.CapturedAt)
				if reviewedTimeErr == nil && (err != nil || capturedAt.After(reviewedTime)) {
					addError("original_decision_after_review", "original decision evidence must be captured no later than reviewed_at")
				}
			}
		}
	}
	if claim.RootCause != nil {
		rootCause := claim.RootCause
		if strings.TrimSpace(rootCause.ID) == "" || strings.TrimSpace(rootCause.SourceID) == "" || strings.TrimSpace(rootCause.Locator) == "" {
			addError("root_cause_reference_incomplete", "root_cause id, source_id and locator must all be present")
		} else {
			source, ok := sources[rootCause.SourceID]
			switch {
			case !ok && invalidSources[rootCause.SourceID]:
				addError("root_cause_source_invalid", fmt.Sprintf("root-cause source %q failed validation", rootCause.SourceID))
			case !ok:
				addError("root_cause_source_missing", fmt.Sprintf("root-cause source %q does not exist", rootCause.SourceID))
			case source.Document.Kind != "mapping":
				addError("root_cause_kind", fmt.Sprintf("root-cause source %q is %s, not mapping", rootCause.SourceID, source.Document.Kind))
			case source.Document.Object.ID != claim.Object.ID || source.Document.Object.Version != claim.Object.Version:
				addError("root_cause_object_mismatch", fmt.Sprintf("root-cause source %q binds %s@%s, not %s@%s", rootCause.SourceID, source.Document.Object.ID, source.Document.Object.Version, claim.Object.ID, claim.Object.Version))
			default:
				excerpt, found := source.Excerpts[rootCause.Locator]
				if !found {
					addError("root_cause_locator_missing", fmt.Sprintf("root-cause source %q has no locator %q", rootCause.SourceID, rootCause.Locator))
				} else {
					if excerpt.RootCauseID != rootCause.ID {
						addError("root_cause_id_mismatch", fmt.Sprintf("mapping records root cause %q, claim references %q", excerpt.RootCauseID, rootCause.ID))
					}
					if excerpt.MappedClaimID != claim.ID {
						addError("root_cause_claim_mismatch", fmt.Sprintf("mapping records claim %q, current claim is %q", excerpt.MappedClaimID, claim.ID))
					}
					capturedAt, err := time.Parse(time.RFC3339, source.Document.CapturedAt)
					if reviewedTimeErr == nil && (err != nil || capturedAt.After(reviewedTime)) {
						addError("root_cause_after_review", "root-cause mapping must be captured no later than reviewed_at")
					}
				}
			}
		}
	}

	covered := map[string]bool{}
	for _, evidence := range claim.Evidence {
		source, ok := sources[evidence.SourceID]
		if !ok {
			if invalidSources[evidence.SourceID] {
				addError("evidence_source_invalid", fmt.Sprintf("evidence source %q failed validation", evidence.SourceID))
			} else {
				addError("evidence_source_missing", fmt.Sprintf("evidence source %q does not exist", evidence.SourceID))
			}
			continue
		}
		if strings.TrimSpace(evidence.Locator) == "" {
			addError("evidence_locator_missing", fmt.Sprintf("evidence %q has no locator", evidence.SourceID))
			continue
		}
		excerpt, found := source.Excerpts[evidence.Locator]
		if !found {
			addError("evidence_locator_missing", fmt.Sprintf("evidence source %q has no locator %q", evidence.SourceID, evidence.Locator))
			continue
		}
		if source.Document.Object.ID != claim.Object.ID || source.Document.Object.Version != claim.Object.Version {
			addError("evidence_object_mismatch", fmt.Sprintf("evidence %s:%s binds object %s@%s, not %s@%s", evidence.SourceID, evidence.Locator, source.Document.Object.ID, source.Document.Object.Version, claim.Object.ID, claim.Object.Version))
			continue
		}
		if source.Document.Kind == "decision" {
			addError("decision_cannot_cover", fmt.Sprintf("decision source %q cannot supply direct evidence", evidence.SourceID))
			continue
		}
		capturedAt, err := time.Parse(time.RFC3339, source.Document.CapturedAt)
		if reviewedTimeErr == nil && (err != nil || capturedAt.After(reviewedTime)) {
			addError("evidence_after_review", fmt.Sprintf("evidence %s:%s was captured after reviewed_at", evidence.SourceID, evidence.Locator))
			continue
		}
		result.DirectEvidenceCount++
		for _, requirement := range excerpt.Covers {
			if contains(claim.Requirements, requirement) {
				covered[requirement] = true
			}
		}
	}
	for _, requirement := range claim.Requirements {
		if covered[requirement] {
			result.CoveredRequirements = append(result.CoveredRequirements, requirement)
		} else {
			result.MissingRequirements = append(result.MissingRequirements, requirement)
		}
	}
	sort.Strings(result.CoveredRequirements)
	sort.Strings(result.MissingRequirements)

	if (claim.Disposition == "excluded" || claim.Disposition == "confirmed") && len(result.MissingRequirements) > 0 {
		code := "unsupported_confirmation"
		if claim.Disposition == "excluded" {
			code = "unsupported_negative_closure"
		}
		addError(code, claim.Disposition+" disposition lacks direct coverage for: "+strings.Join(result.MissingRequirements, ", "))
	}
	for _, citedID := range claim.CitedClaimIDs {
		if citedID == claim.ID {
			addError("self_citation", "claim cites itself")
			continue
		}
		cited, ok := claims[citedID]
		if !ok {
			addError("citation_missing", fmt.Sprintf("cited claim %q does not exist", citedID))
			continue
		}
		if cited.Object.ID != claim.Object.ID || cited.Object.Version != claim.Object.Version {
			addWarning("citation_scope_mismatch", fmt.Sprintf("cited claim %q covers %s@%s, not %s@%s", citedID, cited.Object.ID, cited.Object.Version, claim.Object.ID, claim.Object.Version))
		}
	}
	return result, errors, warnings
}

func validDisposition(value string) bool {
	return value == "excluded" || value == "pending" || value == "confirmed"
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validReasonCode(value string) bool {
	switch value {
	case "missing-precondition", "coverage-scope-mismatch", "source-unreadable", "conflicting-evidence", "insufficient-observation", "stale-version", "unadjudicated":
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func idsOfSources(sources []Source) []string {
	ids := make([]string, len(sources))
	for i, source := range sources {
		ids[i] = source.ID
	}
	return ids
}

func idsOfClaims(claims []Claim) []string {
	ids := make([]string, len(claims))
	for i, claim := range claims {
		ids[i] = claim.ID
	}
	return ids
}

func duplicates(values []string) []string {
	counts := map[string]int{}
	for _, value := range values {
		counts[value]++
	}
	var result []string
	for value, count := range counts {
		if count > 1 {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
