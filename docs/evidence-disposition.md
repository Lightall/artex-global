# Evidence disposition audit

`evidence-audit` is an offline validator for security-review decisions. It reads
an `evidence-audit/v2` Bundle, verifies every referenced source file and
source document, and checks the claim against the object, version, evidence
requirements, original decision, and snapshot recorded in those sources. It
does not call a model, contact a target, or write application state.

The Bundle does not repeat the object, version, or coverage fields inside each
claim evidence entry. Each entry only names a source and a locator. The
validator resolves those fields from the source document after verifying the
source file hash and excerpt hash.

## Decision rules

- `excluded` requires direct `observation` or `control` excerpts that together
  cover every requirement for the same object and version.
- `confirmed` uses the same direct evidence rule. A `decision` source never
  supplies direct coverage.
- Every claim must reference an `original_decision` excerpt whose source kind
  is `decision`, whose object and version match the claim, and whose recorded
  disposition matches `original_disposition`.
- `pending` records a gap in `reason_code` and must contain a specific
  non-empty `unknown` explanation.
- A claim that declares a `root_cause` must reference a `mapping` excerpt that
  records the same root-cause ID, current claim ID, object, and version. Claims
  that do not declare a root cause remain standalone decisions.
- `cited_claim_ids` provide context only. They never transfer evidence coverage
  to the citing claim. A citation bound to another object or version is
  reported as `citation_scope_mismatch`.

Source capture time, review time, and snapshot time must be ordered as source
at or before review and review at or before snapshot. Sources must also carry
the Bundle's `snapshot_id`.

`prepared_by` and `reviewer` are mandatory and must identify different people.
Review time, source snapshot, readable scope, source file hashes, object and
version metadata, locator identities, and excerpt hashes are also mandatory.
The report is written to a new file with mode `0600`; the command refuses to
overwrite an earlier result.

Pending gaps use a fixed vocabulary so counts remain comparable. Use
`missing-precondition`, `coverage-scope-mismatch`, `source-unreadable`,
`conflicting-evidence`, `insufficient-observation`, `stale-version`, or
`unadjudicated`.

## Bundle

```json
{
  "schema_version": "evidence-audit/v2",
  "snapshot": {
    "id": "review-2026-11-22",
    "captured_at": "2026-11-22T12:00:00Z"
  },
  "sources": [
    {
      "id": "decision-1",
      "path": "sources/decision-1.json",
      "sha256": "<lowercase sha256 of the complete source file>"
    },
    {
      "id": "observation-1",
      "path": "sources/observation-1.json",
      "sha256": "<lowercase sha256 of the complete source file>"
    },
    {
      "id": "mapping-1",
      "path": "sources/mapping-1.json",
      "sha256": "<lowercase sha256 of the complete source file>"
    }
  ],
  "claims": [
    {
      "id": "claim-1",
      "statement": "The blocked branch is absent.",
      "object": {"id": "service-branch", "version": "pre-fix"},
      "requirements": ["same-object-test", "negative-observation"],
      "original_disposition": "excluded",
      "disposition": "excluded",
      "prepared_by": "author-id",
      "reviewer": "reviewer-id",
      "reviewed_at": "2026-11-22T10:00:00Z",
      "original_decision": {
        "source_id": "decision-1",
        "locator": "decision:1"
      },
      "root_cause": {
        "id": "rc-auth-bypass",
        "source_id": "mapping-1",
        "locator": "mapping:1"
      },
      "evidence": [
        {
          "source_id": "observation-1",
          "locator": "line:1"
        }
      ]
    }
  ]
}
```

## Source document

Each source path points to a strict `evidence-source/v1` JSON document. Unknown
fields, duplicate excerpts, blank locators, wrong hashes, and object-free
sources are rejected.

```json
{
  "schema_version": "evidence-source/v1",
  "snapshot_id": "review-2026-11-22",
  "kind": "observation",
  "captured_at": "2026-11-22T09:00:00Z",
  "readable_scope": "redacted request and response excerpt",
  "object": {
    "id": "service-branch",
    "version": "pre-fix"
  },
  "excerpts": [
    {
      "locator": "line:1",
      "text": "redacted response showing the negative branch",
      "text_sha256": "<lowercase sha256 of the UTF-8 text field>",
      "covers": ["same-object-test", "negative-observation"]
    }
  ]
}
```

A decision source uses `kind: "decision"` and records the historical result in
each excerpt. It must not declare direct coverage.

```json
{
  "schema_version": "evidence-source/v1",
  "snapshot_id": "review-2026-11-22",
  "kind": "decision",
  "captured_at": "2026-11-22T08:00:00Z",
  "readable_scope": "redacted original disposition",
  "object": {
    "id": "service-branch",
    "version": "pre-fix"
  },
  "excerpts": [
    {
      "locator": "decision:1",
      "text": "original disposition: excluded",
      "text_sha256": "<lowercase sha256 of the UTF-8 text field>",
      "decision_claim_id": "claim-1",
      "decision_disposition": "excluded"
    }
  ]
}
```

A root-cause mapping is an explicit, hashed assertion. A claim that omits
`root_cause` makes no root-cause claim. One that includes it cannot silently
join another record, domain, or symptom to an existing root cause.

```json
{
  "schema_version": "evidence-source/v1",
  "snapshot_id": "review-2026-11-22",
  "kind": "mapping",
  "captured_at": "2026-11-22T08:30:00Z",
  "readable_scope": "redacted reviewer mapping rationale",
  "object": {
    "id": "service-branch",
    "version": "pre-fix"
  },
  "excerpts": [
    {
      "locator": "mapping:1",
      "text": "This record maps to rc-auth-bypass",
      "text_sha256": "<lowercase sha256 of the UTF-8 text field>",
      "root_cause_id": "rc-auth-bypass",
      "mapped_claim_id": "claim-1"
    }
  ]
}
```

The source file hash binds the complete serialized document. The excerpt hash
binds the exact `text` selected by the locator. The object and version come
from that hashed source document, so changing them in a claim or evidence entry
causes validation failure.

Source paths are resolved relative to the Bundle file. The command hashes each
source against its declared SHA-256. Keep sensitive evidence in an authorized
private directory; this format requires only redacted excerpts and locators.

The Bundle and every source document are limited to 32 MiB. The validator reads
one byte beyond the limit, rejects an oversized input, and computes
`bundle_sha256` over the complete Bundle bytes.

## Run

```bash
go run ./cmd/evidence-audit -input review.json
go run ./cmd/evidence-audit -input review.json -output review-report.json
go run ./cmd/evidence-audit -input review.json -strict
```

Exit code `0` means the Bundle is structurally valid. `attention` reports
remain a successful audit with scope-mismatch warnings in the default mode.
With `-strict`, `attention` returns exit code `1`. Exit code `1` also means at
least one claim or source is invalid. Exit code `2` means the command could not
parse or read its input or could not write a unique result.

This validator proves deterministic source, locator, object, version, time, and
coverage boundaries, distinct preparation and review identities, and the
identity of any claimed root-cause mapping. The identities are declarations
until linked to an external identity provider or signed review workflow. A
source text or model statement also does not establish that the semantic
interpretation is correct. Independent semantic blind review remains a
separate evidence step.
