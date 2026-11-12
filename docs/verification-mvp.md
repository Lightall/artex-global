# Local HTTP verification MVP

This isolated candidate adds an opt-in experiment path to ARTEX. It does not
establish a measured improvement in natural-model discovery. No real-model
benchmark is part of its engineering acceptance.

## Supported experiment

The branch also provides the separately configured security-experiment mode in
`docs/security-experiments.md`. A task must use one mode: both operator write
paths reject mixed configuration without removing the existing requirement.
HTTP attempt IDs and security-experiment evidence node IDs are distinct;
`experiment_verified` metadata does not claim an HTTP `test_attempts` receipt.

The operator configures a private JSON resource, its ownership/access rule,
two actor identities, identity checks, login refresh, and JSON pointers for
the object, owner, private flag, protected value and explicit denial.
Configuration uses `PUT /api/tasks/{id}/verification` through the existing
authenticated API. Agent tools accept the configured `case_id`; they cannot
replace the rule or supply a verdict. The MVP only connects to literal
loopback HTTP addresses and does not follow redirects.

The existing Worker receives three tools:

- `run_http_case`: checks both actual identities, reads the owner's baseline,
  probes with the other actor, and repeats using isolated HTTP client state.
- `refresh_http_case_auth`: executes the configured login flow and checks
  each renewed identity. It returns no credentials to the model.
- `get_http_case_attempt`: reads the current task's actual observations;
  login response bodies are withheld.

The runner returns `reproduced`, `not_reproduced`, or `inconclusive`. A public
object, login page, missing baseline, WAF page, failed request or inconsistent
repeat cannot become a reproduced private-resource disclosure. A negative
result describes the particular tested conditions, not every possible input.

## Persistence and completion

`test_attempts` stores the host-produced observations and hashes. Task,
intent, configured case, assets, vulnerability class and case version must
match before a receipt can qualify a finding. A verified finding copies its
five observations into the existing immutable evidence/blob system so the
evidence follows the existing finding read/export path.

`verification_status` is separate from remediation `status`. Within an
opt-in task, a report without qualified receipts is a candidate. Legacy
tasks retain their previous behavior and carry `legacy_unverified` metadata.
Remediation status is never automatically set to fixed by this mechanism.

The planner overview includes the configured cases and actual prerequisite
failures. The normal fact/notification path can wake the existing Planner,
which can create a follow-up intent. Automatic per-version limits are two
verification attempts and one login refresh; every actual request also
reserves the task-wide configured request budget. Interrupted calls and
restart recovery seal unfinished attempts as inconclusive.

Completion checks current receipts, not just model text or asset coverage.
`prove_goal` also checks its actual evidence node. Manager completion paths
apply the same task criterion. Changed case configuration invalidates the
corresponding prior verification status while retaining its historical receipt.

## Zero-model acceptance

The fixture in `internal/verificationlab` runs a real temporary HTTP service.
It generates actor IDs, resource IDs and private markers per run, and has
vulnerable, fixed, business-denial, public-resource, WAF and inconsistent modes.
The fixed Provider has no model HTTP transport. Its decisions exercise the
normal SDK loop, tool assembly, Engine, Planner and Worker paths.

The end-to-end case performs:

1. Invalid owner login -> `inconclusive / owner_identity_invalid`.
2. The Planner sees the recorded gap and dispatches a recovery intent.
3. The Worker refreshes both identities and repeats the experiment.
4. Real baseline/probe/repeat responses reproduce the private-object disclosure.
5. One finding binds five evidence snapshots and satisfies the configured goal.

This fixture uses 10 actual local HTTP requests. A receipt contains the
observations; it is not a claim that a natural model independently chose the
right recovery strategy or discovered an unconfigured attack surface.

With the task-local Go/PostgreSQL runtime supplied alongside this copy:

```sh
python3.12 scripts/check-verification-mvp.py \
  --runtime ../runtime --port 62574 --evidence ../evidence \
  --start-postgres --mode acceptance
```

Use `--mode race` for the new race checks and `--mode regression` for the
five affected packages. Each package receives a newly created, dedicated
PostgreSQL database that is dropped after the run. The script removes model
credentials from its environment and writes JSONL test events and summaries.
The optional startup flag stops only the task-specific database process it
started. Go dependencies must already be available in the supplied cache.

## Remaining limits

- The case and access rule are operator configured; automated surface discovery,
  policy inference, other vulnerability classes and natural-model evaluation
  remain outside this acceptance.
- Task archive/restore does not yet carry the new experiment-history table.
  Keep MVP tasks unarchived pending that integration; this candidate is not a release.
- The API exposes verification metadata; the frontend has no dedicated badge or
  case editor yet. Existing free-text reports are not an authoritative verification verdict.
- Live case reconfiguration invalidates old receipts but does not automatically
  reopen an already completed task. A new task/run is needed for a new experiment.
- Initial and refreshed test credentials follow the project's existing database
  configuration model; production credential management is not implemented here.
