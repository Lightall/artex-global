package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestReviewDomainGateRejectsConflictingHostMetadata(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("allowed.scope-review.test", "goal", TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://outside.scope-review.test/private"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE assets SET domain='allowed.scope-review.test',root_domain='allowed.scope-review.test',bound_domains=ARRAY['allowed.scope-review.test'] WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	hits, err := d.Assets().CheckAssetsIntercept(task.ID, []int64{id})
	if err == nil && len(hits) == 0 {
		t.Fatal("an allowed metadata field authorized an outside URL host")
	}
}

func TestReviewDomainSeedsRollbackWithTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`CREATE OR REPLACE FUNCTION review_reject_domain_seed() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.url='https://b.atomic-scope-review.test' THEN RAISE EXCEPTION 'synthetic seed failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER review_reject_domain_seed BEFORE INSERT ON assets FOR EACH ROW EXECUTE FUNCTION review_reject_domain_seed()`); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DROP TRIGGER review_reject_domain_seed ON assets; DROP FUNCTION review_reject_domain_seed()`)
	counts := func() []int {
		out := make([]int, 5)
		for i, table := range []string{"tasks", "explorations", "task_intercept_rules", "assets", "task_scope"} {
			if err := d.QueryRow("SELECT count(*) FROM " + table).Scan(&out[i]); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	before := counts()
	if _, err := d.CreateTaskWithOptions("a.atomic-scope-review.test\nb.atomic-scope-review.test", "goal", TaskCreateOptions{DomainScopeEnabled: true}); err == nil {
		t.Fatal("seed failure did not abort task creation")
	}
	after := counts()
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("partial state remained after seed failure: %v -> %v", before, after)
	}
}

func TestReviewOldDomainTaskModeMigration(t *testing.T) {
	u, err := url.Parse(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	u.Path += "_mode_migration"
	d, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("a.migration-scope-review.test\nb.migration-scope-review.test", "goal", TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE tasks DROP COLUMN domain_scope_enabled`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d, err = Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	defer d.DeleteTask(task.ID)
	loaded, err := d.GetTask(task.ID)
	if err != nil || !loaded.DomainScopeEnabled {
		t.Fatalf("old task mode lost: %+v %v", loaded, err)
	}
	gate, err := d.Assets().LoadTaskAssetGate(task.ID)
	if err != nil || strings.Join(gate.Domains, "\n") != task.Description {
		t.Fatalf("old task domains lost: %+v %v", gate, err)
	}
}

func TestReviewDomainScopeSurvivesArchiveAndRestore(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("a.archive-scope-review.test\nb.archive-scope-review.test", "goal", TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) }()
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rawRowCount(snapshot.Tables["task_intercept_rules"]) != 2 {
		t.Fatal("generated rules missing from archive")
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/scope-review-archive.tar.zst", "fixture", 100, 50); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM task_intercept_rules WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := d.GetTask(task.ID)
	if err != nil || !loaded.DomainScopeEnabled || !loaded.Paused {
		t.Fatalf("restored mode=%+v error=%v", loaded, err)
	}
	gate, err := d.Assets().LoadTaskAssetGate(task.ID)
	if err != nil || len(gate.Domains) != 2 || len(gate.AllowRules) != 2 {
		t.Fatalf("restored scope=%+v error=%v", gate, err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(snapshot.Tables["tasks"], &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0]["domain_scope_enabled"] != true {
		t.Fatal("mode not recorded in archive snapshot")
	}
}

func TestReviewDomainGateRejectsUnknownAssetID(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("allowed.scope-review.test", "goal", TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	hits, err := d.Assets().CheckAssetsIntercept(task.ID, []int64{9223372036854775000})
	if err == nil && len(hits) == 0 {
		t.Fatal("an unknown asset ID was treated as passing scope validation")
	}
}

func TestReviewDomainGateUsesOperationalTarget(t *testing.T) {
	gate := TaskAssetGate{DomainScopeEnabled: true, AllowRules: []AssetInterceptRule{{Enabled: true, Kind: "exact_domain", Pattern: "allowed.scope-review.test"}}}
	port := 22
	cases := []struct {
		asset   *Asset
		allowed bool
	}{
		{&Asset{Type: "service", URL: "https://ALLOWED.SCOPE-REVIEW.TEST./path"}, true},
		{&Asset{Type: "subdomain", Domain: "allowed.scope-review.test。"}, true},
		{&Asset{Type: "service", Domain: "allowed.scope-review.test", Port: &port, ServiceName: "ssh"}, true},
		{&Asset{Type: "service", Domain: "outside.scope-review.test", RootDomain: "allowed.scope-review.test", Port: &port, ServiceName: "ssh"}, false},
		{&Asset{Type: "service", Domain: "allowed.scope-review.test", IP: "192.0.2.1", Port: &port, ServiceName: "ssh"}, false},
		{&Asset{Type: "subdomain", Domain: "child.allowed.scope-review.test", RootDomain: "allowed.scope-review.test"}, false},
		{&Asset{Type: "ip", IP: "192.0.2.1", BoundDomains: []string{"allowed.scope-review.test"}}, false},
		{&Asset{Type: "service", URL: "https://outside.scope-review.test", Domain: "allowed.scope-review.test"}, false},
		{&Asset{Type: "service", URL: "https:///missing-host", Domain: "allowed.scope-review.test"}, false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := gate.Evaluate(tc.asset); got.Allowed != tc.allowed {
			t.Fatalf("target=%+v decision=%+v", tc.asset, got)
		}
	}
	if (TaskAssetGate{DomainScopeEnabled: true}).Evaluate(cases[0].asset).Allowed {
		t.Fatal("empty strict allow list passed")
	}
	gate.BlockRules = []AssetInterceptRule{{Enabled: true, Kind: "exact_domain", Pattern: "allowed.scope-review.test"}}
	if gate.Evaluate(cases[0].asset).Allowed {
		t.Fatal("block rule lost priority")
	}
}
