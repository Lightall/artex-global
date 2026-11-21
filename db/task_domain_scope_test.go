package db

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestResolveTaskDomainScope(t *testing.T) {
	block := TaskInterceptRuleInput{Enabled: true, Action: "block", Kind: "exact_domain", Pattern: "blocked.test"}
	stale := TaskInterceptRuleInput{Enabled: true, Action: "allow", Kind: "exact_url", Pattern: "https://stale.test/"}
	description, rules, err := ResolveTaskDomainScope(" A.TEST.\r\nb.test，a.test;例子.测试 ", []TaskInterceptRuleInput{block, stale})
	wantDomains := []string{"a.test", "b.test", "xn--fsqu00a.xn--0zwm56d"}
	if err != nil || description != strings.Join(wantDomains, "\n") {
		t.Fatalf("description=%q error=%v", description, err)
	}
	if len(rules) != 4 || rules[0] != block {
		t.Fatalf("block rule lost or stale allow retained: %+v", rules)
	}
	for i, domain := range wantDomains {
		if r := rules[i+1]; !r.Enabled || r.Action != "allow" || r.Kind != "exact_domain" || r.Pattern != domain {
			t.Fatalf("generated rule=%+v", r)
		}
		if !EvaluateAssetGate([]AssetInterceptRule{}, []AssetInterceptRule{{Enabled: true, Kind: rules[i+1].Kind, Pattern: rules[i+1].Pattern}}, []string{domain}, nil, nil).Allowed {
			t.Fatalf("generated rule did not allow %s", domain)
		}
	}
	if EvaluateAssetGate(nil, []AssetInterceptRule{{Enabled: true, Kind: "exact_domain", Pattern: "a.test"}}, []string{"outside.test"}, nil, nil).Allowed {
		t.Fatal("unlisted domain allowed")
	}
}

func TestResolveTaskDomainScopeRejectsWholeInvalidList(t *testing.T) {
	for _, bad := range []string{"", " ", "<测试域名1>", "https://a.test", "a.test/path", "a.test:8443", "*.a.test", "127.0.0.1", "[::1]", "user@a.test", "a..test", "-a.test", "a-.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a", MaxTaskTemplateTextRunes+1)} {
		t.Run(fmt.Sprintf("%q", bad[:min(len(bad), 30)]), func(t *testing.T) {
			description, rules, err := ResolveTaskDomainScope("valid.test\n"+bad, nil)
			if strings.TrimSpace(bad) == "" {
				description, rules, err = ResolveTaskDomainScope(bad, nil)
			}
			if !errors.Is(err, ErrTaskDomainScopeInvalid) || description != "" || rules != nil {
				t.Fatalf("partially accepted invalid input: %q %+v %v", description, rules, err)
			}
		})
	}
}

func TestDomainScopeTaskAndTemplatePersistence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	var tasksBefore, explorationsBefore int
	if err := d.QueryRow("SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM explorations)").Scan(&tasksBefore, &explorationsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTaskWithOptions("a.test\n*.outside.test", "goal", TaskCreateOptions{DomainScopeEnabled: true}); !errors.Is(err, ErrTaskDomainScopeInvalid) {
		t.Fatalf("invalid create=%v", err)
	}
	var tasksAfter, explorationsAfter int
	_ = d.QueryRow("SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM explorations)").Scan(&tasksAfter, &explorationsAfter)
	if tasksBefore != tasksAfter || explorationsBefore != explorationsAfter {
		t.Fatal("invalid domain list persisted a partial task")
	}
	task, err := d.CreateTaskWithOptions("A.TEST.\nb.test\na.test", "goal", TaskCreateOptions{DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	rules, err := d.Assets().ListTaskInterceptRules(task.ID)
	if err != nil || len(rules) != 2 || task.Description != "a.test\nb.test" {
		t.Fatalf("task=%+v rules=%+v err=%v", task, rules, err)
	}
	for _, rule := range rules {
		if rule.Kind != "exact_domain" || rule.Action != "allow" || !rule.Enabled || !strings.Contains(task.Description, rule.Pattern) {
			t.Fatalf("unexpected persisted rule %+v", rule)
		}
	}
	template, err := d.CreateTaskTemplate(TaskTemplateInput{Name: fmt.Sprintf("domain-mode-%d", time.Now().UnixNano()), Description: "<domains>", Goal: "goal", DomainScopeEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTaskTemplate(template.ID)
	goal := "new goal"
	updated, err := d.PatchTaskTemplate(template.ID, TaskTemplatePatch{Goal: &goal})
	if err != nil || !updated.DomainScopeEnabled {
		t.Fatalf("partial patch lost mode: %+v %v", updated, err)
	}
	disabled := false
	updated, err = d.PatchTaskTemplate(template.ID, TaskTemplatePatch{DomainScopeEnabled: &disabled})
	if err != nil || updated.DomainScopeEnabled || updated.Goal != goal {
		t.Fatalf("false mode not persisted: %+v %v", updated, err)
	}
	loaded, err := d.GetTaskTemplate(template.ID)
	if err != nil || !reflect.DeepEqual(loaded, updated) {
		t.Fatalf("mode readback mismatch: %+v %v", loaded, err)
	}
}
