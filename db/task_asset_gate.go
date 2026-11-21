package db

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TaskAssetGate is the current persisted policy for structured asset operations.
// It is not a network sandbox for Bash, shells or MCP tools.
type TaskAssetGate struct {
	DomainScopeEnabled bool
	Domains            []string
	BlockRules         []AssetInterceptRule
	AllowRules         []AssetInterceptRule
}

func (s *AssetStore) LoadTaskAssetGate(taskID int64) (TaskAssetGate, error) {
	var gate TaskAssetGate
	var err error
	gate.BlockRules, err = s.ListAssetInterceptRules()
	if err != nil {
		return gate, fmt.Errorf("read asset block rules: %w", err)
	}
	if taskID <= 0 {
		return gate, nil
	}
	var description string
	if err := s.db.QueryRow(`SELECT domain_scope_enabled,description FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&gate.DomainScopeEnabled, &description); err != nil {
		return gate, fmt.Errorf("read task scope %d: %w", taskID, err)
	}
	block, allow, err := s.TaskInterceptRulesSplit(taskID)
	if err != nil {
		return gate, fmt.Errorf("read task asset rules: %w", err)
	}
	gate.BlockRules = append(gate.BlockRules, block...)
	gate.AllowRules = allow
	if gate.DomainScopeEnabled {
		normalized, _, err := ResolveTaskDomainScope(description, nil)
		if err != nil {
			return gate, err
		}
		gate.Domains = strings.Split(normalized, "\n")
		if !hasEnabledRule(allow) {
			return gate, fmt.Errorf("%w: task has no enabled allow rules", ErrTaskDomainScopeInvalid)
		}
	}
	return gate, nil
}

func (g TaskAssetGate) Evaluate(asset *Asset) AssetGateDecision {
	if asset == nil {
		return AssetGateDecision{Reason: "target asset is unknown"}
	}
	domains, ips, urls := asset.interceptCandidates()
	if !g.DomainScopeEnabled {
		return EvaluateAssetGate(g.BlockRules, g.AllowRules, domains, ips, urls)
	}
	if !hasEnabledRule(g.AllowRules) {
		return AssetGateDecision{Reason: "domain scope has no enabled allow rules"}
	}
	if rule, _, ok := MatchAssetInterceptRules(g.BlockRules, domains, ips, urls); ok {
		return AssetGateDecision{Reason: rule.Reason()}
	}
	// Only fields used by the actual asset operation may satisfy an allow rule.
	// Parent domains, bound domains and enrichment IPs are descriptive metadata.
	domains, ips, urls = nil, nil, nil
	switch asset.Type {
	case "root_domain", "subdomain":
		if host := normalizeTaskDomain(asset.Domain); host != "" {
			domains = []string{host}
		}
	case "service", "endpoint":
		if asset.URL != "" {
			u, err := url.Parse(asset.URL)
			if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
				urls = []string{asset.URL}
				if net.ParseIP(u.Hostname()) != nil {
					ips = []string{u.Hostname()}
				} else if host := normalizeTaskDomain(u.Hostname()); host != "" {
					domains = []string{host}
				}
			}
		} else if asset.Type == "service" && asset.IP == "" {
			// A domain-only non-HTTP service uses the domain as its target.
			if host := normalizeTaskDomain(asset.Domain); host != "" {
				domains = []string{host}
			}
		} else {
			ips = []string{asset.IP}
		}
	case "ip":
		ips = []string{asset.IP}
	}
	return EvaluateAssetGate(g.BlockRules, g.AllowRules, domains, ips, urls)
}
