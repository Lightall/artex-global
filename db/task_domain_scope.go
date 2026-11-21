package db

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var ErrTaskDomainScopeInvalid = errors.New("invalid test domain list")

// ResolveTaskDomainScope derives both agent context and allow rules from one input.
// Existing block rules are retained; generated allows replace any stale allows.
// It performs no DNS lookups or other network requests.
func ResolveTaskDomainScope(raw string, existing []TaskInterceptRuleInput) (string, []TaskInterceptRuleInput, error) {
	if utf8.RuneCountInString(raw) > MaxTaskTemplateTextRunes {
		return "", nil, fmt.Errorf("%w: domain list exceeds %d characters", ErrTaskDomainScopeInvalid, MaxTaskTemplateTextRunes)
	}
	items := strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(",，;；", r)
	})
	if len(items) == 0 {
		return "", nil, fmt.Errorf("%w: enter at least one domain", ErrTaskDomainScopeInvalid)
	}
	domains := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		domain := normalizeTaskDomain(item)
		if domain == "" {
			return "", nil, fmt.Errorf("%w: %q must be a domain without a scheme, port, path, wildcard or IP address", ErrTaskDomainScopeInvalid, item)
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	rules := make([]TaskInterceptRuleInput, 0, len(existing)+len(domains))
	for _, rule := range existing {
		if rule.Action != "allow" {
			rules = append(rules, rule)
		}
	}
	for _, domain := range domains {
		rules = append(rules, TaskInterceptRuleInput{
			Enabled: true, Action: "allow", Kind: "exact_domain", Pattern: domain,
			Note: "Generated from the task domain list",
		})
	}
	return strings.Join(domains, "\n"), rules, nil
}

func normalizeTaskDomain(raw string) string {
	domain, err := idna.Lookup.ToASCII(raw)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if err != nil || !validTaskDomain(domain) {
		return ""
	}
	return domain
}

func validTaskDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	hasLetter := false
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
				hasLetter = true
			case c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return hasLetter
}
