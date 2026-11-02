// Package redact removes likely secrets from tool output before it reaches
// an agent's LLM.
//
// This is a filter, not a boundary: it will miss secrets in formats it does
// not know. It is tuned to prefer false positives (redacting a harmless
// string) over false negatives. Every replacement is counted so the audit log
// records how much was removed.
package redact

import (
	"math"
	"regexp"
	"strings"
)

// Rule replaces matches of Re. If Group > 0, only that submatch is replaced
// (so "password=" stays readable and only the value is hidden).
type Rule struct {
	Name  string
	Re    *regexp.Regexp
	Group int
}

// Redactor applies rules in order.
type Redactor struct {
	Rules []Rule
	// Entropy enables the generic high-entropy token rule.
	Entropy bool
}

func r(name, expr string, group int) Rule {
	return Rule{Name: name, Re: regexp.MustCompile(expr), Group: group}
}

// Default returns the built-in rule set.
func Default() *Redactor {
	return &Redactor{
		Entropy: true,
		Rules: []Rule{
			r("private-key", `(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|\z)`, 0),
			r("aws-access-key-id", `\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b`, 0),
			r("aws-secret", `(?i)(aws_?secret_?access_?key|aws_?session_?token)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{16,})`, 2),
			r("jwt", `\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, 0),
			r("github-token", `\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b`, 0),
			r("slack-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}\b`, 0),
			r("slack-webhook", `https://hooks\.slack\.com/services/[A-Za-z0-9/]+`, 0),
			r("google-api-key", `\bAIza[0-9A-Za-z_-]{35}\b`, 0),
			r("stripe-key", `\b[rs]k_(live|test)_[0-9A-Za-z]{16,}\b`, 0),
			r("openai-anthropic-key", `\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b`, 0),
			r("bearer", `(?i)\b(authorization|bearer)\b["']?\s*[:=]?\s*(bearer\s+)?([A-Za-z0-9._~+/=-]{16,})`, 3),
			r("url-credentials", `(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+):([^\s@/]+)@`, 2),
			r("assignment", `(?i)\b([A-Za-z0-9_.-]*(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)[A-Za-z0-9_.-]*)["']?\s*(=|:|=>)\s*("[^"\n]*"|'[^'\n]*'|[^\s,;&"']+)`, 5),
			// Command lines (ps output, shell history, unit files).
			r("mysql-p", `\b(mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]*?\s-p([^\s]+)`, 2),
			r("sshpass-p", `\bsshpass\b[^\n]*?\s-p\s*([^\s]+)`, 1),
			r("flag-secret", `(?i)--(password|passwd|pass|secret|token|api-?key|access-key|secret-key)(=|\s+)([^\s"']+)`, 3),
			r("env-space", `\b([A-Z0-9_]*(PASS|PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*)[ \t]+([^\s=:]\S*)`, 3),
			r("shadow-hash", `\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:$]*\$[A-Za-z0-9./]{8,}`, 0),
		},
	}
}

const mask = "[REDACTED]"

// Redact returns s with secrets replaced, and the number of replacements.
func (rd *Redactor) Redact(s string) (string, int) {
	total := 0
	for _, rule := range rd.Rules {
		s = replace(rule, s, &total)
	}
	if rd.Entropy {
		s = entropyPass(s, &total)
	}
	return s, total
}

func replace(rule Rule, s string, total *int) string {
	if rule.Group == 0 {
		return rule.Re.ReplaceAllStringFunc(s, func(string) string {
			*total++
			return mask
		})
	}
	idx := rule.Re.FindAllStringSubmatchIndex(s, -1)
	if len(idx) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		gs, ge := m[2*rule.Group], m[2*rule.Group+1]
		if gs < 0 || ge <= gs {
			continue
		}
		v := s[gs:ge]
		if v == mask || strings.Trim(v, `"'`) == mask || strings.Trim(v, `"'`) == "" {
			continue
		}
		b.WriteString(s[last:gs])
		b.WriteString(mask)
		last = ge
		*total++
	}
	b.WriteString(s[last:])
	return b.String()
}

// tokenRe finds candidate opaque tokens for the entropy pass.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)

func entropyPass(s string, total *int) string {
	return tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		if looksLikeSecret(tok) {
			*total++
			return mask
		}
		return tok
	})
}

// looksLikeSecret flags long mixed-class strings with high Shannon entropy.
// Hex-only strings (hashes, container IDs, commit SHAs) are common and
// harmless in logs, so they are left alone.
func looksLikeSecret(tok string) bool {
	if isHex(tok) {
		return false
	}
	var lower, upper, digit bool
	for _, c := range tok {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	if !(lower && upper && digit) {
		return false
	}
	return shannon(tok) >= 4.3
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func shannon(s string) float64 {
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	h := 0.0
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}
