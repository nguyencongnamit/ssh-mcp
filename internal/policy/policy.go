// Package policy decides which identities may call which tools on which hosts.
//
// Deny by default: a call is allowed only if at least one rule matches the
// caller, the host and the tool. Path rules for file tools are checked here
// too, before anything leaves the server (the helper re-checks on the host).
package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
)

// Who selects callers. Exactly one field must be set.
type Who struct {
	EntraGroup string `yaml:"entra_group,omitempty"`
	// User is an Entra object ID (oid). Names and emails are mutable and
	// are rejected.
	User  string `yaml:"user,omitempty"`
	Token string `yaml:"token,omitempty"`
}

// Hosts selects targets: every listed tag must match one of its values.
type Hosts struct {
	All  bool                `yaml:"all,omitempty"`
	Tags map[string][]string `yaml:"tags,omitempty"`
}

// Rule grants tools on hosts to callers.
type Rule struct {
	Name  string   `yaml:"name,omitempty"`
	Who   Who      `yaml:"who"`
	Hosts Hosts    `yaml:"hosts"`
	Tools []string `yaml:"tools"`
	// Rate like "60/min" or "10/s". Empty = default.
	Rate string `yaml:"rate,omitempty"`

	rate rate
}

// Policy is the whole file.
type Policy struct {
	Rules []Rule            `yaml:"rules"`
	Paths pathpolicy.Policy `yaml:"paths"`

	limiter *limiter
}

// DefaultRate applies when a matching rule has no rate.
const DefaultRate = "120/min"

// Load reads and validates a policy file.
func Load(path string, knownTools []string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, knownTools)
}

// Parse validates policy YAML.
func Parse(b []byte, knownTools []string) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	known := map[string]bool{"*": true}
	for _, t := range knownTools {
		known[t] = true
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("rule %d", i)
		}
		n := 0
		for _, s := range []string{r.Who.EntraGroup, r.Who.User, r.Who.Token} {
			if s != "" {
				n++
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("policy %s: who must set exactly one of entra_group, user, token", label)
		}
		if r.Who.User != "" {
			k, err := identity.NormalizeKey(identity.KindUser + ":" + r.Who.User)
			if err != nil {
				return nil, fmt.Errorf("policy %s: %w", label, err)
			}
			r.Who.User = strings.TrimPrefix(k, identity.KindUser+":")
		}
		if r.Who.Token != "" {
			if _, err := identity.NormalizeKey(identity.KindBot + ":" + r.Who.Token); err != nil {
				return nil, fmt.Errorf("policy %s: %w", label, err)
			}
		}
		if !r.Hosts.All && len(r.Hosts.Tags) == 0 {
			return nil, fmt.Errorf("policy %s: hosts needs tags or all: true", label)
		}
		if r.Hosts.All && len(r.Hosts.Tags) > 0 {
			return nil, fmt.Errorf("policy %s: hosts cannot set both all and tags", label)
		}
		for k, vs := range r.Hosts.Tags {
			if len(vs) == 0 {
				return nil, fmt.Errorf("policy %s: tag %q has no values", label, k)
			}
		}
		if len(r.Tools) == 0 {
			return nil, fmt.Errorf("policy %s: tools is empty", label)
		}
		for _, t := range r.Tools {
			if !known[t] {
				return nil, fmt.Errorf("policy %s: unknown tool %q", label, t)
			}
		}
		rs := r.Rate
		if rs == "" {
			rs = DefaultRate
		}
		rt, err := parseRate(rs)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", label, err)
		}
		r.rate = rt
	}
	if len(p.Paths.Allow) == 0 {
		p.Paths.Allow = pathpolicy.Default().Allow
	}
	// The built-in deny list always applies.
	p.Paths.Deny = append(p.Paths.Deny, pathpolicy.Default().Deny...)
	p.limiter = newLimiter()
	return &p, nil
}

func (w Who) matches(id identity.Identity) bool {
	switch {
	case w.Token != "":
		return id.Kind == identity.KindBot && id.Name == w.Token
	case w.User != "":
		return id.Kind == identity.KindUser && id.Name == w.User
	case w.EntraGroup != "":
		if id.Kind != identity.KindUser {
			return false
		}
		for _, g := range id.Groups {
			if g == w.EntraGroup {
				return true
			}
		}
	}
	return false
}

func (h Hosts) matches(host inventory.Host) bool {
	if h.All {
		return true
	}
	for k, vs := range h.Tags {
		v, ok := host.Tags[k]
		if !ok {
			return false
		}
		hit := false
		for _, want := range vs {
			if v == want {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func toolMatch(tools []string, tool string) bool {
	for _, t := range tools {
		if t == "*" || t == tool {
			return true
		}
	}
	return false
}

// Decision is the outcome of Check.
type Decision struct {
	Allow  bool
	Rule   string
	Reason string
}

// CanSeeHost reports whether any rule lets id reach host at all.
func (p *Policy) CanSeeHost(id identity.Identity, host inventory.Host) bool {
	for _, r := range p.Rules {
		if r.Who.matches(id) && r.Hosts.matches(host) {
			return true
		}
	}
	return false
}

// HasAnyRule reports whether any rule names id. list_hosts uses it: the
// host list itself is then filtered per host with CanSeeHost.
func (p *Policy) HasAnyRule(id identity.Identity) bool {
	for _, r := range p.Rules {
		if r.Who.matches(id) {
			return true
		}
	}
	return false
}

// ToolNames lists the tools any rule grants ("*" expanded is not known here,
// so it is returned as-is).
func (p *Policy) ToolNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range p.Rules {
		for _, t := range r.Tools {
			if t != "*" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// RulesForHost names the rules that reach host, with who they grant it to.
func (p *Policy) RulesForHost(host inventory.Host) []string {
	var out []string
	for i, r := range p.Rules {
		if !r.Hosts.matches(host) {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		who := r.Who.Token
		switch {
		case r.Who.EntraGroup != "":
			who = "group " + r.Who.EntraGroup
		case r.Who.User != "":
			who = "user " + r.Who.User
		default:
			who = "bot " + who
		}
		out = append(out, name+" → "+who)
	}
	return out
}

// Check decides one call and consumes rate budget when allowed.
func (p *Policy) Check(id identity.Identity, host inventory.Host, tool string) Decision {
	for i, r := range p.Rules {
		if r.Who.matches(id) && r.Hosts.matches(host) && toolMatch(r.Tools, tool) {
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("rule-%d", i)
			}
			if !p.limiter.allow(id.Key()+"|"+name, r.rate) {
				return Decision{Allow: false, Rule: name, Reason: "rate limit exceeded"}
			}
			return Decision{Allow: true, Rule: name}
		}
	}
	return Decision{Allow: false, Reason: "no rule grants this tool on this host"}
}

// CheckPath applies the server-side path rules.
func (p *Policy) CheckPath(path string, isDir bool) bool { return p.Paths.Allowed(path, isDir) }

// ---------------------------------------------------------------- rate limit

type rate struct {
	n   int
	per time.Duration
}

func parseRate(s string) (rate, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return rate{}, fmt.Errorf("bad rate %q (want N/s, N/min or N/h)", s)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return rate{}, fmt.Errorf("bad rate %q", s)
	}
	var per time.Duration
	switch parts[1] {
	case "s", "sec":
		per = time.Second
	case "m", "min":
		per = time.Minute
	case "h", "hour":
		per = time.Hour
	default:
		return rate{}, fmt.Errorf("bad rate unit in %q", s)
	}
	return rate{n: n, per: per}, nil
}

// limiter is a token bucket per key.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}, now: time.Now} }

func (l *limiter) allow(key string, r rate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(r.n), last: now}
		l.buckets[key] = b
	}
	refill := now.Sub(b.last).Seconds() * float64(r.n) / r.per.Seconds()
	b.tokens = min(float64(r.n), b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
