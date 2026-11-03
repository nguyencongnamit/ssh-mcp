package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

var tools = []string{"journal", "read_file", "ps", "host_overview"}

const sample = `
rules:
  - name: oncall
    who: { entra_group: platform-oncall }
    hosts: { tags: { env: [staging, prod] } }
    tools: ["*"]
  - name: devs
    who: { entra_group: developers }
    hosts: { tags: { env: [staging] } }
    tools: [journal, read_file]
  - name: bot
    who: { token: triage-bot }
    hosts: { tags: { env: [prod], team: [platform] } }
    tools: [journal]
    rate: 2/min
paths:
  allow: [/var/log/]
  deny: [/var/log/private/]
`

var (
	staging = inventory.Host{ID: "i-stg", Tags: map[string]string{"env": "staging"}}
	prod    = inventory.Host{ID: "i-prd", Tags: map[string]string{"env": "prod", "team": "platform"}}
	prodOth = inventory.Host{ID: "i-prd2", Tags: map[string]string{"env": "prod", "team": "data"}}
	untag   = inventory.Host{ID: "i-none", Tags: map[string]string{}}

	oncall = identity.Identity{Kind: identity.KindUser, Name: "00000000-0000-4000-8000-00000000000a", Groups: []string{"platform-oncall"}}
	dev    = identity.Identity{Kind: identity.KindUser, Name: "00000000-0000-4000-8000-00000000000b", Groups: []string{"developers"}}
	bot    = identity.Identity{Kind: identity.KindBot, Name: "triage-bot"}
	nobody = identity.Identity{Kind: identity.KindUser, Name: "00000000-0000-4000-8000-00000000000c"}
	// A user who names themself like the bot must not get the bot's grant.
	spoof = identity.Identity{Kind: identity.KindUser, Name: "triage-bot", Groups: []string{"triage-bot"}}
)

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(sample), tools)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckMatrix(t *testing.T) {
	p := load(t)
	cases := []struct {
		id    identity.Identity
		host  inventory.Host
		tool  string
		allow bool
	}{
		{oncall, prod, "ps", true},
		{oncall, staging, "read_file", true},
		{oncall, untag, "ps", false},
		{dev, staging, "journal", true},
		{dev, staging, "ps", false},
		{dev, prod, "journal", false},
		{bot, prod, "journal", true},
		{bot, prodOth, "journal", false},
		{bot, prod, "read_file", false},
		{nobody, staging, "journal", false},
		{spoof, prod, "journal", false},
	}
	for _, c := range cases {
		d := p.Check(c.id, c.host, c.tool)
		if d.Allow != c.allow {
			t.Errorf("%s on %s %s: got %v (%s), want %v", c.id.Key(), c.host.ID, c.tool, d.Allow, d.Reason, c.allow)
		}
	}
}

func TestRateLimit(t *testing.T) {
	p := load(t)
	now := time.Unix(0, 0)
	p.limiter.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if !p.Check(bot, prod, "journal").Allow {
			t.Fatalf("call %d should pass", i)
		}
	}
	if d := p.Check(bot, prod, "journal"); d.Allow || !strings.Contains(d.Reason, "rate") {
		t.Fatalf("third call should be rate limited: %+v", d)
	}
	now = now.Add(31 * time.Second)
	if !p.Check(bot, prod, "journal").Allow {
		t.Fatal("bucket should refill")
	}
}

func TestPathsMergeDefaultDeny(t *testing.T) {
	p := load(t)
	if p.CheckPath("/var/log/private/x", false) || p.CheckPath("/var/log/app/.env", false) || p.CheckPath("/etc/hosts", false) {
		t.Fatal("path rules not applied")
	}
	if !p.CheckPath("/var/log/syslog", false) {
		t.Fatal("allowed path refused")
	}
}

func TestParseRejects(t *testing.T) {
	bad := map[string]string{
		"two whos":             "rules:\n- who: {entra_group: a, token: b}\n  hosts: {all: true}\n  tools: [ps]\n",
		"no who":               "rules:\n- who: {}\n  hosts: {all: true}\n  tools: [ps]\n",
		"no hosts":             "rules:\n- who: {token: b}\n  hosts: {}\n  tools: [ps]\n",
		"all and tags":         "rules:\n- who: {token: b}\n  hosts: {all: true, tags: {env: [x]}}\n  tools: [ps]\n",
		"empty tag":            "rules:\n- who: {token: b}\n  hosts: {tags: {env: []}}\n  tools: [ps]\n",
		"unknown tool":         "rules:\n- who: {token: b}\n  hosts: {all: true}\n  tools: [shell]\n",
		"no tools":             "rules:\n- who: {token: b}\n  hosts: {all: true}\n  tools: []\n",
		"bad rate":             "rules:\n- who: {token: b}\n  hosts: {all: true}\n  tools: [ps]\n  rate: fast\n",
		"typo field":           "rules:\n- who: {token: b}\n  host: {all: true}\n  tools: [ps]\n",
		"user by email":        "rules:\n- who: {user: a@example.test}\n  hosts: {all: true}\n  tools: [ps]\n",
		"both group spellings": "rules:\n- who: {group: a, entra_group: a}\n  hosts: {all: true}\n  tools: [ps]\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y), tools); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestGenericGroupAndSubject(t *testing.T) {
	y := "rules:\n" +
		"- who: {group: sre}\n  hosts: {all: true}\n  tools: [ps]\n" +
		"- who: {user: 00uAbC123xyz}\n  hosts: {all: true}\n  tools: [journal]\n"
	p, err := Parse([]byte(y), tools)
	if err != nil {
		t.Fatal(err)
	}
	sre := identity.Identity{Kind: identity.KindUser, Name: "u1", Groups: []string{"sre"}}
	okta := identity.Identity{Kind: identity.KindUser, Name: "00uAbC123xyz"}
	oktaCase := identity.Identity{Kind: identity.KindUser, Name: "00uabc123xyz"}
	bot := identity.Identity{Kind: identity.KindBot, Name: "sre", Groups: []string{"sre"}}
	for _, c := range []struct {
		id    identity.Identity
		tool  string
		allow bool
	}{
		{sre, "ps", true}, {sre, "journal", false},
		{okta, "journal", true}, {oktaCase, "journal", false}, // subjects are case-sensitive
		{bot, "ps", false}, // groups never apply to bots
	} {
		if got := p.Check(c.id, staging, c.tool).Allow; got != c.allow {
			t.Errorf("%s %s: allowed=%v, want %v", c.id.Key(), c.tool, got, c.allow)
		}
	}
}
