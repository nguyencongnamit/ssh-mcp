package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/policy"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

type fakePaths struct {
	mu  sync.Mutex
	set []string
}

func (f *fakePaths) SetPaths(js string) { f.mu.Lock(); f.set = append(f.set, js); f.mu.Unlock() }

type fakeReset struct{ n int }

func (f *fakeReset) Reset() { f.n++ }

const polA = `rules:
- name: bot
  who: { token: b }
  hosts: { all: true }
  tools: [ps]
  rate: 1/hour
paths: { allow: [/var/log/] }
`

func TestReload(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(polA)
	p0, err := policy.Load(file, KnownTools)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := policy.NewHolder(p0)
	ca, mir := &fakePaths{}, &fakeReset{}
	r := &Reloader{Path: file, Holder: h, CA: ca, Mirrors: mir, SandboxPrefixes: []string{"/var/log/"},
		Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	bot := identity.Identity{Kind: identity.KindBot, Name: "b"}
	host := inventory.Host{ID: "h"}
	ctx := context.Background()

	// Spend the bot's one call per hour.
	if !h.Load().Check(bot, host, "ps").Allow || h.Load().Check(bot, host, "ps").Allow {
		t.Fatal("rate limit setup")
	}

	// Same paths, new tool: applied, no mirror reset, rate budget kept.
	write(strings.Replace(polA, "tools: [ps]", "tools: [ps, journal]", 1))
	if err := r.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if mir.n != 0 || len(ca.set) != 0 {
		t.Fatalf("paths unchanged but CA set %d times, mirrors reset %d times", len(ca.set), mir.n)
	}
	if h.Load().Check(bot, host, "ps").Allow {
		t.Fatal("reload reset the rate limit")
	}

	// Invalid file: refused, previous policy stays.
	before := h.Load()
	write("rules: [ {who: {}} ]")
	if err := r.Reload(ctx); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if h.Load() != before {
		t.Fatal("invalid policy replaced the running one")
	}

	// Paths no longer contain the sandbox prefix: refused.
	write(strings.Replace(polA, "/var/log/", "/etc/", 1))
	if err := r.Reload(ctx); err == nil || h.Load() != before {
		t.Fatalf("policy without the sandbox prefix accepted: %v", err)
	}

	// Paths change: CA updated, mirrors reset.
	write(strings.Replace(polA, "allow: [/var/log/]", "allow: [/var/log/, /etc/]", 1))
	if err := r.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ca.set) != 1 || !strings.Contains(ca.set[0], "/etc/") || mir.n != 1 {
		t.Fatalf("paths changed: CA set %v, mirrors reset %d", ca.set, mir.n)
	}

	// Every attempt is audited and the chain still verifies.
	recs, err := st.Query(ctx, store.Filter{Tool: "policy_reload"})
	if err != nil {
		t.Fatal(err)
	}
	var allow, refused int
	for _, rec := range recs {
		switch rec.Decision {
		case "allow":
			allow++
		case "error":
			refused++
		}
	}
	if allow != 2 || refused != 2 {
		t.Fatalf("audit: %d applied, %d refused; want 2 and 2", allow, refused)
	}
	if _, broken, err := st.Verify(ctx); err != nil || broken != 0 {
		t.Fatalf("audit chain: broken=%d err=%v", broken, err)
	}
}
