package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func TestAuditChainAndAppendOnly(t *testing.T) {
	s, path := open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Append(ctx, Record{Identity: "user:a", Host: "h", Tool: "ps", Decision: "allow"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	n, broken, err := s.Verify(ctx)
	if err != nil || n != 20 || broken != 0 {
		t.Fatalf("verify: n=%d broken=%d err=%v", n, broken, err)
	}
	if _, err := s.db.Exec(`UPDATE audit SET tool='x' WHERE id=3`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update should be blocked: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM audit WHERE id=3`); err == nil {
		t.Fatal("delete should be blocked")
	}

	// Out-of-band tamper: drop the trigger with a raw connection and edit.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, q := range []string{`DROP TRIGGER audit_no_update`, `UPDATE audit SET tool='rm' WHERE id=7`} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, broken, _ := s.Verify(ctx); broken != 7 {
		t.Fatalf("tamper not detected at 7, got %d", broken)
	}
}

func TestKillSwitch(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if d, _, _ := s.IsDisabled(ctx, "bot:x"); d {
		t.Fatal("should start enabled")
	}
	_ = s.Disable(ctx, "bot:x", "test")
	if d, r, _ := s.IsDisabled(ctx, "bot:x"); !d || r != "test" {
		t.Fatal("identity kill failed")
	}
	if d, _, _ := s.IsDisabled(ctx, "bot:y"); d {
		t.Fatal("other identity affected")
	}
	_ = s.Disable(ctx, GlobalKill, "all stop")
	if d, _, _ := s.IsDisabled(ctx, "bot:y"); !d {
		t.Fatal("global kill failed")
	}
	_ = s.Enable(ctx, GlobalKill)
	_ = s.Enable(ctx, "bot:x")
	if d, _, _ := s.IsDisabled(ctx, "bot:x"); d {
		t.Fatal("enable failed")
	}
}

func TestTokens(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	tok, err := s.CreateToken(ctx, "triage-bot", "ops", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if name, _, err := s.LookupToken(ctx, tok); err != nil || name != "triage-bot" {
		t.Fatalf("lookup: %q %v", name, err)
	}
	if _, _, err := s.LookupToken(ctx, tok+"x"); err == nil {
		t.Fatal("wrong token accepted")
	}
	if _, _, err := s.LookupToken(ctx, "notprefixed"); err == nil {
		t.Fatal("unprefixed accepted")
	}
	now = now.Add(2 * time.Hour)
	if _, _, err := s.LookupToken(ctx, tok); err == nil {
		t.Fatal("expired token accepted")
	}
	now = now.Add(-2 * time.Hour)
	_ = s.RevokeToken(ctx, "triage-bot")
	if _, _, err := s.LookupToken(ctx, tok); err == nil {
		t.Fatal("revoked token accepted")
	}
	if _, err := s.CreateToken(ctx, "x", "o", 100*24*time.Hour); err == nil {
		t.Fatal("ttl > 90d accepted")
	}
	var stored string
	_ = s.db.QueryRow(`SELECT hash FROM tokens WHERE name='triage-bot'`).Scan(&stored)
	if strings.Contains(stored, tok) || stored == tok {
		t.Fatal("plaintext token stored")
	}
}

func TestHMACChainNeedsKey(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.SetAuditKey([]byte("test-key-not-secret"))
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, Record{Identity: "bot:a", Tool: "ps", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, broken, _ := s.Verify(ctx); broken != 0 {
		t.Fatal("chain broken with the right key")
	}
	s.SetAuditKey([]byte("wrong"))
	if _, broken, _ := s.Verify(ctx); broken != 1 {
		t.Fatalf("wrong key should break at record 1, got %d", broken)
	}
	s.SetAuditKey(nil)
	if _, broken, _ := s.Verify(ctx); broken != 1 {
		t.Fatal("unkeyed verify should not accept an HMAC chain")
	}
}
