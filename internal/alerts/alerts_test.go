package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

func watcher(t *testing.T) (*Watcher, *time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	w := &Watcher{cfg: Config{Refusals: 3, Window: time.Minute, Cooldown: 10 * time.Minute, ConsoleURL: "https://console.example/"},
		denies: map[string][]time.Time{}, lastSent: map[string]time.Time{}, now: func() time.Time { return now }}
	return w, &now
}

func TestRefusalBurstWindowAndCooldown(t *testing.T) {
	w, now := watcher(t)
	deny := func(id int64) []Alert {
		return w.Evaluate(store.Record{ID: id, Identity: "bot:x", Decision: "deny", Reason: "path denied by policy: /etc/shadow"})
	}
	if len(deny(1)) != 0 || len(deny(2)) != 0 {
		t.Fatal("alert before the threshold")
	}
	a := deny(3)
	if len(a) != 1 || a[0].Rule != "refusal_burst" || a[0].Link != "https://console.example/activity/3" {
		t.Fatalf("burst alert: %+v", a)
	}
	if len(deny(4)) != 0 {
		t.Fatal("cooldown not applied")
	}
	// Refusals spread wider than the window never add up.
	*now = now.Add(11 * time.Minute)
	deny(5)
	*now = now.Add(2 * time.Minute)
	deny(6)
	*now = now.Add(2 * time.Minute)
	if len(deny(7)) != 0 {
		t.Fatal("refusals outside the window counted")
	}
	// Another identity has its own count.
	for i := int64(10); i < 12; i++ {
		w.Evaluate(store.Record{ID: i, Identity: "bot:y", Decision: "deny"})
	}
	if a := w.Evaluate(store.Record{ID: 12, Identity: "bot:y", Decision: "deny"}); len(a) != 1 {
		t.Fatal("second identity's burst missed")
	}
}

func TestHostRefusalAndAdmin(t *testing.T) {
	w, _ := watcher(t)
	a := w.Evaluate(store.Record{ID: 1, Identity: "bot:x", Host: "web-1", Tool: "journal", Decision: "error",
		Reason: "refused by target helper: invalid request: bad unit name"})
	if len(a) != 1 || a[0].Rule != "host_refusal" {
		t.Fatalf("host refusal: %+v", a)
	}
	for i, tool := range []string{"kill", "unkill", "token_revoke", "token_create"} {
		if a := w.Evaluate(store.Record{ID: int64(2 + i), Identity: "cli:ops", Decision: "admin", Tool: tool, Args: "bot:x"}); len(a) != 1 {
			t.Errorf("admin %s: %+v", tool, a)
		}
	}
	for _, r := range []store.Record{
		{Decision: "allow"}, {Decision: "result"}, {Decision: "error", Reason: "call timed out"},
		{Decision: "issue", Tool: "mirror_cert"}, {Decision: "allow", Tool: "policy_reload"},
	} {
		if a := w.Evaluate(r); len(a) != 0 {
			t.Errorf("unexpected alert for %+v: %+v", r, a)
		}
	}
}

func TestSinksPayloads(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got[r.URL.Path] = body
		mu.Unlock()
	}))
	defer srv.Close()
	a := Alert{Rule: "host_refusal", Title: "Target refused a call the server allowed", Identity: "bot:x",
		Host: "web-1", Detail: "bad unit", Link: "https://console.example/activity/9"}
	ctx := context.Background()
	if err := (&Slack{URL: srv.URL + "/slack"}).Send(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := (&Teams{URL: srv.URL + "/teams"}).Send(ctx, a); err != nil {
		t.Fatal(err)
	}
	slack, _ := got["/slack"]["text"].(string)
	if !strings.Contains(slack, "Target refused") || !strings.Contains(slack, "<https://console.example/activity/9|") {
		t.Fatalf("slack payload %q", slack)
	}
	b, _ := json.Marshal(got["/teams"])
	teams := string(b)
	for _, want := range []string{`"type":"message"`, "application/vnd.microsoft.card.adaptive", "AdaptiveCard", "Action.OpenUrl", "activity/9", "Host: web-1"} {
		if !strings.Contains(teams, want) {
			t.Errorf("teams payload lacks %s: %s", want, teams)
		}
	}
}

func TestNewAndRun(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(Config{Enabled: true}, nil, nil); err == nil {
		t.Fatal("enabled with no sink accepted")
	}
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte("https://hooks.example/x"), 0o644)
	if _, err := New(Config{Enabled: true, SlackWebhookFile: loose}, nil, nil); err == nil {
		t.Fatal("world-readable webhook file accepted")
	}
	plain := filepath.Join(dir, "plain")
	_ = os.WriteFile(plain, []byte("http://hooks.example/x"), 0o600)
	if _, err := New(Config{Enabled: true, TeamsWebhookFile: plain}, nil, nil); err == nil {
		t.Fatal("non-https webhook accepted")
	}

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	orig := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = orig }()
	hook := filepath.Join(dir, "hook")
	_ = os.WriteFile(hook, []byte(srv.URL+"\n"), 0o600)
	st, err := store.Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A record from before start-up is not replayed.
	_, _ = st.Append(ctx, store.Record{Identity: "cli:ops", Decision: "admin", Tool: "kill", Args: "bot:old"})
	w, err := New(Config{Enabled: true, SlackWebhookFile: hook, TeamsWebhookFile: hook}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	w.Interval = 20 * time.Millisecond
	go w.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	_, _ = st.Append(ctx, store.Record{Identity: "cli:ops", Decision: "admin", Tool: "kill", Args: "bot:new"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(bodies)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("want one Slack and one Teams delivery, got %d: %v", len(bodies), bodies)
	}
	for _, b := range bodies {
		if strings.Contains(b, "bot:old") || !strings.Contains(b, "bot:new") {
			t.Fatalf("delivery %s", b)
		}
	}
}
