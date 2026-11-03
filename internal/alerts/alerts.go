// Package alerts watches the audit log and notifies Slack and Microsoft
// Teams about events worth a human look. It is off by default.
//
// It reads the audit log after the fact (no hook in the request path), so a
// slow or failing webhook never delays or blocks a call. Rules are fixed and
// deterministic; no model is involved:
//
//   - refusal burst: one identity refused Refusals times within Window
//   - host refusal: the server allowed a call but the target's helper refused
//     it (a policy mismatch, or someone probing for a bypass)
//   - admin action: kill switch, unkill, token revoke from the console
//
// Each alert links to the call trail in the admin console.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

// Config is the alerts section of ssh-mcp.yaml.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// Webhook URLs are secrets, so they are read from files (0600).
	SlackWebhookFile string `yaml:"slack_webhook_file"`
	TeamsWebhookFile string `yaml:"teams_webhook_file"`
	// ConsoleURL, e.g. https://localhost:8444, builds call-trail links.
	ConsoleURL string        `yaml:"console_url"`
	Refusals   int           `yaml:"refusals"` // default 5
	Window     time.Duration `yaml:"window"`   // default 10m
	Cooldown   time.Duration `yaml:"cooldown"` // default 30m, per rule and identity
}

// Alert is one notification.
type Alert struct {
	Rule     string
	Title    string
	Identity string
	Host     string
	Tool     string
	Detail   string
	RecordID int64
	Link     string
}

// Sink delivers alerts.
type Sink interface {
	Send(ctx context.Context, a Alert) error
	Name() string
}

// Watcher polls the audit log and raises alerts.
type Watcher struct {
	Store    *store.Store
	Sinks    []Sink
	Log      *slog.Logger
	Interval time.Duration
	cfg      Config

	mu       sync.Mutex
	last     int64
	denies   map[string][]time.Time
	lastSent map[string]time.Time
	now      func() time.Time
}

// New validates cfg and builds a Watcher with its sinks.
func New(cfg Config, st *store.Store, log *slog.Logger) (*Watcher, error) {
	if cfg.Refusals <= 0 {
		cfg.Refusals = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Minute
	}
	w := &Watcher{Store: st, Log: log, Interval: 15 * time.Second, cfg: cfg,
		denies: map[string][]time.Time{}, lastSent: map[string]time.Time{}, now: time.Now}
	for _, s := range []struct {
		file string
		mk   func(string) Sink
	}{
		{cfg.SlackWebhookFile, func(u string) Sink { return &Slack{URL: u} }},
		{cfg.TeamsWebhookFile, func(u string) Sink { return &Teams{URL: u} }},
	} {
		if s.file == "" {
			continue
		}
		u, err := readSecret(s.file)
		if err != nil {
			return nil, err
		}
		w.Sinks = append(w.Sinks, s.mk(u))
	}
	if len(w.Sinks) == 0 {
		return nil, errors.New("alerts.enabled needs slack_webhook_file and/or teams_webhook_file")
	}
	return w, nil
}

func readSecret(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: permissions %o are too open (want 0600)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	u := strings.TrimSpace(string(b))
	if !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("%s: webhook must be an https:// URL", path)
	}
	return u, nil
}

// Run polls until ctx ends. It starts after the newest existing record, so
// a restart does not replay old events.
func (w *Watcher) Run(ctx context.Context) {
	if recs, err := w.Store.Tail(ctx, 1); err == nil && len(recs) == 1 {
		w.last = recs[0].ID
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.poll(ctx)
		}
	}
}

func (w *Watcher) poll(ctx context.Context) {
	for {
		recs, err := w.Store.Since(ctx, w.last, 500)
		if err != nil {
			w.Log.Error("alerts: read audit log", "err", err)
			return
		}
		for _, r := range recs {
			w.last = r.ID
			for _, a := range w.Evaluate(r) {
				w.deliver(ctx, a)
			}
		}
		if len(recs) < 500 {
			return
		}
	}
}

// Evaluate applies the rules to one record and returns alerts to send
// (cooldown already applied).
func (w *Watcher) Evaluate(r store.Record) []Alert {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	var out []Alert
	emit := func(a Alert, key string) {
		if t, ok := w.lastSent[key]; ok && now.Sub(t) < w.cfg.Cooldown {
			return
		}
		w.lastSent[key] = now
		a.RecordID = r.ID
		if w.cfg.ConsoleURL != "" {
			a.Link = strings.TrimRight(w.cfg.ConsoleURL, "/") + fmt.Sprintf("/activity/%d", r.ID)
		}
		out = append(out, a)
	}
	switch {
	case r.Decision == "deny":
		ts := append(w.denies[r.Identity], now)
		cut := 0
		for cut < len(ts) && now.Sub(ts[cut]) > w.cfg.Window {
			cut++
		}
		ts = ts[cut:]
		w.denies[r.Identity] = ts
		if len(ts) >= w.cfg.Refusals {
			emit(Alert{Rule: "refusal_burst", Identity: r.Identity, Host: r.Host, Tool: r.Tool,
				Title:  fmt.Sprintf("%d refusals in %s for %s", len(ts), w.cfg.Window, r.Identity),
				Detail: "latest: " + r.Reason}, "burst|"+r.Identity)
		}
	case r.Decision == "error" && strings.HasPrefix(r.Reason, "refused by target helper"):
		emit(Alert{Rule: "host_refusal", Identity: r.Identity, Host: r.Host, Tool: r.Tool,
			Title:  "Target refused a call the server allowed",
			Detail: r.Reason}, fmt.Sprintf("host|%s|%s", r.Identity, r.Host))
	case r.Decision == "admin" && (r.Tool == "kill" || r.Tool == "unkill" || r.Tool == "token_revoke" || r.Tool == "token_create"):
		emit(Alert{Rule: "admin_action", Identity: r.Identity, Tool: r.Tool,
			Title:  fmt.Sprintf("Console: %s %s", r.Tool, r.Args),
			Detail: r.Reason}, fmt.Sprintf("admin|%d", r.ID))
	}
	return out
}

func (w *Watcher) deliver(ctx context.Context, a Alert) {
	for _, s := range w.Sinks {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.Send(cctx, a)
		cancel()
		if err != nil {
			w.Log.Error("alerts: delivery failed", "sink", s.Name(), "rule", a.Rule, "err", err)
		}
	}
}

func lines(a Alert) []string {
	l := []string{}
	for _, kv := range [][2]string{{"Identity", a.Identity}, {"Host", a.Host}, {"Tool", a.Tool}, {"Detail", a.Detail}} {
		if kv[1] != "" {
			l = append(l, kv[0]+": "+kv[1])
		}
	}
	return l
}

// httpClient delivers webhooks; replaced in tests.
var httpClient = &http.Client{Timeout: 10 * time.Second}

func post(ctx context.Context, url string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// Slack posts to an incoming webhook.
type Slack struct{ URL string }

// Name implements Sink.
func (*Slack) Name() string { return "slack" }

// Send implements Sink.
func (s *Slack) Send(ctx context.Context, a Alert) error {
	text := "*ssh-mcp: " + a.Title + "*\n" + strings.Join(lines(a), "\n")
	if a.Link != "" {
		text += "\n<" + a.Link + "|Open the call trail>"
	}
	return post(ctx, s.URL, map[string]string{"text": text})
}

// Teams posts an Adaptive Card to a Teams Workflows webhook.
type Teams struct{ URL string }

// Name implements Sink.
func (*Teams) Name() string { return "teams" }

// Send implements Sink.
func (t *Teams) Send(ctx context.Context, a Alert) error {
	body := []map[string]any{{"type": "TextBlock", "text": "ssh-mcp: " + a.Title, "weight": "Bolder", "wrap": true}}
	for _, l := range lines(a) {
		body = append(body, map[string]any{"type": "TextBlock", "text": l, "wrap": true})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	if a.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open the call trail", "url": a.Link}}
	}
	return post(ctx, t.URL, map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive", "content": card,
		}},
	})
}
