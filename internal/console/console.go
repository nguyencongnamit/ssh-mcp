// Package console is the ssh-mcp admin web UI: activity, hosts, identities,
// policy and audit integrity, plus the kill switch and token revocation.
//
// It is served on its own listener (127.0.0.1 by default), separate from the
// agent-facing MCP endpoint, behind HTTP Basic auth with a bcrypt hash.
// Every state-changing action is a POST carrying a CSRF token, must come from
// the console's own origin, and is written to the audit log as
// console:<user>.
package console

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/policy"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Console serves the admin UI.
type Console struct {
	Store        *store.Store
	Policy       *policy.Policy
	PolicyRef    *policy.Holder // when set, takes precedence over Policy
	Inventory    inventory.Source
	User         string
	PasswordHash string // bcrypt
	Version      string
	Log          *slog.Logger
	// Loc is the time zone dates are shown in (default: server local).
	Loc *time.Location
	// Tools lists every tool name, for the command palette.
	Tools []string

	csrfKey []byte
	tmpl    map[string]*template.Template

	authMu sync.Mutex
	authOK map[string]time.Time // HMAC of verified credentials -> expiry
}

// bcryptCost is a variable so tests can lower it.
var bcryptCost = 12

// HashPassword returns a bcrypt hash for the console config.
func HashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", fmt.Errorf("console password must be at least 12 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(b), err
}

func (c *Console) funcs() template.FuncMap {
	loc := c.Loc
	parse := func(ts string) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339Nano, ts)
		return t.In(loc), err == nil
	}
	return template.FuncMap{
		"since": func(ts string) string {
			t, ok := parse(ts)
			if !ok {
				return ts
			}
			d := time.Since(t)
			switch {
			case d < 10*time.Second:
				return "just now"
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
			return t.Format("Jan 2")
		},
		"clock": func(ts string) string {
			if t, ok := parse(ts); ok {
				return t.Format("15:04:05")
			}
			return ts
		},
		"day": func(ts string) string {
			if t, ok := parse(ts); ok {
				return t.Format("2 Jan 15:04")
			}
			return ts
		},
		"until": func(ts string) string {
			t, ok := parse(ts)
			if !ok {
				return ts
			}
			d := time.Until(t)
			switch {
			case d <= 0:
				return "expired"
			case d < time.Hour:
				return fmt.Sprintf("in %dm", int(d.Minutes()))
			case d < 72*time.Hour:
				return fmt.Sprintf("in %dh", int(d.Hours()))
			}
			return fmt.Sprintf("in %dd", int(d.Hours()/24))
		},
		"stamp": func(ts string) string {
			if t, ok := parse(ts); ok {
				return t.Format("Mon 2 Jan 2006, 15:04:05 MST")
			}
			return ts
		},
		"short": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"join": strings.Join,
		"kv": func(m map[string]string) []string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out := make([]string, 0, len(keys))
			for _, k := range keys {
				out = append(out, k+"="+m[k])
			}
			return out
		},
		"q":       func(k, v string) string { return url.Values{k: {v}}.Encode() },
		"argsum":  argSummary,
		"kind":    identityKind,
		"initial": initial,
		"pct": func(n, max int64) int {
			if max <= 0 {
				return 0
			}
			return int(float64(n) / float64(max) * 100)
		},
		"spark": sparkline,
		"bytes": func(n int64) string {
			switch {
			case n >= 1<<20:
				return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
			case n >= 1<<10:
				return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
			}
			return fmt.Sprintf("%d B", n)
		},
		"dur": func(ms int64) string {
			if ms >= 1000 {
				return fmt.Sprintf("%.1f s", float64(ms)/1000)
			}
			return fmt.Sprintf("%d ms", ms)
		},
		"pretty": func(js string) string {
			var v any
			if json.Unmarshal([]byte(js), &v) != nil {
				return js
			}
			var b strings.Builder
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if enc.Encode(v) != nil {
				return js
			}
			return strings.TrimSpace(b.String())
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"tz": func() string { return loc.String() },
	}
}

// argSummary turns stored JSON arguments into a short readable line.
func argSummary(js string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil || len(m) == 0 {
		return ""
	}
	delete(m, "host")
	order := []string{"command", "path", "unit", "lines", "limit", "since_seconds", "priority", "offset", "length", "serial"}
	var parts []string
	for _, k := range order {
		if v, ok := m[k]; ok {
			parts = append(parts, fmt.Sprintf("%s %v", strings.ReplaceAll(k, "_", " "), v))
			delete(m, k)
		}
	}
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s %v", k, v))
	}
	return strings.Join(parts, " · ")
}

func identityKind(key string) string {
	k, _, _ := strings.Cut(key, ":")
	return k
}

func initial(display, key string) string {
	s := display
	if s == "" {
		_, s, _ = strings.Cut(key, ":")
	}
	if s == "" {
		return "?"
	}
	return strings.ToUpper(s[:1])
}

// Handler builds the HTTP handler.
func (c *Console) Handler() (http.Handler, error) {
	if c.User == "" || c.PasswordHash == "" {
		return nil, fmt.Errorf("console needs user and password_hash (ssh-mcp console passwd)")
	}
	c.csrfKey = make([]byte, 32)
	if _, err := rand.Read(c.csrfKey); err != nil {
		return nil, err
	}
	if c.Loc == nil {
		c.Loc = time.Local
	}
	c.tmpl = map[string]*template.Template{}
	for _, page := range []string{"overview", "activity", "record", "hosts", "identities", "policy", "integrity"} {
		t, err := template.New("layout.html").Funcs(c.funcs()).ParseFS(assets, "templates/layout.html", "templates/partials.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		c.tmpl[page] = t
	}
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", c.overview)
	mux.HandleFunc("GET /activity", c.activity)
	mux.HandleFunc("GET /activity/{id}", c.record)
	mux.HandleFunc("GET /hosts", c.hosts)
	mux.HandleFunc("GET /identities", c.identities)
	mux.HandleFunc("GET /policy", c.policy)
	mux.HandleFunc("GET /integrity", c.integrity)
	mux.HandleFunc("POST /kill", c.post(c.kill))
	mux.HandleFunc("POST /unkill", c.post(c.unkill))
	mux.HandleFunc("POST /token/revoke", c.post(c.revoke))
	return c.secure(c.auth(mux)), nil
}

// ---------------------------------------------------------------- security

func (c *Console) secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func (c *Console) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !c.checkCredentials(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="ssh-mcp console", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// checkCredentials runs bcrypt once per credential pair and remembers a
// success for five minutes (keyed by an HMAC, never the password), so page
// loads do not each pay bcrypt's cost.
func (c *Console) checkCredentials(u, p string) bool {
	m := hmac.New(sha256.New, c.csrfKey)
	m.Write([]byte("auth:" + u + "\x00" + p))
	key := hex.EncodeToString(m.Sum(nil))
	now := time.Now()
	c.authMu.Lock()
	exp, hit := c.authOK[key]
	c.authMu.Unlock()
	if hit && now.Before(exp) {
		return true
	}
	userOK := subtle.ConstantTimeCompare([]byte(u), []byte(c.User)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte(p)) == nil
	if !userOK || !passOK {
		return false
	}
	c.authMu.Lock()
	if c.authOK == nil || len(c.authOK) > 64 {
		c.authOK = map[string]time.Time{}
	}
	c.authOK[key] = now.Add(5 * time.Minute)
	c.authMu.Unlock()
	return true
}

func (c *Console) csrfToken() string {
	m := hmac.New(sha256.New, c.csrfKey)
	m.Write([]byte("csrf:" + c.User))
	return hex.EncodeToString(m.Sum(nil))
}

// post wraps a state-changing handler: CSRF token, same-origin, audit.
func (c *Console) post(fn func(r *http.Request) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(c.csrfToken())) != 1 {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || u.Host != r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		back, err := fn(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

func (c *Console) audit(ctx context.Context, tool, target, reason string) {
	if _, err := c.Store.Append(ctx, store.Record{
		Identity: "console:" + c.User, Tool: tool, Args: target, Decision: "admin", Reason: reason,
	}); err != nil && c.Log != nil {
		c.Log.Error("audit console action", "err", err)
	}
}

// ---------------------------------------------------------------- render

type page struct {
	Title   string
	Nav     string
	CSRF    string
	Version string
	Killed  *store.Disabled
	Stopped int
	Palette template.JS
	Data    any
}

type paletteItem struct {
	Label string `json:"l"`
	Hint  string `json:"h"`
	Href  string `json:"u"`
}

func (c *Console) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	ctx := r.Context()
	p := page{Title: title, Nav: name, CSRF: c.csrfToken(), Version: c.Version, Data: data}
	if ds, err := c.Store.ListDisabled(ctx); err == nil {
		for i := range ds {
			if ds[i].Key == store.GlobalKill {
				p.Killed = &ds[i]
			} else {
				p.Stopped++
			}
		}
	}
	// Command palette entries: pages, identities, hosts, tools.
	items := []paletteItem{
		{"Overview", "page", "/"}, {"Activity", "page", "/activity"}, {"Refusals", "filter", "/activity?decision=deny"},
		{"Errors", "filter", "/activity?decision=error"}, {"Hosts", "page", "/hosts"}, {"Identities", "page", "/identities"},
		{"Policy", "page", "/policy"}, {"Audit integrity", "page", "/integrity"},
	}
	if ids, err := c.Store.Identities(ctx); err == nil {
		for _, i := range ids {
			label := i.Key
			if i.Display != "" {
				label = i.Display + "  " + i.Key
			}
			items = append(items, paletteItem{label, "identity", "/activity?" + url.Values{"identity": {i.Key}}.Encode()})
		}
	}
	if hs, err := c.Inventory.Hosts(ctx); err == nil {
		for _, h := range hs {
			items = append(items, paletteItem{h.Name + "  " + h.ID, "host", "/activity?" + url.Values{"host": {h.ID}}.Encode()})
		}
	}
	tools := c.Tools
	if len(tools) == 0 {
		tools = c.activePolicy().ToolNames()
	}
	for _, t := range tools {
		items = append(items, paletteItem{t, "tool", "/activity?" + url.Values{"tool": {t}}.Encode()})
	}
	if b, err := json.Marshal(items); err == nil {
		p.Palette = template.JS(b) //nolint:gosec // json.Marshal escapes <, >, & for script context
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.tmpl[name].Execute(w, p); err != nil && c.Log != nil {
		c.Log.Error("render", "page", name, "err", err)
	}
}

func (c *Console) fail(w http.ResponseWriter, err error) {
	if c.Log != nil {
		c.Log.Error("console", "err", err)
	}
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---------------------------------------------------------------- pages

func (c *Console) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	day, err := c.Store.StatsBetween(ctx, now.Add(-24*time.Hour), now)
	if err != nil {
		c.fail(w, err)
		return
	}
	prev, _ := c.Store.StatsBetween(ctx, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	hourly, err := c.Store.Hourly(ctx, 24)
	if err != nil {
		c.fail(w, err)
		return
	}
	series := func(f func(store.Bucket) int64) []int64 {
		out := make([]int64, len(hourly))
		for i, b := range hourly {
			out[i] = f(b)
		}
		return out
	}
	since := now.Add(-24 * time.Hour)
	tools, _ := c.Store.TopN(ctx, "tool", since, 6)
	ids, _ := c.Store.TopN(ctx, "identity", since, 6)
	hostsTop, _ := c.Store.TopN(ctx, "host", since, 6)
	denied, _ := c.Store.Query(ctx, store.Filter{Decision: "deny", Limit: 4})
	feed, _ := c.Store.Query(ctx, store.Filter{Limit: 10})
	disabled, _ := c.Store.ListDisabled(ctx)
	hosts, _ := c.Inventory.Hosts(ctx)
	maxOf := func(cs []store.Count) int64 {
		if len(cs) == 0 {
			return 0
		}
		return cs[0].N
	}
	c.render(w, r, "overview", "Overview", map[string]any{
		"Day": day, "Prev": prev, "HostCount": len(hosts),
		"DCalls":  mkDelta(day.Calls, prev.Calls, false),
		"DDenied": mkDelta(day.Denied, prev.Denied, true),
		"DErrors": mkDelta(day.Errors, prev.Errors, true),
		"DRedact": mkDelta(day.Redactions, prev.Redactions, false),
		"SCalls":  series(func(b store.Bucket) int64 { return b.Allowed }),
		"SDenied": series(func(b store.Bucket) int64 { return b.Denied }),
		"SErrors": series(func(b store.Bucket) int64 { return b.Errors }),
		"SRedact": series(func(b store.Bucket) int64 { return b.Redacts }),
		"Chart":   activityChart(hourly, c.Loc),
		"Tools":   tools, "ToolsMax": maxOf(tools),
		"Ids": ids, "IdsMax": maxOf(ids),
		"HostsTop": hostsTop, "HostsMax": maxOf(hostsTop),
		"Denied": denied, "Feed": feed, "Disabled": disabled,
	})
}

func (c *Console) activity(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	f := store.Filter{Identity: q.Get("identity"), Host: q.Get("host"), Tool: q.Get("tool"), Decision: q.Get("decision"), Before: before, Limit: 100}
	recs, err := c.Store.Query(r.Context(), f)
	if err != nil {
		c.fail(w, err)
		return
	}
	next := ""
	if len(recs) == f.Limit {
		v := url.Values{}
		for _, k := range []string{"identity", "host", "tool", "decision"} {
			if q.Get(k) != "" {
				v.Set(k, q.Get(k))
			}
		}
		v.Set("before", strconv.FormatInt(recs[len(recs)-1].ID, 10))
		next = "/activity?" + v.Encode()
	}
	c.render(w, r, "activity", "Activity", map[string]any{"Records": recs, "F": f, "Next": next})
}

func (c *Console) record(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rec, err := c.Store.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	trail, _ := c.Store.CallTrail(r.Context(), rec)
	history, _ := c.Store.Query(r.Context(), store.Filter{Identity: rec.Identity, Limit: 8})
	c.render(w, r, "record", fmt.Sprintf("Record %d", id), map[string]any{"R": rec, "Trail": trail, "History": history})
}

type hostRow struct {
	inventory.Host
	Activity store.HostActivity
	Rules    []string
	Spark    []int64
}

func (c *Console) hosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hs, err := c.Inventory.Hosts(ctx)
	if err != nil {
		c.fail(w, err)
		return
	}
	act, _ := c.Store.HostActivity(ctx)
	sparks, _ := c.Store.HostHourly(ctx, 24)
	rows := make([]hostRow, 0, len(hs))
	for _, h := range hs {
		sp := sparks[h.ID]
		if sp == nil {
			sp = make([]int64, 24)
		}
		rows = append(rows, hostRow{Host: h, Activity: act[h.ID], Rules: c.activePolicy().RulesForHost(h), Spark: sp})
	}
	c.render(w, r, "hosts", "Hosts", rows)
}

func (c *Console) identities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	seen, err := c.Store.Identities(ctx)
	if err != nil {
		c.fail(w, err)
		return
	}
	tokens, _ := c.Store.ListTokens(ctx)
	disabled, _ := c.Store.ListDisabled(ctx)
	off := map[string]store.Disabled{}
	for _, d := range disabled {
		off[d.Key] = d
	}
	c.render(w, r, "identities", "Identities", map[string]any{"Seen": seen, "Tokens": tokens, "Off": off})
}

func (c *Console) policy(w http.ResponseWriter, r *http.Request) {
	c.render(w, r, "policy", "Policy", c.activePolicy())
}

func (c *Console) integrity(w http.ResponseWriter, r *http.Request) {
	n, broken, err := c.Store.Verify(r.Context())
	last, _ := c.Store.Query(r.Context(), store.Filter{Limit: 5})
	for i, j := 0, len(last)-1; i < j; i, j = i+1, j-1 {
		last[i], last[j] = last[j], last[i]
	}
	c.render(w, r, "integrity", "Audit integrity", map[string]any{"N": n, "Broken": broken, "Err": err, "At": time.Now().In(c.Loc).Format("15:04:05 MST"), "Chain": last})
}

// ---------------------------------------------------------------- actions

func (c *Console) kill(r *http.Request) (string, error) {
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	if reason == "" {
		return "", fmt.Errorf("a reason is required")
	}
	key := store.GlobalKill
	if r.PostForm.Get("all") != "1" {
		k, err := identity.NormalizeKey(r.PostForm.Get("identity"))
		if err != nil {
			return "", err
		}
		key = k
	}
	if err := c.Store.Disable(r.Context(), key, reason); err != nil {
		return "", err
	}
	c.audit(r.Context(), "kill", key, reason)
	return safeBack(r.PostForm.Get("back")), nil
}

func (c *Console) unkill(r *http.Request) (string, error) {
	key := r.PostForm.Get("key")
	if key != store.GlobalKill {
		k, err := identity.NormalizeKey(key)
		if err != nil {
			return "", err
		}
		key = k
	}
	if err := c.Store.Enable(r.Context(), key); err != nil {
		return "", err
	}
	c.audit(r.Context(), "unkill", key, "")
	return safeBack(r.PostForm.Get("back")), nil
}

func (c *Console) revoke(r *http.Request) (string, error) {
	name := r.PostForm.Get("name")
	if err := c.Store.RevokeToken(r.Context(), name); err != nil {
		return "", err
	}
	c.audit(r.Context(), "token_revoke", "bot:"+name, "")
	return "/identities", nil
}

// safeBack only allows local paths, so a crafted form cannot redirect off-site.
func safeBack(p string) string {
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\\r\n") {
		return p
	}
	return "/"
}

func (c *Console) activePolicy() *policy.Policy {
	if c.PolicyRef != nil {
		return c.PolicyRef.Load()
	}
	return c.Policy
}
