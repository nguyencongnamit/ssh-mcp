package console

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/policy"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

const pw = "correct horse battery"

func init() { bcryptCost = 4 }

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, r := range []store.Record{
		{Identity: "bot:ops-bot", Host: "web-1", Tool: "read_file", Args: `{"path":"/var/log/app.log"}`, Decision: "allow", Rule: "ops"},
		{Identity: "bot:ops-bot", Host: "web-1", Tool: "read_file", Decision: "result", BytesOut: 120, Redactions: 2},
		{Identity: "bot:ops-bot", Host: "web-1", Tool: "read_file", Args: `{"path":"/etc/shadow"}`, Decision: "deny", Reason: "path denied by policy: /etc/shadow <script>x</script>"},
		{Identity: "user:00000000-0000-4000-8000-00000000000a", Display: "a@example.test", Host: "web-1", Tool: "ps", Decision: "allow"},
	} {
		if _, err := st.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.CreateToken(ctx, "ops-bot", "tester", 3600e9); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte("rules:\n- name: ops\n  who: {token: ops-bot}\n  hosts: {tags: {env: [staging]}}\n  tools: [\"*\"]\n"), []string{"read_file", "ps"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	c := &Console{
		Store: st, Policy: pol, Version: "test", User: "admin", PasswordHash: hash,
		Inventory: &inventory.Static{List: []inventory.Host{{ID: "web-1", Name: "web-1", Transport: "direct", Tags: map[string]string{"env": "staging"}}}},
	}
	h, err := c.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, st
}

func get(t *testing.T, ts *httptest.Server, path string, auth bool) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	if auth {
		req.SetBasicAuth("admin", pw)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func post(t *testing.T, ts *httptest.Server, path string, form url.Values, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", pw)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func csrf(t *testing.T, ts *httptest.Server) string {
	_, body := get(t, ts, "/identities", true)
	m := regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token in page")
	}
	return m[1]
}

func TestAuthRequired(t *testing.T) {
	ts, _ := setup(t)
	if code, _ := get(t, ts, "/", false); code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", code)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.SetBasicAuth("admin", "wrong password!!")
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", res.StatusCode)
	}
}

func TestPagesRender(t *testing.T) {
	ts, _ := setup(t)
	pages := map[string][]string{
		"/":                       {"Agent activity", "Recent refusals", "Stop all agents", "Calls per hour", "Top tools", `class="chart"`, `data-tip=`},
		"/activity":               {"Audit log", "read_file", "a@example.test", "2 redacted", "path /var/log/app.log"},
		"/activity?decision=deny": {"/etc/shadow"},
		"/activity/3":             {"path denied by policy", "Hash chain", "Call trail"},
		"/hosts":                  {"web-1", "env=staging", "ops → bot ops-bot"},
		"/identities":             {"bot:ops-bot", "a@example.test", "Bot tokens", "tester"},
		"/policy":                 {"ops", "/var/log/", "/etc/shadow", "every tool"},
		"/integrity":              {"Audit chain intact", "4</b> records"},
		"/static/app.css":         {"--brand: #1f66f1"},
	}
	for path, wants := range pages {
		code, body := get(t, ts, path, true)
		if code != 200 {
			t.Errorf("%s: %d", path, code)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", path, w)
			}
		}
	}
	// Audit content is escaped, never rendered as HTML.
	_, body := get(t, ts, "/activity/3", true)
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("audit content not escaped")
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := setup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.SetBasicAuth("admin", pw)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP: %q", csp)
	}
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("no X-Frame-Options")
	}
}

func TestKillActionNeedsCSRFAndSameOrigin(t *testing.T) {
	ts, st := setup(t)
	ctx := context.Background()
	form := url.Values{"identity": {"bot:ops-bot"}, "reason": {"test"}, "back": {"/identities"}}
	if code := post(t, ts, "/kill", form, nil); code != http.StatusForbidden {
		t.Fatalf("no csrf: %d", code)
	}
	form.Set("csrf", csrf(t, ts))
	if code := post(t, ts, "/kill", form, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", code)
	}
	if code := post(t, ts, "/kill", form, map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", code)
	}
	if off, _, _ := st.IsDisabled(ctx, "bot:ops-bot"); off {
		t.Fatal("refused request still changed state")
	}
	if code := post(t, ts, "/kill", form, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != http.StatusSeeOther {
		t.Fatalf("valid kill: %d", code)
	}
	if off, reason, _ := st.IsDisabled(ctx, "bot:ops-bot"); !off || reason != "test" {
		t.Fatal("kill not applied")
	}
	recs, _ := st.Query(ctx, store.Filter{Identity: "console:admin"})
	if len(recs) != 1 || recs[0].Tool != "kill" || recs[0].Args != "bot:ops-bot" {
		t.Fatalf("console action not audited: %+v", recs)
	}
	// Unkill, kill-all, and validation.
	if code := post(t, ts, "/unkill", url.Values{"csrf": {form.Get("csrf")}, "key": {"bot:ops-bot"}}, nil); code != http.StatusSeeOther {
		t.Fatalf("unkill: %d", code)
	}
	if code := post(t, ts, "/kill", url.Values{"csrf": {form.Get("csrf")}, "identity": {"user:Alice@corp"}, "reason": {"x"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("email identity accepted: %d", code)
	}
	if code := post(t, ts, "/kill", url.Values{"csrf": {form.Get("csrf")}, "all": {"1"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("kill without reason accepted: %d", code)
	}
	if code := post(t, ts, "/kill", url.Values{"csrf": {form.Get("csrf")}, "all": {"1"}, "reason": {"drill"}}, nil); code != http.StatusSeeOther {
		t.Fatalf("kill all: %d", code)
	}
	if _, body := get(t, ts, "/", true); !strings.Contains(body, "Every agent call is being refused") {
		t.Fatal("global kill banner missing")
	}
}

func TestSafeBack(t *testing.T) {
	for in, want := range map[string]string{"/identities": "/identities", "//evil.example": "/", "https://evil.example": "/", "/\\evil": "/", "": "/"} {
		if got := safeBack(in); got != want {
			t.Errorf("safeBack(%q) = %q", in, got)
		}
	}
}
