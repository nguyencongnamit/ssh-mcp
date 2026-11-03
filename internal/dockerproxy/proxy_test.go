package dockerproxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeDocker is a Docker Engine stand-in on a unix socket. It records the
// upstream requests the proxy makes.
type fakeDocker struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeDocker) start(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		switch {
		case r.URL.Path == "/containers/json":
			_, _ = io.WriteString(w, `[{"Id":"0123456789abcdef0123","Names":["/web"],"Image":"nginx:1.27","State":"running",
				"Status":"Up 3 hours","Created":1790000000,"Command":"nginx -g 'daemon off;' --password=SECRET-CMD",
				"Labels":{"db.password":"SECRET-LABEL"},"Mounts":[{"Source":"/srv/secret"}],
				"Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"PrivatePort":443,"Type":"tcp"}]}]`)
		case r.URL.Path == "/containers/web/logs":
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			_, _ = w.Write([]byte{1, 0, 0, 0, 0, 0, 0, 6})
			_, _ = io.WriteString(w, "hello\n")
		case r.URL.Path == "/containers/nope/logs":
			http.Error(w, "no such container", http.StatusNotFound)
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func get(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestContainersReduced(t *testing.T) {
	fd := &fakeDocker{}
	h := New(fd.start(t)).Handler()
	rec := get(t, h, "GET", "/containers?all=1")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, secret := range []string{"SECRET-CMD", "SECRET-LABEL", "/srv/secret", "Labels", "Command", "Mounts"} {
		if strings.Contains(body, secret) {
			t.Errorf("response leaks %q: %s", secret, body)
		}
	}
	var cs []Container
	if err := json.Unmarshal(rec.Body.Bytes(), &cs); err != nil || len(cs) != 1 {
		t.Fatalf("decode: %v %s", err, body)
	}
	c := cs[0]
	if c.ID != "0123456789ab" || c.Names[0] != "web" || len(c.Ports) != 2 || c.Ports[0] != "0.0.0.0:8080->80/tcp" {
		t.Fatalf("container %+v", c)
	}
	if fd.seen[0] != "GET /containers/json?all=1" {
		t.Fatalf("upstream request %q", fd.seen[0])
	}
}

func TestLogsRebuildsRequest(t *testing.T) {
	fd := &fakeDocker{}
	h := New(fd.start(t)).Handler()
	rec := get(t, h, "GET", "/containers/web/logs?tail=50&since=1790000000")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("status %d body %q", rec.Code, rec.Body)
	}
	up := fd.seen[0]
	for _, want := range []string{"follow=0", "tail=50", "since=1790000000", "stdout=1", "stderr=1", "timestamps=1"} {
		if !strings.Contains(up, want) {
			t.Errorf("upstream %q lacks %s", up, want)
		}
	}
	if rec := get(t, h, "GET", "/containers/nope/logs?tail=5&since=0"); rec.Code != 404 {
		t.Fatalf("missing container: status %d", rec.Code)
	}
}

func TestRefusals(t *testing.T) {
	fd := &fakeDocker{}
	h := New(fd.start(t)).Handler()
	for _, c := range []struct{ method, target string }{
		{"POST", "/containers"},
		{"DELETE", "/containers/web"},
		{"GET", "/containers/json"},                             // raw API path
		{"GET", "/containers/web/exec"},                         // exec
		{"GET", "/containers/web/json"},                         // inspect: env, mounts
		{"GET", "/images/json"},                                 // anything else
		{"GET", "/v1.43/containers"},                            // versioned path
		{"GET", "/containers?all=1&filters=x"},                  // extra parameter
		{"GET", "/containers?all=1&all=0"},                      // repeated parameter
		{"GET", "/containers/web/logs?tail=5&since=0&follow=1"}, // follow
		{"GET", "/containers/web/logs?tail=0&since=0"},          // tail out of range
		{"GET", "/containers/web/logs?tail=999999&since=0"},     // tail out of range
		{"GET", "/containers/web/logs?tail=5&since=-1"},         // negative since
		{"GET", "/containers/web/logs?tail=5"},                  // missing since
		{"GET", "/containers/-web/logs?tail=5&since=0"},         // option-like id
		{"GET", "/containers/..%2Fimages/logs?tail=5&since=0"},  // encoded traversal
		{"GET", "/containers/a%2Fb/logs?tail=5&since=0"},        // encoded slash
	} {
		if rec := get(t, h, c.method, c.target); rec.Code < 400 {
			t.Errorf("%s %s: status %d, want refusal", c.method, c.target, rec.Code)
		}
	}
	if len(fd.seen) != 0 {
		t.Fatalf("refused requests reached Docker: %v", fd.seen)
	}
}
