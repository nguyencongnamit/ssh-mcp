package helper

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nguyencongnamit/ssh-mcp/internal/dockerproxy"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

func frame(stream byte, s string) []byte {
	b := make([]byte, 8, 8+len(s))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
	return append(b, s...)
}

// serveUnix serves h on a fresh unix socket in a short temp dir (macOS
// limits socket paths to 104 bytes).
func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// The helper talks to the real proxy, which talks to a fake Docker Engine.
func dockerFixture(t *testing.T) *fixture {
	f := newFixture(t)
	engine := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			_, _ = io.WriteString(w, `[{"Id":"0123456789abcdef","Names":["/api"],"Image":"api:2","State":"running","Status":"Up 5 minutes","Created":1800000000,"Ports":[{"PrivatePort":8080,"Type":"tcp"}]}]`)
		case "/containers/api/logs":
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			_, _ = w.Write(frame(1, "2026-11-02T09:00:00Z listening on :8080\n"))
			_, _ = w.Write(frame(2, "2026-11-02T09:00:01Z warn: slow upstream\n"))
		default:
			http.Error(w, "no such container", http.StatusNotFound)
		}
	}))
	f.h.DockerSocket = serveUnix(t, dockerproxy.New(engine).Handler())
	return f
}

func TestDockerPS(t *testing.T) {
	f := dockerFixture(t)
	out, err := f.run(t, protocol.ToolDockerPS, `{"all":true}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CONTAINER ID", "0123456789ab", "api", "api:2", "running", "8080/tcp"} {
		if !strings.Contains(out, want) {
			t.Errorf("docker_ps output lacks %q:\n%s", want, out)
		}
	}
}

func TestDockerLogs(t *testing.T) {
	f := dockerFixture(t)
	out, err := f.run(t, protocol.ToolDockerLogs, `{"container":"api","lines":10}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "listening on :8080") || !strings.Contains(out, "[stderr] 2026-11-02T09:00:01Z warn") {
		t.Fatalf("docker_logs output:\n%q", out)
	}
	out, _ = f.run(t, protocol.ToolDockerLogs, `{"container":"missing"}`)
	if !strings.Contains(out, "404") {
		t.Fatalf("missing container output: %q", out)
	}
	if _, err := f.run(t, protocol.ToolDockerLogs, `{"container":"-x"}`); !errors.Is(err, protocol.ErrInvalid) {
		t.Fatalf("option-like container accepted: %v", err)
	}
}

func TestDockerOffIsAnAnswer(t *testing.T) {
	f := newFixture(t)
	f.h.DockerSocket = filepath.Join(t.TempDir(), "absent.sock")
	out, err := f.run(t, protocol.ToolDockerPS, `{}`)
	if err != nil || !strings.Contains(out, "not enabled on this host") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}
