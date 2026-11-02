package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

// fixture builds a fake filesystem root and a fake bin dir. Directory names
// avoid words on the deny list (the test name is not used in paths).
type fixture struct {
	root, logs, conf, outside, bin string
	h                              *Helper
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base, err := os.MkdirTemp("", "smh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	base, _ = filepath.EvalSymlinks(base) // macOS: /var -> /private/var
	f := &fixture{
		root:    base,
		logs:    filepath.Join(base, "logs"),
		conf:    filepath.Join(base, "conf"),
		outside: filepath.Join(base, "outside"),
		bin:     filepath.Join(base, "bin"),
	}
	for _, d := range []string{f.logs, f.conf, f.outside, f.bin, filepath.Join(f.conf, "ssh")} {
		must(t, os.MkdirAll(d, 0o755))
	}
	pol := pathpolicy.Policy{
		Allow: []string{f.logs + "/", f.conf + "/"},
		Deny:  append([]string{f.conf + "/ssh/"}, pathpolicy.Default().Deny...),
	}
	f.h = &Helper{
		Policy:        pol,
		BinDirs:       []string{f.bin},
		CheckBinOwner: false,
		Timeout:       5 * time.Second,
		Now:           func() time.Time { return time.Unix(1_800_000_000, 0) },
		ProcFD:        false,
	}
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) run(t *testing.T, tool string, args string) (string, error) {
	t.Helper()
	line := fmt.Sprintf(`{"tool":%q,"args":%s}`, tool, args)
	var out bytes.Buffer
	err := f.h.Run(context.Background(), line, &out)
	return out.String(), err
}

func (f *fixture) fakeBin(t *testing.T, name, script string) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(f.bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755))
}

func q(s string) string { return fmt.Sprintf("%q", s) }

func TestReadFileHappyPath(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.logs, "app.log")
	must(t, os.WriteFile(p, []byte("hello\nworld\n"), 0o644))
	out, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`}`)
	if err != nil || out != "hello\nworld\n" {
		t.Fatalf("got %q, %v", out, err)
	}
	out, err = f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`,"offset":6,"length":3}`)
	if err != nil || out != "wor" {
		t.Fatalf("offset/length: got %q, %v", out, err)
	}
}

func TestSymlinkToDeniedFileIsRefused(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.outside, "shadow")
	must(t, os.WriteFile(target, []byte("root:$6$hash"), 0o644))
	link := filepath.Join(f.logs, "innocent.log")
	must(t, os.Symlink(target, link))
	out, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(link)+`}`)
	if !errors.Is(err, ErrDenied) || strings.Contains(out, "hash") {
		t.Fatalf("symlink escape not blocked: %q, %v", out, err)
	}
}

func TestSymlinkedDirectoryEscapeIsRefused(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.outside, "data.txt"), []byte("leak"), 0o644))
	must(t, os.Symlink(f.outside, filepath.Join(f.logs, "dir")))
	out, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(filepath.Join(f.logs, "dir", "data.txt"))+`}`)
	if !errors.Is(err, ErrDenied) || strings.Contains(out, "leak") {
		t.Fatalf("dir symlink escape not blocked: %q, %v", out, err)
	}
}

func TestTraversalIsRefused(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.outside, "x"), []byte("leak"), 0o644))
	p := f.logs + "/../outside/x"
	if _, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`}`); !errors.Is(err, ErrDenied) {
		t.Fatalf("traversal not blocked: %v", err)
	}
}

func TestDenyListInsideAllowedTree(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{".env", "server.pem", "id_ed25519", "db_password.txt"} {
		p := filepath.Join(f.conf, name)
		must(t, os.WriteFile(p, []byte("leak"), 0o644))
		if _, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`}`); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want ErrDenied, got %v", name, err)
		}
	}
	p := filepath.Join(f.conf, "ssh", "sshd_config")
	must(t, os.WriteFile(p, []byte("x"), 0o644))
	if _, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`}`); !errors.Is(err, ErrDenied) {
		t.Errorf("deny subtree: got %v", err)
	}
}

func TestFIFOAndDirectoryAreNotRead(t *testing.T) {
	f := newFixture(t)
	fifo := filepath.Join(f.logs, "pipe")
	must(t, syscall.Mkfifo(fifo, 0o644))
	done := make(chan error, 1)
	go func() { _, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(fifo)+`}`); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read should fail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO read blocked")
	}
	if _, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(f.logs)+`}`); err == nil {
		t.Fatal("reading a directory as a file should fail")
	}
}

func TestReadFileCapsOutput(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.logs, "big.log")
	must(t, os.WriteFile(p, bytes.Repeat([]byte("a"), protocol.MaxFileBytes+5000), 0o644))
	out, err := f.run(t, protocol.ToolReadFile, `{"path":`+q(p)+`}`)
	if err != nil || len(out) != protocol.MaxFileBytes {
		t.Fatalf("len=%d err=%v", len(out), err)
	}
}

func TestTailFile(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.logs, "t.log")
	var b strings.Builder
	for i := 1; i <= 500; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	must(t, os.WriteFile(p, []byte(b.String()), 0o644))
	out, err := f.run(t, protocol.ToolTailFile, `{"path":`+q(p)+`,"lines":3}`)
	if err != nil || out != "line 498\nline 499\nline 500\n" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestListDirMarksDenied(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.conf, "app.conf"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.conf, ".env"), []byte("x"), 0o644))
	out, err := f.run(t, protocol.ToolListDir, `{"path":`+q(f.conf)+`}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "app.conf\n") || !strings.Contains(out, ".env  [denied]") {
		t.Fatalf("unexpected listing:\n%s", out)
	}
	if _, err := f.run(t, protocol.ToolListDir, `{"path":`+q(f.outside)+`}`); !errors.Is(err, ErrDenied) {
		t.Fatalf("listing outside allow: %v", err)
	}
}

func TestExecPassesFixedArgvAndNoClientEnv(t *testing.T) {
	f := newFixture(t)
	t.Setenv("LEAKY_CLIENT_VAR", "should-not-appear")
	f.fakeBin(t, "journalctl", `for a in "$@"; do echo "ARG:$a"; done; env`)
	out, err := f.run(t, protocol.ToolJournal, `{"unit":"nginx.service","lines":5,"since_seconds":60,"priority":3}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ARG:--no-pager", "ARG:--lines=5", "ARG:--since=@1799999940",
		"ARG:--unit=nginx.service", "ARG:--priority=3", "PAGER=cat", "SYSTEMD_PAGER=cat",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "LEAKY_CLIENT_VAR") || strings.Contains(out, "SSH_ORIGINAL_COMMAND") {
		t.Errorf("client environment leaked:\n%s", out)
	}
}

func TestSystemctlStatusNonZeroExitIsReported(t *testing.T) {
	f := newFixture(t)
	f.fakeBin(t, "systemctl", `echo "ARGS:$*"; exit 3`)
	out, err := f.run(t, protocol.ToolSystemctlStatus, `{"unit":"nginx"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ARGS:status --no-pager --full --lines=20 -- nginx") || !strings.Contains(out, "[exit status 3]") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	f := newFixture(t)
	f.h.Timeout = 300 * time.Millisecond
	f.fakeBin(t, "ss", `sleep 30 & sleep 30`)
	start := time.Now()
	out, err := f.run(t, protocol.ToolListeningPorts, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second || !strings.Contains(out, "[timed out]") {
		t.Fatalf("timeout not enforced (%v): %q", time.Since(start), out)
	}
}

func TestPSLimitsRows(t *testing.T) {
	f := newFixture(t)
	f.fakeBin(t, "ps", `echo HEADER; i=0; while [ $i -lt 50 ]; do echo row$i; i=$((i+1)); done`)
	out, err := f.run(t, protocol.ToolPS, `{"limit":3}`)
	if err != nil || out != "HEADER\nrow0\nrow1\nrow2\n" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestUntrustedBinaryIsRefused(t *testing.T) {
	f := newFixture(t)
	f.h.CheckBinOwner = true // temp files are not root-owned
	f.fakeBin(t, "ss", `echo ran`)
	out, err := f.run(t, protocol.ToolListeningPorts, `{}`)
	if err == nil || strings.Contains(out, "ran") {
		t.Fatalf("non-root-owned binary executed: %q %v", out, err)
	}
}

func TestMissingBinaryIsAnError(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, protocol.ToolListeningPorts, `{}`); err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestUnknownToolRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, "shell", `{"cmd":"id"}`); !errors.Is(err, protocol.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
