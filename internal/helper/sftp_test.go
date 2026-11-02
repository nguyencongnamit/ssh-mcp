package helper

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nguyencongnamit/ssh-mcp/internal/ca"
	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
)

func sftpClient(t *testing.T, h *Helper) *sftp.Client {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	go func() { _ = h.ServeSFTP(srvConn) }()
	c, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSFTPEnforcesPolicy(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.logs, "app.log"), []byte("hello\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.logs, ".env"), []byte("leak-env"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.logs, "server.key"), []byte("leak-key"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.outside, "x"), []byte("leak-outside"), 0o644))
	must(t, os.Symlink(filepath.Join(f.outside, "x"), filepath.Join(f.logs, "link")))
	must(t, os.Symlink(filepath.Join(f.logs, "app.log"), filepath.Join(f.logs, "alias.log")))
	c := sftpClient(t, f.h)

	// Listing shows only allowed entries; symlinks appear as their target.
	ents, err := c.ReadDir(f.logs)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		if e.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s shown as a symlink", e.Name())
		}
	}
	got := strings.Join(names, ",")
	if got != "alias.log,app.log" {
		t.Fatalf("listing = %s", got)
	}

	read := func(p string) (string, error) {
		fh, err := c.Open(p)
		if err != nil {
			return "", err
		}
		defer fh.Close()
		b, err := io.ReadAll(fh)
		return string(b), err
	}
	if s, err := read(filepath.Join(f.logs, "app.log")); err != nil || s != "hello\n" {
		t.Fatalf("allowed read: %q %v", s, err)
	}
	if s, err := read(filepath.Join(f.logs, "alias.log")); err != nil || s != "hello\n" {
		t.Fatalf("allowed symlink read: %q %v", s, err)
	}
	for _, p := range []string{".env", "server.key", "link"} {
		s, err := read(filepath.Join(f.logs, p))
		if err == nil || strings.Contains(s, "leak") {
			t.Errorf("%s readable: %q", p, s)
		}
		if _, err := c.Stat(filepath.Join(f.logs, p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: stat should say not-exist, got %v", p, err)
		}
	}
	if _, err := read(filepath.Join(f.outside, "x")); err == nil {
		t.Error("outside path readable")
	}
	if _, err := c.ReadDir(f.outside); err == nil {
		t.Error("outside dir listable")
	}
	if _, err := c.ReadLink(filepath.Join(f.logs, "link")); err == nil {
		t.Error("readlink allowed")
	}

	// Every write-class operation is refused and nothing changes on disk.
	if fh, err := c.Create(filepath.Join(f.logs, "pwned")); err == nil {
		_, werr := fh.Write([]byte("x"))
		fh.Close()
		if werr == nil {
			t.Error("write allowed")
		}
	}
	for name, op := range map[string]func() error{
		"mkdir":   func() error { return c.Mkdir(filepath.Join(f.logs, "d")) },
		"remove":  func() error { return c.Remove(filepath.Join(f.logs, "app.log")) },
		"rename":  func() error { return c.Rename(filepath.Join(f.logs, "app.log"), filepath.Join(f.logs, "z")) },
		"chmod":   func() error { return c.Chmod(filepath.Join(f.logs, "app.log"), 0o777) },
		"symlink": func() error { return c.Symlink("/etc/passwd", filepath.Join(f.logs, "s")) },
	} {
		if err := op(); err == nil {
			t.Errorf("%s allowed", name)
		}
	}
	if _, err := os.Stat(filepath.Join(f.logs, "pwned")); err == nil {
		t.Error("file created on disk")
	}
	if fi, _ := os.Stat(filepath.Join(f.logs, "app.log")); fi == nil || fi.Mode().Perm() != 0o644 {
		t.Error("app.log changed")
	}
}

func TestCertPolicyNarrowsHostFloor(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.conf, "app.conf"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.logs, "app.log"), []byte("y"), 0o644))
	f.h.CertPaths = &pathpolicy.Policy{Allow: []string{f.logs + "/"}}
	if _, err := f.run(t, "read_file", `{"path":`+q(filepath.Join(f.conf, "app.conf"))+`}`); !errors.Is(err, ErrDenied) {
		t.Fatalf("cert policy did not narrow: %v", err)
	}
	if out, err := f.run(t, "read_file", `{"path":`+q(filepath.Join(f.logs, "app.log"))+`}`); err != nil || out != "y" {
		t.Fatalf("allowed read failed: %q %v", out, err)
	}
	// A symlink in an allowed dir pointing at a cert-denied path is refused
	// on the host (finding: server-side checks alone miss this).
	must(t, os.Symlink(filepath.Join(f.conf, "app.conf"), filepath.Join(f.logs, "to-conf")))
	if _, err := f.run(t, "read_file", `{"path":`+q(filepath.Join(f.logs, "to-conf"))+`}`); !errors.Is(err, ErrDenied) {
		t.Fatalf("symlink around cert policy: %v", err)
	}
	// The cert cannot widen: host floor still denies outside.
	f.h.CertPaths = &pathpolicy.Policy{Allow: []string{"/"}}
	must(t, os.WriteFile(filepath.Join(f.outside, "z"), []byte("z"), 0o644))
	if _, err := f.run(t, "read_file", `{"path":`+q(filepath.Join(f.outside, "z"))+`}`); !errors.Is(err, ErrDenied) {
		t.Fatalf("cert widened the host floor: %v", err)
	}
}

func authInfoFor(cert *ssh.Certificate) []byte {
	return []byte("publickey " + cert.Type() + " " + base64.StdEncoding.EncodeToString(cert.Marshal()) + "\n")
}

func TestCertPolicyParsing(t *testing.T) {
	dir := t.TempDir()
	pub, err := ca.GenerateFile(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := ca.LoadFile(filepath.Join(dir, "ca"))
	authority.Paths = `{"allow":["/var/log/"],"deny":["/var/log/private/"]}`
	e, err := authority.IssueLive("t", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := CertPolicy(authInfoFor(e.Cert), []byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed("/var/log/syslog", false) || p.Allowed("/var/log/private/x", false) || p.Allowed("/etc/hosts", false) {
		t.Fatalf("policy not parsed correctly: %+v", p)
	}

	// Same cert checked against a different CA: rejected.
	pub2, _ := ca.GenerateFile(filepath.Join(dir, "ca2"))
	if _, err := CertPolicy(authInfoFor(e.Cert), []byte(pub2)); err == nil {
		t.Fatal("certificate from an untrusted CA accepted")
	}
	// Tampered extension (signature no longer matches): rejected.
	tampered := *e.Cert
	tampered.Permissions.Extensions = map[string]string{PathsExtension: `{"allow":["/"]}`}
	if _, err := CertPolicy(authInfoFor(&tampered), []byte(pub)); err == nil {
		t.Fatal("tampered certificate accepted")
	}
	if _, err := CertPolicy([]byte("publickey ssh-ed25519 AAAA\n"), []byte(pub)); err == nil {
		t.Fatal("plain key accepted")
	}
	if _, err := CertPolicy(nil, []byte(pub)); err == nil {
		t.Fatal("empty auth info accepted")
	}
}
