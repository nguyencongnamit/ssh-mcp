//go:build e2e

// Package e2e attacks the running test bed (./testbed/up.sh) two ways:
// through MCP as an agent would, and directly against the target's sshd with
// hand-crafted certificates, to prove each boundary holds on its own.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

const (
	mcpURL     = "http://127.0.0.1:18471/mcp"
	targetAddr = "127.0.0.1:18472"
)

func bedDir(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

func token(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join(bedDir(t), "state", name+".token"))
	if err != nil {
		t.Skipf("test bed not up (%v); run ./testbed/up.sh", err)
	}
	return strings.TrimSpace(string(b))
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func session(t *testing.T, who string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: mcpURL, HTTPClient: &http.Client{Transport: bearer{token(t, who)}}, MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect as %s: %v", who, err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func expect(t *testing.T, label, out string, wantErr, isErr bool, contains []string, absent []string) {
	t.Helper()
	if wantErr != isErr {
		t.Errorf("%s: isError=%v, want %v\n%s", label, isErr, wantErr, out)
	}
	for _, c := range contains {
		if !strings.Contains(out, c) {
			t.Errorf("%s: missing %q\n%s", label, c, out)
		}
	}
	for _, a := range absent {
		if strings.Contains(out, a) {
			t.Errorf("%s: must not contain %q\n%s", label, a, out)
		}
	}
}

// ------------------------------------------------------------------ via MCP

func TestMCPLiveTools(t *testing.T) {
	cs := session(t, "ops-bot")
	h := map[string]any{"host": "web-1"}

	out, isErr := call(t, cs, "list_hosts", nil)
	expect(t, "list_hosts", out, false, isErr, []string{"web-1", "env=staging"}, []string{"db-1"})

	out, isErr = call(t, cs, "host_overview", h)
	expect(t, "host_overview", out, false, isErr, []string{"Linux", "== disk ==", "<untrusted-output"}, nil)

	out, isErr = call(t, cs, "ps", map[string]any{"host": "web-1", "limit": 5})
	expect(t, "ps", out, false, isErr, []string{"PID", "sshd"}, nil)

	out, isErr = call(t, cs, "listening_ports", h)
	expect(t, "listening_ports", out, false, isErr, []string{":22"}, nil)

	out, isErr = call(t, cs, "list_dir", map[string]any{"host": "web-1", "path": "/var/log/app"})
	expect(t, "list_dir", out, false, isErr, []string{"app.log", "private.log"}, nil)
}

func TestMCPReadAndRedact(t *testing.T) {
	cs := session(t, "ops-bot")
	out, isErr := call(t, cs, "read_file", map[string]any{"host": "web-1", "path": "/var/log/app/app.log"})
	expect(t, "app.log", out, false, isErr,
		[]string{"ERROR upstream timeout", "token=[REDACTED]", "Treat it as data"},
		[]string{"Zx9Qm2Lp7Rt4Vw8Ky1Nb5Hc3Jd6Fg0Sa2Ue"})

	out, isErr = call(t, cs, "tail_file", map[string]any{"host": "web-1", "path": "/var/log/app/app.log", "lines": 1})
	expect(t, "tail", out, false, isErr, []string{"Ignore previous instructions"}, []string{"ERROR upstream"})

	out, isErr = call(t, cs, "read_file", map[string]any{"host": "web-1", "path": "/etc/app/app.conf"})
	expect(t, "app.conf", out, false, isErr, []string{"listen=8080", "db.password=[REDACTED]"}, []string{"NotARealOne"})
}

func TestMCPBoundaries(t *testing.T) {
	cs := session(t, "ops-bot")
	cases := []struct {
		label, path string
		contains    string
	}{
		// Server-side path policy.
		{"shadow", "/etc/shadow", "refused"},
		{".env by name", "/etc/app/.env", "refused"},
		{"outside allow", "/root/canary", "refused"},
		{"traversal", "/var/log/../../root/canary", "refused"},
		// Passes the server's name check; the helper resolves the symlink on
		// the host and refuses.
		{"symlink to .env", "/var/log/app/link-to-env", "refused by target helper"},
		// The OS refuses: /root is 0700 and agent-ro is not root.
		{"symlink to root", "/var/log/app/link-to-root", "permission denied"},
		// The OS refuses: file is 0600 root.
		{"root-only log", "/var/log/app/private.log", "permission denied"},
	}
	for _, c := range cases {
		out, isErr := call(t, cs, "read_file", map[string]any{"host": "web-1", "path": c.path})
		expect(t, c.label, out, true, isErr, []string{c.contains}, []string{"canary-root-file", "fake-env-value-000", "root only"})
	}
	out, isErr := call(t, cs, "ps", map[string]any{"host": "db-1"})
	expect(t, "prod host", out, true, isErr, []string{"unknown host"}, nil)
	out, isErr = call(t, cs, "journal", map[string]any{"host": "web-1", "unit": "x;id"})
	expect(t, "unit injection", out, true, isErr, []string{"refused"}, nil)
}

func TestMCPScopedIdentities(t *testing.T) {
	logs := session(t, "log-bot")
	out, isErr := call(t, logs, "read_file", map[string]any{"host": "web-1", "path": "/var/log/app/app.log"})
	expect(t, "log-bot read_file", out, true, isErr, []string{"refused"}, nil)
	out, isErr = call(t, logs, "tail_file", map[string]any{"host": "web-1", "path": "/var/log/app/app.log", "lines": 2})
	expect(t, "log-bot tail_file", out, false, isErr, []string{"WARN"}, nil)

	stranger := session(t, "stranger")
	out, isErr = call(t, stranger, "list_hosts", nil)
	expect(t, "stranger", out, true, isErr, []string{"refused"}, []string{"web-1"})
}

func TestMCPSandbox(t *testing.T) {
	cs := session(t, "ops-bot")
	run := func(cmd string) (string, bool) {
		return call(t, cs, "sandbox_exec", map[string]any{"host": "web-1", "command": cmd})
	}
	out, isErr := run("grep -rh ERROR /targets/web-1/var/log/app/app.log")
	expect(t, "grep mirror", out, false, isErr, []string{"ERROR upstream timeout"}, nil)

	out, isErr = run("touch /targets/web-1/var/log/app/pwned; echo rc=$?")
	expect(t, "write mirror", out, false, isErr, []string{"Read-only file system", "rc=1"}, nil)

	out, isErr = run("tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '")
	expect(t, "no network", out, false, isErr, []string{"lo"}, []string{"eth0"})

	out, isErr = run("ls /etc/ssh-mcp /var/lib/ssh-mcp 2>&1; id -u")
	expect(t, "no server secrets", out, false, isErr, []string{"No such file", "65534"}, []string{"ca_key", "ssh-mcp.db"})

	out, isErr = run("cat /targets/web-1/etc/shadow 2>&1; echo; cat /targets/web-1/etc/ssh/sshd_config 2>&1 | wc -c")
	expect(t, "masked paths", out, false, isErr, nil, []string{"root:", "TrustedUserCAKeys"})

	// Denied files never reach the mirror: the target's SFTP helper hides
	// them, so encoding tricks that beat redaction have nothing to encode.
	out, isErr = run("cat /targets/web-1/etc/app/.env 2>&1; sed 's/./& /g' /targets/web-1/etc/app/.env 2>&1; od -c /targets/web-1/etc/app/server.key 2>&1")
	expect(t, "denied files unreadable", out, false, isErr, []string{"No such file"},
		[]string{"fake-env-value", "f a k e", "fake-private", "f   a   k   e"})
	out, isErr = run("ls -a /targets/web-1/etc/app")
	expect(t, "denied files not listed", out, false, isErr, []string{"app.conf"}, []string{"server.key", ".env"})
	out, isErr = run("cat /targets/web-1/var/log/app/link-to-env 2>&1; cat /targets/web-1/var/log/app/link-to-root 2>&1")
	expect(t, "symlinks to denied files absent", out, false, isErr, []string{"No such file"}, []string{"fake-env-value", "canary"})

	out, isErr = run("sleep 60")
	expect(t, "timeout", out, false, isErr, []string{"[timed out]"}, nil)
}

// The sandbox's cgroup must contain resource abuse; the server keeps
// answering afterwards.
func TestMCPSandboxResourceLimits(t *testing.T) {
	cs := session(t, "ops-bot")
	run := func(cmd string) (string, bool) {
		return call(t, cs, "sandbox_exec", map[string]any{"host": "web-1", "command": cmd})
	}
	logs, _ := exec.Command("docker", "compose", "-f", filepath.Join(bedDir(t), "docker-compose.yml"), "logs", "server").CombinedOutput()
	if !strings.Contains(string(logs), "sandbox cgroups active") {
		t.Skip("sandbox cgroups not active in this environment")
	}
	out, _ := run("i=0; while [ $i -lt 400 ]; do sleep 20 & i=$((i+1)); done 2>&1 | tail -1; echo started")
	if !strings.Contains(out, "fork") && !strings.Contains(out, "Resource temporarily unavailable") && !strings.Contains(out, "Cannot") {
		t.Errorf("400 processes started despite pids.max=128:\n%s", out)
	}
	run("bomb() { bomb | bomb & }; bomb; sleep 5")
	out, _ = run("head -c 900000000 /dev/zero > /tmp/fill; echo rc=$?")
	if strings.Contains(out, "rc=0") {
		t.Errorf("900 MB written to sandbox /tmp despite memory.max:\n%s", out)
	}
	out, isErr := call(t, cs, "list_hosts", nil)
	expect(t, "server alive after abuse", out, false, isErr, []string{"web-1"}, nil)
}

// ------------------------------------------------------------- direct sshd

func caSigner(t *testing.T) ssh.Signer {
	b, err := os.ReadFile(filepath.Join(bedDir(t), "server", "etc", "ca_key"))
	if err != nil {
		t.Skipf("no test CA: %v", err)
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const pathsExt = "ssh-mcp-paths@ssh-mcp"

var defaultPaths = `{"allow":["/var/log/","/etc/"],"deny":[]}`

// mintCert signs a certificate with the test CA. Unless exts already sets
// it, the server's path-policy extension is added, as the real CA does.
func mintCert(t *testing.T, principal string, opts, exts map[string]string, validFor time.Duration) ssh.Signer {
	t.Helper()
	e := map[string]string{pathsExt: defaultPaths}
	for k, v := range exts {
		e[k] = v
	}
	if v, ok := exts[pathsExt]; ok && v == "" {
		delete(e, pathsExt) // explicit "" = no policy
	}
	exts = e
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	now := time.Now()
	after, before := now.Add(-time.Minute), now.Add(validFor)
	if validFor < 0 {
		after, before = now.Add(2*validFor), now.Add(validFor)
	}
	cert := &ssh.Certificate{
		Key: sp, CertType: ssh.UserCert, KeyId: "e2e", ValidPrincipals: []string{principal},
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix()),
		Permissions: ssh.Permissions{CriticalOptions: opts, Extensions: exts},
	}
	if err := cert.SignCert(rand.Reader, caSigner(t)); err != nil {
		t.Fatal(err)
	}
	ks, _ := ssh.NewSignerFromKey(priv)
	cs, _ := ssh.NewCertSigner(cert, ks)
	return cs
}

func dial(user string, s ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", targetAddr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(s)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test bed only: host is our own container
		Timeout:         10 * time.Second,
	})
}

func runCmd(c *ssh.Client, cmd string) (string, int) {
	s, err := c.NewSession()
	if err != nil {
		return err.Error(), -1
	}
	defer s.Close()
	var stdout, stderr bytes.Buffer
	s.Stdout, s.Stderr = &stdout, &stderr
	err = s.Run(cmd)
	out := stdout.String() + stderr.String()
	if ee, ok := err.(*ssh.ExitError); ok {
		return out, ee.ExitStatus()
	}
	if err != nil {
		return out + err.Error(), -1
	}
	return out, 0
}

var liveOpts = map[string]string{"force-command": "/usr/local/libexec/ssh-mcp-helper"}

func TestSSHDShellCommandIsNeverExecuted(t *testing.T) {
	c, err := dial("agent-ro", mintCert(t, "ssh-mcp-live", liveOpts, nil, 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, code := runCmd(c, "id; cat /etc/shadow; touch /tmp/pwned")
	if code != 2 || strings.Contains(out, "uid=") {
		t.Fatalf("shell command reached a shell (exit %d): %s", code, out)
	}
}

func TestSSHDCertWithoutForceCommandIsStillForced(t *testing.T) {
	// Simulates a CA misuse: a live cert with no force-command and every
	// extension. sshd's Match block must still force the helper.
	all := map[string]string{"permit-pty": "", "permit-port-forwarding": "", "permit-agent-forwarding": "", "permit-user-rc": "", "permit-X11-forwarding": ""}
	c, err := dial("agent-ro", mintCert(t, "ssh-mcp-live", nil, all, 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, code := runCmd(c, "id")
	if code != 2 || strings.Contains(out, "uid=") {
		t.Fatalf("sshd ForceCommand bypassed (exit %d): %s", code, out)
	}
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("port forwarding allowed despite AllowTcpForwarding no")
	}
	s, _ := c.NewSession()
	defer s.Close()
	if err := s.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("pty allowed despite PermitTTY no")
	}
}

func helperCall(t *testing.T, exts map[string]string, req string) (string, int) {
	t.Helper()
	c, err := dial("agent-ro", mintCert(t, "ssh-mcp-live", liveOpts, exts, 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return runCmd(c, req)
}

func TestSSHDCertPolicyIsEnforcedOnHost(t *testing.T) {
	narrow := map[string]string{pathsExt: `{"allow":["/var/log/"],"deny":[]}`}
	// Allowed under the host floor, outside the certificate policy.
	out, code := helperCall(t, narrow, `{"tool":"read_file","args":{"path":"/etc/app/app.conf"}}`)
	if code != 2 || strings.Contains(out, "listen=8080") {
		t.Fatalf("cert policy not enforced (exit %d): %s", code, out)
	}
	// A symlink inside the allowed tree pointing outside it.
	out, code = helperCall(t, narrow, `{"tool":"read_file","args":{"path":"/var/log/app/link-to-conf"}}`)
	if code != 2 || strings.Contains(out, "listen=8080") {
		t.Fatalf("symlink got around cert policy (exit %d): %s", code, out)
	}
	// Same request with the default policy works.
	out, code = helperCall(t, nil, `{"tool":"read_file","args":{"path":"/var/log/app/link-to-conf"}}`)
	if code != 0 || !strings.Contains(out, "listen=8080") {
		t.Fatalf("allowed read failed (exit %d): %s", code, out)
	}
	// A certificate without any path policy is refused outright.
	out, code = helperCall(t, map[string]string{pathsExt: ""}, `{"tool":"host_overview"}`)
	if code != 2 || !strings.Contains(out, "no path policy") {
		t.Fatalf("policy-less cert accepted (exit %d): %s", code, out)
	}
	// The certificate cannot widen the host floor.
	wide := map[string]string{pathsExt: `{"allow":["/"],"deny":[]}`}
	out, code = helperCall(t, wide, `{"tool":"read_file","args":{"path":"/etc/shadow"}}`)
	if code != 2 || strings.Contains(out, "root:") {
		t.Fatalf("cert widened the host floor (exit %d): %s", code, out)
	}
}

func TestSSHDInteractiveLoginRefused(t *testing.T) {
	c, err := dial("agent-ro", mintCert(t, "ssh-mcp-live", liveOpts, nil, 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	defer s.Close()
	var stdout, stderr bytes.Buffer
	s.Stdout, s.Stderr = &stdout, &stderr
	if err := s.Shell(); err != nil {
		return // refusing the shell request outright is also fine
	}
	err = s.Wait()
	ee, ok := err.(*ssh.ExitError)
	if !ok || ee.ExitStatus() != 2 || !strings.Contains(stderr.String(), "interactive login is not allowed") {
		t.Fatalf("interactive shell not refused: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func TestSSHDCertificateChecks(t *testing.T) {
	if _, err := dial("agent-ro", mintCert(t, "ssh-mcp-sftp", nil, nil, 5*time.Minute)); err == nil {
		t.Error("sftp principal accepted for agent-ro")
	}
	if _, err := dial("agent-ro", mintCert(t, "ssh-mcp-live", liveOpts, nil, -time.Minute)); err == nil {
		t.Error("expired certificate accepted")
	}
	if _, err := dial("root", mintCert(t, "root", nil, nil, 5*time.Minute)); err == nil {
		t.Error("root login accepted")
	}
	// A key not signed by the CA.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	plain, _ := ssh.NewSignerFromKey(priv)
	if _, err := dial("agent-ro", plain); err == nil {
		t.Error("plain key accepted")
	}
	// A certificate signed by a different CA.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherCA, _ := ssh.NewSignerFromKey(other)
	pub, kpriv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	cert := &ssh.Certificate{Key: sp, CertType: ssh.UserCert, ValidPrincipals: []string{"ssh-mcp-live"},
		ValidAfter: 0, ValidBefore: ssh.CertTimeInfinity, Permissions: ssh.Permissions{CriticalOptions: liveOpts}}
	_ = cert.SignCert(rand.Reader, otherCA)
	ks, _ := ssh.NewSignerFromKey(kpriv)
	forged, _ := ssh.NewCertSigner(cert, ks)
	if _, err := dial("agent-ro", forged); err == nil {
		t.Error("certificate from a foreign CA accepted")
	}
}

func TestSFTPIsReadOnly(t *testing.T) {
	// Drive OpenSSH's sftp client with a freshly minted SFTP certificate.
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	cert := &ssh.Certificate{Key: sp, CertType: ssh.UserCert, ValidPrincipals: []string{"ssh-mcp-sftp"},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(5 * time.Minute).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{pathsExt: defaultPaths}}}
	if err := cert.SignCert(rand.Reader, caSigner(t)); err != nil {
		t.Fatal(err)
	}
	block, _ := ssh.MarshalPrivateKey(priv, "")
	keyPEM := pemEncode(block)
	if err := os.WriteFile(filepath.Join(dir, "k"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k-cert.pub"), ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no local sftp client")
	}
	batch := "get /var/log/app/app.log " + filepath.Join(dir, "got") + "\nput " + filepath.Join(dir, "k-cert.pub") + " /var/log/app/pwned\nmkdir /var/log/app/pwned-dir\nrm /var/log/app/app.log\nget /etc/app/.env " + filepath.Join(dir, "env") + "\n"
	cmd := exec.Command("sftp", "-b", "-", "-P", "18472",
		"-i", filepath.Join(dir, "k"), "-o", "CertificateFile="+filepath.Join(dir, "k-cert.pub"),
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes", "agent-sftp@127.0.0.1")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(batch, "\n", "\n-")) // "-" prefix: keep going on error
	out, _ := cmd.CombinedOutput()
	got, _ := os.ReadFile(filepath.Join(dir, "got"))
	if !strings.Contains(string(got), "ERROR upstream timeout") {
		t.Fatalf("sftp read failed:\n%s", out)
	}
	if n := strings.Count(strings.ToLower(string(out)), "permission denied"); n < 3 {
		t.Fatalf("expected 3 refused writes, sftp said:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "env")); err == nil {
		t.Fatalf("denied .env fetched over sftp:\n%s", out)
	}
}

// TestPolicyReload edits policy.yaml inside the running server and sends
// SIGHUP, as `systemctl reload` does. A valid change applies without a
// restart; an invalid file is refused and the running policy stays.
func TestPolicyReload(t *testing.T) {
	compose := func(args ...string) {
		t.Helper()
		cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
		cmd.Dir = bedDir(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("docker compose %v: %v\n%s", args, err, out)
		}
	}
	const file = "/etc/ssh-mcp/policy.yaml"
	edit := func(script string) {
		t.Helper()
		compose("exec", "-T", "-u", "root", "server", "sh", "-c", script)
		compose("kill", "-s", "HUP", "server")
		time.Sleep(time.Second)
	}
	compose("exec", "-T", "-u", "root", "server", "cp", "-p", file, file+".orig")
	t.Cleanup(func() { edit("cp -p " + file + ".orig " + file) })

	cs := session(t, "log-bot")
	ps := map[string]any{"host": "web-1", "limit": 3}
	out, isErr := call(t, cs, "ps", ps)
	expect(t, "ps before reload", out, true, isErr, []string{"refused"}, nil)

	edit(`sed -i 's/tools: \[journal, tail_file\]/tools: [journal, tail_file, ps]/' ` + file)
	out, isErr = call(t, cs, "ps", ps)
	expect(t, "ps after reload", out, false, isErr, []string{"PID"}, nil)

	edit(`printf 'rules: [ {who: {}} ]\n' > ` + file)
	out, isErr = call(t, cs, "ps", ps)
	expect(t, "ps after a refused reload", out, false, isErr, []string{"PID"}, nil)
}
