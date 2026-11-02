package sandbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nguyencongnamit/ssh-mcp/internal/ca"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

func TestArgsIsolation(t *testing.T) {
	mirror := t.TempDir()
	r := NewRunner(2)
	argv, err := r.Args(mirror, "i-0abc", "grep -r error /targets/i-0abc/var/log | head")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--unshare-all", "--die-with-parent", "--cap-drop ALL", "--clearenv",
		"--ro-bind " + mirror + " /targets/i-0abc",
		"--size 67108864 --tmpfs /tmp",
		"--remount-ro /", "--uid 65534", "--as=1073741824",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"--share-net", "--bind ", "/var/lib/ssh-mcp", "--ro-bind /etc /etc", "/home", "--ro-bind /proc"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unexpected %q in argv", bad)
		}
	}
	if argv[len(argv)-1] != "grep -r error /targets/i-0abc/var/log | head" || argv[len(argv)-3] != "/bin/sh" {
		t.Errorf("script not passed as a single final argument: %v", argv[len(argv)-4:])
	}
}

func TestCheckPrefixes(t *testing.T) {
	if err := CheckPrefixes([]string{"/var/log/", "/etc/"}, []string{"/var/log/"}); err == nil {
		t.Error("/etc mirrored while policy allows only /var/log")
	}
	if err := CheckPrefixes([]string{"/var/log/app/"}, []string{"/var/log/"}); err != nil {
		t.Error(err)
	}
	if err := CheckPrefixes([]string{"/var/logevil/"}, []string{"/var/log/"}); err == nil {
		t.Error("prefix boundary not respected")
	}
}

func TestValidateAWS(t *testing.T) {
	for _, bad := range []inventory.Host{
		{Region: "us-east-1>/tmp/x"}, {Region: "us-east-1\n"}, {Region: "us east 1"},
		{Profile: "p;id"}, {Profile: "p>x"}, {Profile: "p q"},
	} {
		if validateAWS(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if validateAWS(inventory.Host{Region: "ap-southeast-1", Profile: "prod_ro"}) != nil {
		t.Error("rejected valid region/profile")
	}
}

func TestArgsRejects(t *testing.T) {
	r := NewRunner(1)
	if _, err := r.Args("/m", "../../etc", "ls"); err == nil {
		t.Error("path traversal in host dir accepted")
	}
	if _, err := r.Args("/m", "h", ""); err == nil {
		t.Error("empty script accepted")
	}
	if _, err := r.Args("/m", "h", strings.Repeat("a", MaxScriptBytes+1)); err == nil {
		t.Error("oversized script accepted")
	}
}

func TestSSHFSArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")
	if _, err := ca.GenerateFile(path); err != nil {
		t.Fatal(err)
	}
	c, _ := ca.LoadFile(path)
	c.Paths = `{"allow":["/var/log/"]}`
	m := &Mirrors{Root: "/srv/m", StateDir: "/srv/s", KnownHosts: "/srv/kh", CA: c, Prefixes: []string{"/var/log/"}}
	argv, err := m.sshfsArgs(inventory.Host{ID: "i-0123456789abcdef0", Transport: "ssm", Region: "ap-southeast-1"}, "/var/log/", "/srv/m/i-0123456789abcdef0/var/log")
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "agent-sftp@i-0123456789abcdef0:/var/log/" {
		t.Errorf("target: %s", argv[1])
	}
	opts := strings.Split(argv[4], ",")
	for _, want := range []string{"ro", "StrictHostKeyChecking=yes", "BatchMode=yes", "IdentitiesOnly=yes",
		"ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region ap-southeast-1"} {
		if !slices.Contains(opts, want) {
			t.Errorf("missing option %q", want)
		}
	}
	if _, err := m.sshfsArgs(inventory.Host{ID: "i-0123456789abcdef0", Transport: "ssm", Region: "us-east-1>/x"}, "/var/log/", "/x"); err == nil {
		t.Error("unsafe region accepted")
	}
}
