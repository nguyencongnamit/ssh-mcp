package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

func key(t *testing.T) ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// SSM connections have no meaningful remote IP. Host keys must still verify
// by instance ID, and a key for one instance must not satisfy another.
func TestSSMHostKeyMatchesByInstanceID(t *testing.T) {
	good, other := key(t), key(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"i-0aaaaaaaaaaaaaaa1"}, good) + "\n" + knownhosts.Line([]string{"i-0bbbbbbbbbbbbbbb2"}, other) + "\n"
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(kh)
	if err != nil {
		t.Fatal(err)
	}
	remote := (&procConn{}).RemoteAddr()
	if err := cb("i-0aaaaaaaaaaaaaaa1:22", remote, good); err != nil {
		t.Fatalf("valid host key rejected: %v", err)
	}
	if err := cb("i-0aaaaaaaaaaaaaaa1:22", remote, other); err == nil {
		t.Fatal("another instance's key accepted")
	}
	if err := cb("i-0ccccccccccccccc3:22", remote, good); err == nil {
		t.Fatal("unknown instance accepted")
	}
}

func TestSourceAddress(t *testing.T) {
	s := Sources{Direct: "10.0.0.5/32", Jump: "10.0.9.9/32"}
	if SourceAddress(inventory.Host{Transport: "ssm"}, s) != LoopbackSource {
		t.Fatal("ssm must use loopback")
	}
	if SourceAddress(inventory.Host{Transport: "direct"}, s) != "10.0.0.5/32" {
		t.Fatal("direct must use the server's source")
	}
	if SourceAddress(inventory.Host{Transport: "jump"}, s) != "10.0.9.9/32" {
		t.Fatal("jump must use the bastion's source")
	}
}

func TestValidInstanceID(t *testing.T) {
	for _, ok := range []string{"i-0123456789abcdef0", "i-01234567"} {
		if !validInstanceID(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"", "i-", "i-XYZ12345", "web-1", "i-0123456789abcdef0;id", "i-0123456789abcdef01234"} {
		if validInstanceID(bad) {
			t.Errorf("%s should be invalid", bad)
		}
	}
}
