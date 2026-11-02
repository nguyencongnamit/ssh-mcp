package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIssueLiveCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")
	pubLine, err := GenerateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateFile(path); err == nil {
		t.Fatal("overwrite allowed")
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Paths = `{"allow":["/var/log/"],"deny":[]}`
	e, err := c.IssueLive("user:a call:1", "10.0.0.5/32")
	if err != nil {
		t.Fatal(err)
	}
	cert := e.Cert
	if cert.Permissions.CriticalOptions["force-command"] != DefaultHelperPath {
		t.Fatal("force-command not pinned")
	}
	if cert.Permissions.CriticalOptions["source-address"] != "10.0.0.5/32" {
		t.Fatal("source-address missing")
	}
	for k := range cert.Permissions.Extensions {
		if k != PathsExtension {
			t.Fatalf("unexpected extension %q (no permit-* allowed)", k)
		}
	}
	if cert.Permissions.Extensions[PathsExtension] != c.Paths {
		t.Fatal("path policy not embedded")
	}
	c.Paths = ""
	if _, err := c.IssueLive("x", ""); err == nil {
		t.Fatal("issued a certificate with no path policy")
	}
	c.Paths = `{"allow":["/var/log/"],"deny":[]}`
	life := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if life > 6*time.Minute {
		t.Fatalf("certificate lives too long: %v", life)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != PrincipalLive {
		t.Fatalf("principals: %v", cert.ValidPrincipals)
	}

	// The certificate must verify against the CA public key.
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubLine))
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority:          func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(caPub.Marshal()) },
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(PrincipalLive, cert); err != nil {
		t.Fatalf("cert does not verify: %v", err)
	}
	if err := checker.CheckCert(PrincipalSFTP, cert); err == nil {
		t.Fatal("live cert valid for sftp principal")
	}
}

func TestLoadFileRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")
	if _, err := GenerateFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("world-readable CA key accepted")
	}
}
