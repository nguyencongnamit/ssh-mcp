package pathpolicy

import (
	"path"
	"strings"
	"testing"
)

// FuzzDefaultPolicy checks the built-in policy against invariants that must
// hold for every possible path, not just the ones in the table tests.
func FuzzDefaultPolicy(f *testing.F) {
	for _, s := range []string{
		"/var/log/syslog", "/etc/hosts", "/etc/shadow", "/etc/ssh/sshd_config",
		"/var/log/../etc/shadow", "/etc//shadow", "/etc/./shadow", "/etc/app/.ENV",
		"/var/log/app/Secrets/x.log", "/var/log", "/etc", "/", "relative/path",
		"/etc/sudoers.d/90-cloud", "/var/log/audit/audit.log", "/etc/app/id_ed25519.pub",
		"/var/logs/x", "/etcx/hosts", "/var/log/app/db.Password.txt",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	pol := Default()
	sensitive := []string{"secret", "password", "token", ".env", "id_rsa", "id_ed25519", ".pem", ".key"}
	f.Fuzz(func(t *testing.T, p string, isDir bool) {
		ok := pol.Allowed(p, isDir)
		if !ok {
			return
		}
		c := Clean(p)
		if c == "" {
			t.Fatalf("relative path %q allowed", p)
		}
		// Cleaning must not change the decision: "..", "//" and "." can never
		// be used to step around a rule.
		if !pol.Allowed(c, isDir) {
			t.Fatalf("%q allowed but its clean form %q is not", p, c)
		}
		if !(strings.HasPrefix(c, "/var/log/") || strings.HasPrefix(c, "/etc/") ||
			(isDir && (c == "/var/log" || c == "/etc"))) {
			t.Fatalf("%q (clean %q) allowed outside the allow prefixes", p, c)
		}
		for _, d := range []string{"/etc/ssh", "/etc/sudoers.d", "/etc/ssl/private", "/etc/ssh-mcp", "/etc/letsencrypt", "/var/log/audit"} {
			if c == d || strings.HasPrefix(c, d+"/") {
				t.Fatalf("%q allowed inside denied subtree %s", p, d)
			}
		}
		for _, el := range strings.Split(strings.ToLower(c), "/") {
			for _, s := range sensitive {
				if strings.Contains(el, s) && (s != ".env" || el == ".env" || strings.HasPrefix(el, ".env.")) &&
					(s != ".pem" && s != ".key" || strings.HasSuffix(el, s)) &&
					(s != "id_rsa" && s != "id_ed25519" || strings.HasPrefix(el, s)) {
					t.Fatalf("%q allowed although element %q matches %q", p, el, s)
				}
			}
		}
		if b := path.Base(c); b == "shadow" && path.Dir(c) == "/etc" {
			t.Fatalf("%q allowed", p)
		}
	})
}
