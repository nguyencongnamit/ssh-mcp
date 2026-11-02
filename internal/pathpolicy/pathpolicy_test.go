package pathpolicy

import "testing"

func TestDefaultPolicy(t *testing.T) {
	p := Default()
	allow := []struct {
		path  string
		isDir bool
	}{
		{"/var/log/syslog", false},
		{"/var/log/nginx/access.log", false},
		{"/var/log", true},
		{"/etc/nginx/nginx.conf", false},
		{"/etc/os-release", false},
		{"/etc/hosts", false},
	}
	for _, c := range allow {
		if !p.Allowed(c.path, c.isDir) {
			t.Errorf("%s should be allowed", c.path)
		}
	}
	deny := []string{
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/90-cloud",
		"/etc/ssh/sshd_config", "/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssl/private/server.key", "/etc/app/.env", "/etc/app/.env.production",
		"/etc/app/tls.pem", "/etc/app/conf.d/secrets/db.yml", "/etc/app/api_token",
		"/etc/app/DB_PASSWORD", "/var/log/audit/audit.log", "/var/log/btmp",
		"/etc/ssh-mcp/helper-policy.json",
		// outside allow prefixes
		"/root/.bash_history", "/home/ubuntu/.ssh/authorized_keys", "/proc/1/environ",
		"/var/lib/app/data.db", "/", "/var/logevil/x", "/etcetera/x",
		// traversal
		"/var/log/../../etc/shadow", "/var/log/../lib/app/x",
		// relative
		"var/log/syslog", "",
		// list the deny subtree itself
	}
	for _, d := range deny {
		if p.Allowed(d, false) {
			t.Errorf("%s should be denied", d)
		}
	}
	if p.Allowed("/etc/ssh", true) {
		t.Error("/etc/ssh dir should be denied")
	}
	if p.Allowed("/etc", false) {
		t.Error("/etc as a file should not be allowed (prefix match needs a child)")
	}
}

func TestDenyWinsOverAllow(t *testing.T) {
	p := Policy{Allow: []string{"/"}, Deny: []string{"/etc/shadow"}}
	if p.Allowed("/etc/shadow", false) {
		t.Fatal("deny must win")
	}
	if !p.Allowed("/srv/app/app.log", false) {
		t.Fatal("root allow should allow other paths")
	}
}
