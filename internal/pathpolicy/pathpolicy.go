// Package pathpolicy decides which absolute paths a tool may read.
//
// The same rules run twice: on the server (against the requested path, before
// anything leaves) and in the helper on the target (against the path after
// symlinks are resolved on the real filesystem). Deny always wins over allow.
package pathpolicy

import (
	"path"
	"strings"
)

// Policy is an allow-prefix list plus deny patterns.
type Policy struct {
	// Allow lists directory prefixes, each ending in "/", e.g. "/var/log/".
	Allow []string `json:"allow" yaml:"allow"`
	// Deny lists patterns. A pattern ending in "/" denies a whole subtree.
	// A pattern starting with "**/" matches that glob against the final path
	// element at any depth. Anything else is matched with path.Match against
	// the full path.
	Deny []string `json:"deny" yaml:"deny"`
}

// Default is the built-in policy. It is deliberately narrow.
func Default() Policy {
	return Policy{
		Allow: []string{"/var/log/", "/etc/"},
		Deny: []string{
			"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
			"/etc/sudoers", "/etc/sudoers.d/",
			"/etc/ssh/", "/etc/ssl/private/", "/etc/pki/tls/private/",
			"/etc/ssh-mcp/",
			"/etc/security/opasswd",
			"/etc/letsencrypt/",
			"/var/log/btmp", "/var/log/audit/",
			"**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
			"**/id_rsa*", "**/id_ecdsa*", "**/id_ed25519*", "**/id_dsa*",
			"**/.netrc", "**/.pgpass", "**/.my.cnf", "**/credentials",
			"**/*.kdbx", "**/*secret*", "**/*password*", "**/*token*",
		},
	}
}

// Clean normalises p (absolute, no "..", no trailing slash except root).
// It returns "" if p is not absolute.
func Clean(p string) string {
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	return path.Clean(p)
}

// Allowed reports whether the cleaned absolute path p may be read.
// isDir must be true when p names a directory (used for list_dir, so that
// the allow prefix itself, e.g. "/var/log", is listable).
func (pol Policy) Allowed(p string, isDir bool) bool {
	c := Clean(p)
	if c == "" {
		return false
	}
	if pol.denied(c) {
		return false
	}
	for _, a := range pol.Allow {
		a = strings.TrimSuffix(a, "/")
		if a == "" { // "/" as an allow prefix
			return true
		}
		if strings.HasPrefix(c, a+"/") {
			return true
		}
		if isDir && c == a {
			return true
		}
	}
	return false
}

func (pol Policy) denied(c string) bool {
	base := path.Base(c)
	lowerBase := strings.ToLower(base)
	for _, d := range pol.Deny {
		switch {
		case strings.HasPrefix(d, "**/"):
			pat := strings.ToLower(strings.TrimPrefix(d, "**/"))
			if ok, _ := path.Match(pat, lowerBase); ok {
				return true
			}
			// A denied name anywhere in the path denies everything below it
			// (e.g. a directory called "secrets").
			for _, el := range strings.Split(strings.TrimPrefix(c, "/"), "/") {
				if ok, _ := path.Match(pat, strings.ToLower(el)); ok {
					return true
				}
			}
		case strings.HasSuffix(d, "/"):
			dd := strings.TrimSuffix(d, "/")
			if c == dd || strings.HasPrefix(c, dd+"/") {
				return true
			}
		default:
			if ok, _ := path.Match(d, c); ok {
				return true
			}
		}
	}
	return false
}
