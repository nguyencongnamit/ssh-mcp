package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAKeyOrKMS(t *testing.T) {
	base := "data_dir: d\nknown_hosts: k\npolicy: p\ninventory: {static: s}\n"
	for name, c := range map[string]struct {
		extra string
		ok    bool
	}{
		"key file":   {"ca_key: ca\n", true},
		"kms":        {"ca_kms: {key_id: alias/ssh-mcp-ca, region: eu-west-1}\n", true},
		"both":       {"ca_key: ca\nca_kms: {key_id: alias/x}\n", false},
		"neither":    {"", false},
		"typo field": {"ca_kms: {key: alias/x}\n", false},
	} {
		f := filepath.Join(t.TempDir(), "ssh-mcp.yaml")
		if err := os.WriteFile(f, []byte(base+c.extra), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(f)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, c.ok)
		}
		if err == nil && c.ok && strings.Contains(c.extra, "ca_kms") && cfg.CAKMS.KeyID != "alias/ssh-mcp-ca" {
			t.Errorf("%s: key id %q", name, cfg.CAKMS.KeyID)
		}
	}
}
