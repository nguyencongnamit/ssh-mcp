// Package config loads the ssh-mcp server configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nguyencongnamit/ssh-mcp/internal/authn"
)

// Config is the server configuration file.
type Config struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	TLS       struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	DataDir       string            `yaml:"data_dir"`
	AuditKey      string            `yaml:"audit_key"`
	CAKey         string            `yaml:"ca_key"`
	SourceAddress string            `yaml:"source_address"`
	HelperPath    string            `yaml:"helper_path"`
	KnownHosts    string            `yaml:"known_hosts"`
	Policy        string            `yaml:"policy"`
	OIDC          *authn.OIDCConfig `yaml:"oidc"`
	Inventory     struct {
		Static string `yaml:"static"`
		EC2    []struct {
			Region  string `yaml:"region"`
			Profile string `yaml:"profile"`
		} `yaml:"ec2"`
	} `yaml:"inventory"`
	Transport struct {
		SSM    bool `yaml:"ssm"`
		Direct bool `yaml:"direct"`
	} `yaml:"transport"`
	Console struct {
		// Listen enables the admin web console, e.g. 127.0.0.1:8444. Keep it
		// off the network the agents use; reach it over SSM port forwarding
		// or a VPN.
		Listen       string `yaml:"listen"`
		User         string `yaml:"user"`
		PasswordHash string `yaml:"password_hash"` // ssh-mcp console passwd
		// Timezone for dates in the UI, e.g. Asia/Ho_Chi_Minh (default: server local).
		Timezone string `yaml:"timezone"`
	} `yaml:"console"`
	Sandbox struct {
		Enabled       bool     `yaml:"enabled"`
		Prefixes      []string `yaml:"prefixes"`
		MaxConcurrent int      `yaml:"max_concurrent"`
		// Cgroups: "auto" (use if delegated, warn otherwise), "required", "off".
		Cgroups string `yaml:"cgroups"`
	} `yaml:"sandbox"`
}

// Load reads and validates a config file. Relative paths are resolved
// against the config file's directory.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	abs := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	for _, p := range []*string{&c.DataDir, &c.AuditKey, &c.CAKey, &c.KnownHosts, &c.Policy, &c.Inventory.Static, &c.TLS.CertFile, &c.TLS.KeyFile} {
		abs(p)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8443"
	}
	if c.DataDir == "" {
		return nil, errors.New("data_dir is required")
	}
	if c.CAKey == "" || c.KnownHosts == "" || c.Policy == "" {
		return nil, errors.New("ca_key, known_hosts and policy are required")
	}
	if c.Inventory.Static == "" && len(c.Inventory.EC2) == 0 {
		return nil, errors.New("inventory needs static and/or ec2")
	}
	if !c.Transport.SSM && !c.Transport.Direct {
		c.Transport.SSM = true
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return nil, errors.New("tls needs both cert_file and key_file")
	}
	if c.Console.Listen != "" && (c.Console.User == "" || c.Console.PasswordHash == "") {
		return nil, errors.New("console.listen needs console.user and console.password_hash (ssh-mcp console passwd)")
	}
	switch c.Sandbox.Cgroups {
	case "":
		c.Sandbox.Cgroups = "auto"
	case "auto", "required", "off":
	default:
		return nil, errors.New("sandbox.cgroups must be auto, required or off")
	}
	if len(c.Sandbox.Prefixes) == 0 {
		c.Sandbox.Prefixes = []string{"/var/log/", "/etc/"}
	}
	return &c, nil
}

// DBPath is the SQLite file.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "ssh-mcp.db") }
