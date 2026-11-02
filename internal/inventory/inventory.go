// Package inventory lists target hosts and their tags.
//
// Two sources: a static YAML list (local test bed, or hosts outside EC2) and
// EC2 discovery by tag. Only hosts tagged ssh-mcp=enabled are ever returned by
// EC2 discovery, mirroring the IAM condition on the server role.
package inventory

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// EnableTag must be set to EnableValue on a host for ssh-mcp to touch it.
const (
	EnableTag   = "ssh-mcp"
	EnableValue = "enabled"
)

// Host is one target.
type Host struct {
	// ID is the stable identifier: the EC2 instance ID, or a static name.
	ID   string            `yaml:"id" json:"id"`
	Name string            `yaml:"name" json:"name"`
	Tags map[string]string `yaml:"tags" json:"tags"`
	// Transport is "ssm" (default for EC2) or "direct".
	Transport string `yaml:"transport" json:"transport"`
	// Address is host:port for the direct transport.
	Address string `yaml:"address,omitempty" json:"-"`
	Region  string `yaml:"region,omitempty" json:"region,omitempty"`
	// Profile/RoleARN select AWS credentials for multi-account setups.
	Profile string `yaml:"profile,omitempty" json:"-"`
}

// Source returns the current hosts.
type Source interface {
	Hosts(ctx context.Context) ([]Host, error)
}

// Static is a fixed host list loaded from YAML.
type Static struct{ List []Host }

// LoadStatic reads a YAML file of the form {hosts: [...]}.
func LoadStatic(path string) (*Static, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Hosts []Host `yaml:"hosts"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for i, h := range doc.Hosts {
		if h.ID == "" {
			return nil, fmt.Errorf("%s: host %d has no id", path, i)
		}
		if seen[h.ID] {
			return nil, fmt.Errorf("%s: duplicate host id %q", path, h.ID)
		}
		seen[h.ID] = true
		if h.Transport == "" {
			doc.Hosts[i].Transport = "ssm"
		}
		if doc.Hosts[i].Transport == "direct" && h.Address == "" {
			return nil, fmt.Errorf("%s: host %q uses direct transport but has no address", path, h.ID)
		}
		if doc.Hosts[i].Name == "" {
			doc.Hosts[i].Name = h.ID
		}
	}
	return &Static{List: doc.Hosts}, nil
}

// Hosts implements Source.
func (s *Static) Hosts(context.Context) ([]Host, error) { return s.List, nil }

// Multi merges sources; IDs must be unique across them.
type Multi []Source

// Hosts implements Source.
func (m Multi) Hosts(ctx context.Context) ([]Host, error) {
	var all []Host
	seen := map[string]bool{}
	for _, s := range m {
		hs, err := s.Hosts(ctx)
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			if seen[h.ID] {
				return nil, fmt.Errorf("duplicate host id %q across inventories", h.ID)
			}
			seen[h.ID] = true
			all = append(all, h)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	return all, nil
}

// Cached wraps a Source with a TTL cache.
type Cached struct {
	Src Source
	TTL time.Duration

	mu    sync.Mutex
	at    time.Time
	hosts []Host
}

// Hosts implements Source.
func (c *Cached) Hosts(ctx context.Context) ([]Host, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hosts != nil && time.Since(c.at) < c.TTL {
		return c.hosts, nil
	}
	hs, err := c.Src.Hosts(ctx)
	if err != nil {
		if c.hosts != nil {
			return c.hosts, nil // serve stale on transient errors
		}
		return nil, err
	}
	c.hosts, c.at = hs, time.Now()
	return hs, nil
}

// Find returns the host whose ID or Name equals key.
func Find(hosts []Host, key string) (Host, bool) {
	for _, h := range hosts {
		if h.ID == key {
			return h, true
		}
	}
	for _, h := range hosts {
		if h.Name == key {
			return h, true
		}
	}
	return Host{}, false
}
