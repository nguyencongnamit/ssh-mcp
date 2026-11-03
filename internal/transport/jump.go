package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

// JumpConfig reaches targets through an SSH bastion (jump host), for fleets
// outside AWS or without SSM. The bastion account only needs TCP forwarding
// to the targets' port 22; it never gets a shell (see docs/deployment.md).
type JumpConfig struct {
	Address    string `yaml:"address"`     // bastion host:port
	User       string `yaml:"user"`        // bastion account
	KeyFile    string `yaml:"key_file"`    // private key for the bastion, 0600
	KnownHosts string `yaml:"known_hosts"` // the bastion's host key
	// SourceAddress is the bastion's address as targets see it. It is
	// pinned into certificates for jump hosts.
	SourceAddress string `yaml:"source_address"`
}

// safeToken is what may appear in the sshfs ProxyCommand, which ssh runs
// through a shell: no spaces, quotes or metacharacters.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9_./:@\[\]-]+$`)

// Validate checks the config. Paths must already be absolute.
func (c *JumpConfig) Validate() error {
	if c.Address == "" || c.User == "" || c.KeyFile == "" || c.KnownHosts == "" {
		return errors.New("transport.jump needs address, user, key_file and known_hosts")
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return fmt.Errorf("transport.jump.address: %w", err)
	}
	for name, v := range map[string]string{"address": c.Address, "user": c.User, "key_file": c.KeyFile, "known_hosts": c.KnownHosts} {
		if !safeToken.MatchString(v) || strings.HasPrefix(v, "-") {
			return fmt.Errorf("transport.jump.%s %q contains characters that are not allowed", name, v)
		}
	}
	fi, err := os.Stat(c.KeyFile)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: permissions %o are too open (want 0600)", c.KeyFile, fi.Mode().Perm())
	}
	return nil
}

// Jump dials targets through the bastion.
type Jump struct {
	Config  JumpConfig
	Timeout time.Duration

	once    sync.Once
	signer  ssh.Signer
	hostKey ssh.HostKeyCallback
	initErr error
}

func (j *Jump) init() error {
	j.once.Do(func() {
		b, err := os.ReadFile(j.Config.KeyFile)
		if err != nil {
			j.initErr = err
			return
		}
		if j.signer, err = ssh.ParsePrivateKey(b); err != nil {
			j.initErr = fmt.Errorf("%s: %w", j.Config.KeyFile, err)
			return
		}
		if j.hostKey, err = knownhosts.New(j.Config.KnownHosts); err != nil {
			j.initErr = fmt.Errorf("%s: %w", j.Config.KnownHosts, err)
		}
	})
	return j.initErr
}

// Dial opens one bastion connection for this call and a TCP channel through
// it to h.Address. Closing the returned conn closes both.
func (j *Jump) Dial(ctx context.Context, h inventory.Host) (net.Conn, error) {
	if err := j.init(); err != nil {
		return nil, err
	}
	timeout := j.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	nd := net.Dialer{Timeout: timeout}
	raw, err := nd.DialContext(ctx, "tcp", j.Config.Address)
	if err != nil {
		return nil, fmt.Errorf("bastion %s: %w", j.Config.Address, err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, j.Config.Address, &ssh.ClientConfig{
		User:            j.Config.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(j.signer)},
		HostKeyCallback: j.hostKey,
		Timeout:         timeout,
	})
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("bastion %s: %w", j.Config.Address, err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	conn, err := client.DialContext(ctx, "tcp", h.Address)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("bastion %s -> %s: %w", j.Config.Address, h.Address, err)
	}
	return &jumpConn{Conn: conn, client: client}, nil
}

type jumpConn struct {
	net.Conn
	client *ssh.Client
	once   sync.Once
}

func (c *jumpConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.client.Close() })
	return err
}

// ProxyCommand returns the ssh ProxyCommand that reaches %h:%p through the
// bastion, for sshfs mirrors. Every token was checked by Validate.
func (c *JumpConfig) ProxyCommand() string {
	host, port, _ := net.SplitHostPort(c.Address)
	return "ssh -i " + c.KeyFile + " -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes" +
		" -o UserKnownHostsFile=" + c.KnownHosts + " -o GlobalKnownHostsFile=/dev/null" +
		" -p " + port + " -W %h:%p " + c.User + "@" + host
}
