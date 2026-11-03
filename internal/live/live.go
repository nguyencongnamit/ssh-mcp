// Package live runs one helper request on a target over SSH.
//
// Each call: mint a 5-minute certificate for a fresh in-memory key, open a
// transport, verify the host key, send ONE JSON line as the SSH command, read
// capped output, close. No pty is requested and none would be granted.
package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nguyencongnamit/ssh-mcp/internal/ca"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
	"github.com/nguyencongnamit/ssh-mcp/internal/transport"
)

// User is the target account for live tools.
const User = "agent-ro"

// ErrRefused means the helper refused the request (exit 2).
var ErrRefused = errors.New("refused by target helper")

// Client executes helper requests.
type Client struct {
	CA      *ca.CA
	Dialer  transport.Dialer
	HostKey ssh.HostKeyCallback
	Timeout time.Duration
	// DirectSource is the certificate source-address for direct-transport
	// hosts (the server's private IP). SSM hosts always get loopback.
	DirectSource string
	// JumpSource is the bastion's address, for jump-transport hosts.
	JumpSource string
}

// HostKeysFromFile builds a host-key callback from an OpenSSH known_hosts
// file. Entries are keyed by host ID (the instance ID for SSM hosts);
// @cert-authority lines are supported, so a host CA can vouch for the fleet.
func HostKeysFromFile(path string) (ssh.HostKeyCallback, error) {
	return knownhosts.New(path)
}

// Result of a call.
type Result struct {
	Output   string
	ExitCode int
	Stderr   string
}

// Exec runs req on host. keyID is recorded in the target's sshd log.
func (c *Client) Exec(ctx context.Context, host inventory.Host, keyID string, req protocol.Request) (*Result, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(line) > protocol.MaxRequestBytes {
		return nil, fmt.Errorf("request too large")
	}
	if strings.ContainsAny(string(line), "\n\r") {
		return nil, fmt.Errorf("request contains newline")
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	eph, err := c.CA.IssueLive(keyID, transport.SourceAddress(host, transport.Sources{Direct: c.DirectSource, Jump: c.JumpSource}))
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	conn, err := c.Dialer.Dial(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", host.ID, err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()

	cfg := &ssh.ClientConfig{
		User:            User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(eph.Signer)},
		HostKeyCallback: c.HostKey,
		Timeout:         15 * time.Second,
		ClientVersion:   "SSH-2.0-ssh-mcp",
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, host.ID+":22", cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake with %s: %w", host.ID, err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr capBuf
	stdout.max = protocol.MaxFileBytes + 1024 // helper output plus trailer
	stderr.max = 4096
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	runErr := sess.Run(string(line))
	res := &Result{Output: stdout.String(), Stderr: strings.TrimSpace(stderr.String())}
	if runErr == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("call timed out after %v", timeout)
	}
	var ee *ssh.ExitError
	if errors.As(runErr, &ee) {
		res.ExitCode = ee.ExitStatus()
		if res.ExitCode == 2 {
			return res, fmt.Errorf("%w: %s", ErrRefused, res.Stderr)
		}
		return res, fmt.Errorf("helper failed (exit %d): %s", res.ExitCode, res.Stderr)
	}
	return res, runErr
}

// capBuf keeps at most max bytes.
type capBuf struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (b *capBuf) Write(p []byte) (int, error) {
	n := len(p)
	room := b.max - b.Len()
	if room <= 0 {
		b.truncated = true
		return n, nil
	}
	if len(p) > room {
		p = p[:room]
		b.truncated = true
	}
	b.Buffer.Write(p)
	return n, nil
}
