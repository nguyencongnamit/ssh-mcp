// Package transport opens a byte stream to a target's sshd.
//
// "ssm" tunnels through AWS Systems Manager using the AWS-StartSSHSession
// document, so no inbound port is open on the target and every session lands
// in CloudTrail. "direct" dials host:port (local test bed, or networks where
// SSH is already reachable over VPN).
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

// Dialer opens a connection to a host's sshd.
type Dialer interface {
	Dial(ctx context.Context, h inventory.Host) (net.Conn, error)
}

// Auto picks the transport from the host record.
type Auto struct {
	SSM    *SSM
	Direct *Direct
}

// Dial implements Dialer.
func (a Auto) Dial(ctx context.Context, h inventory.Host) (net.Conn, error) {
	switch h.Transport {
	case "direct":
		if a.Direct == nil {
			return nil, errors.New("direct transport disabled")
		}
		return a.Direct.Dial(ctx, h)
	case "ssm", "":
		if a.SSM == nil {
			return nil, errors.New("ssm transport disabled")
		}
		return a.SSM.Dial(ctx, h)
	default:
		return nil, fmt.Errorf("unknown transport %q", h.Transport)
	}
}

// Direct dials TCP.
type Direct struct{ Timeout time.Duration }

// Dial implements Dialer.
func (d *Direct) Dial(ctx context.Context, h inventory.Host) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.Timeout}
	return nd.DialContext(ctx, "tcp", h.Address)
}

// SSM tunnels SSH over `aws ssm start-session`. It needs the AWS CLI and the
// session-manager-plugin on the server.
type SSM struct {
	AWSBin string // default "aws"
	Port   int    // default 22
}

// Dial implements Dialer.
func (s *SSM) Dial(ctx context.Context, h inventory.Host) (net.Conn, error) {
	if !validInstanceID(h.ID) {
		return nil, fmt.Errorf("ssm transport needs an EC2 instance ID, got %q", h.ID)
	}
	bin := s.AWSBin
	if bin == "" {
		bin = "aws"
	}
	port := s.Port
	if port == 0 {
		port = 22
	}
	args := []string{
		"ssm", "start-session",
		"--target", h.ID,
		"--document-name", "AWS-StartSSHSession",
		"--parameters", fmt.Sprintf("portNumber=%d", port),
	}
	if h.Region != "" {
		args = append(args, "--region", h.Region)
	}
	if h.Profile != "" {
		args = append(args, "--profile", h.Profile)
	}
	// Not CommandContext: the process must outlive the dial context and is
	// killed when the connection is closed.
	cmd := exec.Command(bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &tailBuffer{max: 4096}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start aws ssm: %w", err)
	}
	c := &procConn{cmd: cmd, r: stdout, w: stdin, stderr: stderr, id: h.ID, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-c.done:
		}
	}()
	return c, nil
}

func validInstanceID(s string) bool {
	if len(s) < 10 || len(s) > 19 || s[:2] != "i-" {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// procConn adapts a subprocess's stdio to net.Conn.
type procConn struct {
	cmd    *exec.Cmd
	r      io.ReadCloser
	w      io.WriteCloser
	stderr *tailBuffer
	id     string

	once sync.Once
	done chan struct{}
}

func (c *procConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF && n == 0 {
		if msg := c.stderr.String(); msg != "" {
			return 0, fmt.Errorf("ssm session ended: %s", msg)
		}
	}
	return n, err
}

func (c *procConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *procConn) Close() error {
	c.once.Do(func() {
		_ = c.w.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.cmd.Wait()
		close(c.done)
	})
	return nil
}

func (c *procConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// RemoteAddr has no IP: host keys for SSM hosts are matched on the instance
// ID only (known_hosts "i-0abc... ssh-ed25519 ..."). knownhosts needs a
// host:port shape; an empty host matches no known_hosts line by address.
func (c *procConn) RemoteAddr() net.Addr             { return &net.TCPAddr{Port: 22} }
func (c *procConn) SetDeadline(time.Time) error      { return nil }
func (c *procConn) SetReadDeadline(time.Time) error  { return nil }
func (c *procConn) SetWriteDeadline(time.Time) error { return nil }

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

// LoopbackSource is what sshd sees under AWS-StartSSHSession: the SSM agent
// on the instance connects to sshd from loopback.
const LoopbackSource = "127.0.0.1/32,::1/128"

// SourceAddress returns the certificate source-address for a host: loopback
// for SSM, the configured server address for direct SSH.
func SourceAddress(h inventory.Host, direct string) string {
	if h.Transport == "direct" {
		return direct
	}
	return LoopbackSource
}
