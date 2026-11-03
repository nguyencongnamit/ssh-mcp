package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

// bastion is an in-process SSH server that accepts one client key and
// forwards direct-tcpip channels, recording where they went.
func bastion(t *testing.T, clientKey ssh.PublicKey) (addr string, hostKey ssh.PublicKey, opened chan string) {
	t.Helper()
	_, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hpriv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) {
			return nil, nil
		}
		return nil, io.EOF
	}}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	opened = make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "direct-tcpip" {
						_ = nc.Reject(ssh.Prohibited, "no")
						continue
					}
					p := nc.ExtraData()
					hl := binary.BigEndian.Uint32(p)
					host := string(p[4 : 4+hl])
					port := binary.BigEndian.Uint32(p[4+hl:])
					dst := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
					opened <- dst
					up, err := net.Dial("tcp", dst)
					if err != nil {
						_ = nc.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, creqs, _ := nc.Accept()
					go ssh.DiscardRequests(creqs)
					go func() { _, _ = io.Copy(ch, up); ch.Close() }()
					go func() { _, _ = io.Copy(up, ch); up.Close() }()
				}
			}()
		}
	}()
	return l.Addr().String(), hs.PublicKey(), opened
}

func TestJumpDial(t *testing.T) {
	dir := t.TempDir()
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	cs, _ := ssh.NewSignerFromKey(cpriv)
	block, _ := ssh.MarshalPrivateKey(cpriv, "")
	keyFile := filepath.Join(dir, "jump_key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, hk, opened := bastion(t, cs.PublicKey())

	// The "target": an echo server.
	tl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tl.Close()
	go func() {
		c, err := tl.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
		}
	}()

	kh := filepath.Join(dir, "known_hosts")
	host, port, _ := net.SplitHostPort(addr)
	line := "[" + host + "]:" + port + " " + string(ssh.MarshalAuthorizedKey(hk))
	_ = os.WriteFile(kh, []byte(line), 0o600)
	cfg := JumpConfig{Address: addr, User: "ssh-mcp-jump", KeyFile: keyFile, KnownHosts: kh, SourceAddress: "10.0.9.9/32"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	j := &Jump{Config: cfg, Timeout: 5 * time.Second}
	conn, err := j.Dial(context.Background(), inventory.Host{ID: "web-9", Transport: "jump", Address: tl.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-opened; got != tl.Addr().String() {
		t.Fatalf("bastion forwarded to %s", got)
	}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through bastion: %q %v", buf, err)
	}
	conn.Close()

	// A bastion whose host key is not the pinned one is refused.
	_ = os.WriteFile(kh, []byte("["+host+"]:"+port+" "+string(ssh.MarshalAuthorizedKey(cs.PublicKey()))), 0o600)
	j2 := &Jump{Config: cfg}
	if _, err := j2.Dial(context.Background(), inventory.Host{Address: tl.Addr().String()}); err == nil {
		t.Fatal("bastion with an unknown host key accepted")
	}
}

func TestJumpValidate(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	_ = os.WriteFile(key, []byte("x"), 0o600)
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte("x"), 0o644)
	good := JumpConfig{Address: "bastion.internal:22", User: "jump", KeyFile: key, KnownHosts: filepath.Join(dir, "kh")}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if pc := good.ProxyCommand(); !strings.Contains(pc, "-W %h:%p jump@bastion.internal") || !strings.Contains(pc, "-p 22") {
		t.Fatalf("ProxyCommand %q", pc)
	}
	for name, mut := range map[string]func(*JumpConfig){
		"no port":        func(c *JumpConfig) { c.Address = "bastion" },
		"shell in user":  func(c *JumpConfig) { c.User = "jump;id" },
		"space in path":  func(c *JumpConfig) { c.KnownHosts = dir + "/a b" },
		"option as user": func(c *JumpConfig) { c.User = "-oProxyCommand=x" },
		"loose key":      func(c *JumpConfig) { c.KeyFile = loose },
		"missing user":   func(c *JumpConfig) { c.User = "" },
	} {
		c := good
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
