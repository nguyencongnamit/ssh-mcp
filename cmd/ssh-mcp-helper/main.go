// Command ssh-mcp-helper is installed on each target host at
// /usr/local/libexec/ssh-mcp-helper and forced by sshd for both agent users:
//
//	agent-ro:   ForceCommand /usr/local/libexec/ssh-mcp-helper
//	            sshd passes the client's command in SSH_ORIGINAL_COMMAND; the
//	            helper treats it as a JSON request, never as shell input.
//	agent-sftp: ForceCommand /usr/local/libexec/ssh-mcp-helper --sftp
//	            a read-only SFTP server that hides every path the policy denies.
//
// In both modes the effective path policy is the host floor (built-in, or
// /etc/ssh-mcp/helper-policy.json) intersected with the policy the server
// put in the CA-signed certificate (read via ExposeAuthInfo). A session
// without that certificate policy is refused.
//
// Exit codes: 0 tool ran (its own exit status, if non-zero, is in the
// output), 2 request refused (invalid or denied by path policy), 1 failure.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nguyencongnamit/ssh-mcp/internal/helper"
	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

const (
	localPolicyFile = "/etc/ssh-mcp/helper-policy.json"
	caFile          = "/etc/ssh/ssh-mcp-ca.pub"
)

var version = "dev"

func main() {
	sftpMode := false
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			fmt.Println(version)
			return
		case "--sftp":
			sftpMode = true
		default:
			fail(2, "unknown argument")
		}
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		fail(1, "refusing to run as root")
	}
	floor, err := loadPolicy()
	if err != nil {
		fail(1, "policy: %v", err)
	}
	certPaths, err := helper.LoadCertPolicy(caFile)
	if err != nil {
		fail(2, "%v", err)
	}
	h := helper.New(floor)
	h.CertPaths = certPaths

	if sftpMode {
		if err := h.ServeSFTP(stdio{}); err != nil {
			fail(1, "sftp: %v", err)
		}
		return
	}

	line, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	if !ok {
		fail(2, "no request (interactive login is not allowed)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := h.Run(ctx, line, os.Stdout); err != nil {
		if errors.Is(err, protocol.ErrInvalid) || errors.Is(err, helper.ErrDenied) {
			fail(2, "%v", err)
		}
		fail(1, "%v", err)
	}
}

func fail(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ssh-mcp-helper: "+format+"\n", a...)
	os.Exit(code)
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return os.Stdout.Close() }

func loadPolicy() (pathpolicy.Policy, error) {
	fi, err := os.Stat(localPolicyFile)
	if errors.Is(err, os.ErrNotExist) {
		return pathpolicy.Default(), nil
	}
	if err != nil {
		return pathpolicy.Policy{}, err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return pathpolicy.Policy{}, fmt.Errorf("%s is group/world-writable", localPolicyFile)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return pathpolicy.Policy{}, fmt.Errorf("%s is not root-owned", localPolicyFile)
	}
	b, err := os.ReadFile(localPolicyFile)
	if err != nil {
		return pathpolicy.Policy{}, err
	}
	var p pathpolicy.Policy
	if err := protocol.DecodeStrict(b, &p); err != nil {
		return pathpolicy.Policy{}, err
	}
	// The built-in deny list always applies, even if the local file omits it.
	p.Deny = append(p.Deny, pathpolicy.Default().Deny...)
	if len(p.Allow) == 0 {
		return pathpolicy.Policy{}, errors.New("allow list is empty")
	}
	return p, nil
}
