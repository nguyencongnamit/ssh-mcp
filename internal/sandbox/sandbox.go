// Package sandbox runs free-form read-only shell commands (grep, awk, find,
// jq, wc) over a read-only sshfs mirror of a target's files.
//
// Each call runs in a fresh bubblewrap sandbox on the ssh-mcp server:
// every namespace unshared (no network at all), all capabilities dropped,
// the mirror bind-mounted read-only, a small tmpfs for /tmp, a cleared
// environment, and none of the server's /etc, /home or state directories.
// The command never reaches the target: the worst it can do is read what the
// mirror already exposes, which is agent-sftp's read-only view.
//
// bubblewrap is used instead of Docker on purpose: the Docker socket is
// root-equivalent, and a FUSE mount inside the server is not visible to
// containers started by the Docker daemon.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MaxScriptBytes caps the command text.
const MaxScriptBytes = 4096

// Runner executes sandboxed commands.
type Runner struct {
	BwrapBin   string // default "bwrap"
	PrlimitBin string // default "prlimit"; empty string disables rlimits
	Timeout    time.Duration
	MaxOutput  int
	// TmpBytes sizes the sandbox's /tmp tmpfs when bwrap supports --size
	// (0.7+). Older bwrap gets an unsized tmpfs; its pages are still charged
	// to the sandbox cgroup's memory.max.
	TmpBytes int64
	// SizeFlag records whether bwrap accepts --size (see DetectFeatures).
	SizeFlag bool
	// Cgroups, when set, puts every sandbox in its own cgroup with pids and
	// memory limits (needs a delegated cgroup v2 subtree, see cgroup_linux.go).
	Cgroups *Cgroups

	slots chan struct{}
}

// NewRunner returns a Runner with defaults. Path policy is not applied here:
// the mirror is served by the target's policy-enforcing SFTP helper, so
// denied files never reach the server.
func NewRunner(maxConcurrent int) *Runner {
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &Runner{
		BwrapBin:   "bwrap",
		PrlimitBin: "prlimit",
		Timeout:    30 * time.Second,
		MaxOutput:  256 * 1024,
		TmpBytes:   64 << 20,
		SizeFlag:   true,
		slots:      make(chan struct{}, maxConcurrent),
	}
}

// Args builds the full argv (exported for tests and dry runs). mirror is the
// host's mirror root on the server; hostDir is the name it gets inside the
// sandbox, under /targets.
func (r *Runner) Args(mirror, hostDir, script string) ([]string, error) {
	if len(script) == 0 || len(script) > MaxScriptBytes {
		return nil, fmt.Errorf("command must be 1-%d bytes", MaxScriptBytes)
	}
	if strings.IndexByte(script, 0) >= 0 {
		return nil, errors.New("command contains NUL")
	}
	if !safeName(hostDir) {
		return nil, fmt.Errorf("bad host dir %q", hostDir)
	}
	inside := "/targets/" + hostDir
	var argv []string
	if r.PrlimitBin != "" {
		argv = append(argv, r.PrlimitBin,
			"--as=1073741824",  // 1 GiB address space
			"--fsize=67108864", // 64 MiB per file (tmpfs only is writable)
			"--cpu=30",
			"--nofile=256",
			"--core=0",
			"--")
	}
	argv = append(argv, r.BwrapBin,
		"--unshare-all", // user, ipc, pid, net, uts, cgroup
		"--die-with-parent",
		"--new-session",
		"--cap-drop", "ALL",
		"--clearenv",
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "HOME", "/tmp",
		"--uid", "65534", "--gid", "65534",
		"--hostname", "sandbox",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--proc", "/proc",
		"--dev", "/dev",
	)
	if r.SizeFlag {
		argv = append(argv, "--size", strconv.FormatInt(r.tmpBytes(), 10))
	}
	argv = append(argv, "--tmpfs", "/tmp",
		"--ro-bind", mirror, inside,
	)
	argv = append(argv,
		"--remount-ro", "/",
		"--chdir", inside,
		"--", "/bin/sh", "-c", script)
	return argv, nil
}

func safeName(s string) bool {
	if s == "" || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// DetectFeatures probes the installed bwrap. It returns an error if bwrap is
// missing, so a misconfigured server fails at startup, not on first use.
func (r *Runner) DetectFeatures() error {
	out, err := exec.Command(r.BwrapBin, "--help").CombinedOutput()
	if err != nil && len(out) == 0 {
		return fmt.Errorf("bwrap not usable: %w", err)
	}
	r.SizeFlag = strings.Contains(string(out), "--size")
	return nil
}

func (r *Runner) tmpBytes() int64 {
	if r.TmpBytes > 0 {
		return r.TmpBytes
	}
	return 64 << 20
}

// Result of a sandbox run.
type Result struct {
	Output    string
	ExitCode  int
	TimedOut  bool
	Truncated bool
}

// Run executes script over mirror.
func (r *Runner) Run(ctx context.Context, mirror, hostDir, script string) (*Result, error) {
	argv, err := r.Args(mirror, hostDir, script)
	if err != nil {
		return nil, err
	}
	if r.slots != nil {
		select {
		case r.slots <- struct{}{}:
			defer func() { <-r.slots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return nil, errors.New("sandbox busy: too many concurrent commands, retry shortly")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	if r.Cgroups != nil {
		cg, err := r.Cgroups.New()
		if err != nil {
			return nil, fmt.Errorf("sandbox cgroup: %w", err)
		}
		defer cg.Close()
		cg.Attach(cmd)
	}
	out := &capBuffer{max: r.MaxOutput}
	cmd.Stdout = out
	cmd.Stderr = out
	runErr := cmd.Run()
	res := &Result{Output: out.String(), Truncated: out.truncated}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, runErr
}

type capBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
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
