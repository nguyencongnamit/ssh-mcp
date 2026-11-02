// Package helper implements ssh-mcp-helper, the only program an ssh-mcp
// certificate can run on a target host (it is pinned as force-command).
//
// Guarantees, independent of anything the server does:
//   - It never invokes a shell. Every tool maps to a fixed binary path and a
//     fixed argv built from validated, typed arguments.
//   - Binaries are resolved only from trusted system directories and must be
//     root-owned and not group/world-writable.
//   - The child environment is fixed (no client env), pagers are disabled,
//     stdin is /dev/null, and each child runs in its own process group with
//     a hard timeout.
//   - File tools open files themselves (no cat/less), refuse symlinks in the
//     final component, re-check the path policy against the path the kernel
//     actually opened, and read regular files only.
//
// It runs as the unprivileged agent-ro user, so Linux permissions remain the
// last line of defence even if every check here were wrong.
package helper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

// ErrDenied is returned when the path policy refuses a path.
var ErrDenied = errors.New("denied by path policy")

// TrustedBinDirs are the only directories binaries are resolved from.
var TrustedBinDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// Helper executes one validated request.
type Helper struct {
	// Policy is the host-local floor (built-in or helper-policy.json).
	Policy pathpolicy.Policy
	// CertPaths is the server's effective path policy, carried in the
	// CA-signed certificate. A path must pass both; the server can narrow
	// what the host allows but never widen it.
	CertPaths *pathpolicy.Policy
	BinDirs   []string
	// CheckBinOwner enforces root ownership and no group/world write on
	// resolved binaries. Always true in production; tests on dev machines
	// may turn it off.
	CheckBinOwner bool
	Timeout       time.Duration
	Now           func() time.Time
	// procFD enables the /proc/self/fd re-check (Linux).
	ProcFD bool
}

// New returns a Helper with production settings.
func New(pol pathpolicy.Policy) *Helper {
	_, err := os.Stat("/proc/self/fd")
	return &Helper{
		Policy:        pol,
		BinDirs:       TrustedBinDirs,
		CheckBinOwner: true,
		Timeout:       20 * time.Second,
		Now:           time.Now,
		ProcFD:        err == nil,
	}
}

// allowed applies the host floor and, when present, the certificate policy.
func (h *Helper) allowed(p string, isDir bool) bool {
	if !h.Policy.Allowed(p, isDir) {
		return false
	}
	return h.CertPaths == nil || h.CertPaths.Allowed(p, isDir)
}

// Run parses line, validates it, and writes the tool's output to out
// (capped at protocol.MaxFileBytes). A returned error wrapping
// protocol.ErrInvalid or ErrDenied means the request was refused.
func (h *Helper) Run(ctx context.Context, line string, out io.Writer) error {
	req, err := protocol.ParseRequest([]byte(strings.TrimSpace(line)))
	if err != nil {
		return err
	}
	args, err := protocol.Normalize(req.Tool, req.Args)
	if err != nil {
		return err
	}
	w := newCapWriter(out, protocol.MaxFileBytes)
	defer w.finish()

	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	switch req.Tool {
	case protocol.ToolHostOverview:
		return h.hostOverview(ctx, w)
	case protocol.ToolPS:
		return h.ps(ctx, w, args.(*protocol.PSArgs))
	case protocol.ToolListeningPorts:
		return h.exec(ctx, w, "ss", "-tulnp")
	case protocol.ToolJournal:
		return h.journal(ctx, w, args.(*protocol.JournalArgs))
	case protocol.ToolSystemctlStatus:
		a := args.(*protocol.UnitArgs)
		return h.exec(ctx, w, "systemctl", "status", "--no-pager", "--full",
			"--lines="+strconv.Itoa(a.Lines), "--", a.Unit)
	case protocol.ToolFailedUnits:
		return h.exec(ctx, w, "systemctl", "list-units", "--failed", "--no-pager", "--plain", "--no-legend")
	case protocol.ToolReadFile:
		return h.readFile(w, args.(*protocol.FileArgs))
	case protocol.ToolTailFile:
		return h.tailFile(w, args.(*protocol.TailArgs))
	case protocol.ToolListDir:
		return h.listDir(w, args.(*protocol.DirArgs))
	}
	return fmt.Errorf("%w: unhandled tool", protocol.ErrInvalid)
}

// ---------------------------------------------------------------- exec tools

func (h *Helper) resolveBin(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("binary name must be bare: %q", name)
	}
	for _, d := range h.BinDirs {
		p := filepath.Join(d, name)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if h.CheckBinOwner {
			if fi.Mode().Perm()&0o022 != 0 {
				return "", fmt.Errorf("%s is group/world-writable; refusing", p)
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
				return "", fmt.Errorf("%s is not root-owned; refusing", p)
			}
		}
		return p, nil
	}
	return "", fmt.Errorf("%s not found in trusted directories", name)
}

// childEnv is the complete environment for every child. Nothing from the
// SSH client is inherited.
var childEnv = []string{
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"LANG=C.UTF-8",
	"LC_ALL=C.UTF-8",
	"TERM=dumb",
	"PAGER=cat",
	"SYSTEMD_PAGER=cat",
	"SYSTEMD_PAGERSECURE=1",
	"SYSTEMD_COLORS=0",
	"SYSTEMD_LESS=",
}

func (h *Helper) command(ctx context.Context, name string, argv ...string) (*exec.Cmd, error) {
	bin, err := h.resolveBin(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdin = nil // /dev/null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

// exec runs a fixed command and streams combined output to w. A non-zero
// child exit is reported in the output, not as a refusal: "systemctl status"
// exits 3 for an inactive unit, which is a valid answer.
func (h *Helper) exec(ctx context.Context, w io.Writer, name string, argv ...string) error {
	cmd, err := h.command(ctx, name, argv...)
	if err != nil {
		return err
	}
	cmd.Stdout = w
	cmd.Stderr = w
	runErr := cmd.Run()
	return reportExit(ctx, w, runErr)
}

func reportExit(ctx context.Context, w io.Writer, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		fmt.Fprintf(w, "\n[timed out]\n")
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		fmt.Fprintf(w, "\n[exit status %d]\n", ee.ExitCode())
		return nil
	}
	return err
}

func (h *Helper) hostOverview(ctx context.Context, w io.Writer) error {
	sections := []struct {
		title string
		name  string
		argv  []string
	}{
		{"uname", "uname", []string{"-a"}},
		{"uptime", "uptime", nil},
		{"memory", "free", []string{"-m"}},
		{"disk", "df", []string{"-hP"}},
		{"cpus", "nproc", nil},
	}
	for _, s := range sections {
		fmt.Fprintf(w, "== %s ==\n", s.title)
		if err := h.exec(ctx, w, s.name, s.argv...); err != nil {
			fmt.Fprintf(w, "(unavailable: %v)\n", err)
		}
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		fmt.Fprintf(w, "== os-release ==\n%s", b)
	}
	return nil
}

func (h *Helper) ps(ctx context.Context, w io.Writer, a *protocol.PSArgs) error {
	cmd, err := h.command(ctx, "ps", "-eo", "pid,user,pcpu,pmem,etime,args", "--sort=-pcpu")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	cmd.Stdout = newCapWriter(&buf, protocol.MaxFileBytes)
	cmd.Stderr = cmd.Stdout
	runErr := cmd.Run()
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 0; sc.Scan() && n <= a.Limit; n++ { // header + Limit rows
		fmt.Fprintln(w, sc.Text())
	}
	return reportExit(ctx, w, runErr)
}

func (h *Helper) journal(ctx context.Context, w io.Writer, a *protocol.JournalArgs) error {
	since := h.Now().Add(-time.Duration(a.SinceSeconds) * time.Second).Unix()
	argv := []string{
		"--no-pager", "--quiet", "--output=short-iso",
		"--lines=" + strconv.Itoa(a.Lines),
		"--since=@" + strconv.FormatInt(since, 10),
	}
	if a.Unit != "" {
		argv = append(argv, "--unit="+a.Unit)
	}
	if a.Priority != nil {
		argv = append(argv, "--priority="+strconv.Itoa(*a.Priority))
	}
	return h.exec(ctx, w, "journalctl", argv...)
}

// ---------------------------------------------------------------- file tools

// secureOpen opens p for reading after policy, symlink and type checks.
func (h *Helper) secureOpen(p string, wantDir bool) (*os.File, string, error) {
	c := pathpolicy.Clean(p)
	if !h.allowed(c, wantDir) {
		return nil, "", ErrDenied
	}
	resolved, err := filepath.EvalSymlinks(c)
	if err != nil {
		return nil, "", notFound(err)
	}
	if !h.allowed(resolved, wantDir) {
		return nil, "", ErrDenied
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if wantDir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := os.OpenFile(resolved, flags, 0)
	if err != nil {
		return nil, "", notFound(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, "", err
	}
	if wantDir != fi.IsDir() || (!wantDir && !fi.Mode().IsRegular()) {
		f.Close()
		if wantDir {
			return nil, "", errors.New("not a directory")
		}
		return nil, "", errors.New("not a regular file")
	}
	// The path may have been swapped between EvalSymlinks and open. Ask the
	// kernel what we actually opened and check that path too.
	if h.ProcFD {
		real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
		if err != nil || !h.allowed(real, wantDir) {
			f.Close()
			return nil, "", ErrDenied
		}
		resolved = real
	} else if lfi, err := os.Lstat(resolved); err != nil || !os.SameFile(fi, lfi) {
		f.Close()
		return nil, "", ErrDenied
	}
	return f, resolved, nil
}

func notFound(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return errors.New("permission denied (agent-ro cannot read this)")
	}
	return errors.New("not found or not readable")
}

func (h *Helper) readFile(w io.Writer, a *protocol.FileArgs) error {
	f, _, err := h.secureOpen(a.Path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	if a.Offset > 0 {
		if _, err := f.Seek(a.Offset, io.SeekStart); err != nil {
			return err
		}
	}
	_, err = io.Copy(w, io.LimitReader(f, a.Length))
	return err
}

func (h *Helper) tailFile(w io.Writer, a *protocol.TailArgs) error {
	f, _, err := h.secureOpen(a.Path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	start := fi.Size() - protocol.MaxFileBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, protocol.MaxFileBytes))
	if err != nil {
		return err
	}
	if start > 0 { // drop the partial first line
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if len(lines) > a.Lines {
		lines = lines[len(lines)-a.Lines:]
	}
	for _, l := range lines {
		if _, err := w.Write(l); err != nil {
			return err
		}
	}
	return nil
}

func (h *Helper) listDir(w io.Writer, a *protocol.DirArgs) error {
	f, real, err := h.secureOpen(a.Path, true)
	if err != nil {
		return err
	}
	defer f.Close()
	ents, err := f.ReadDir(protocol.MaxDirEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	truncated := len(ents) > protocol.MaxDirEntries
	if truncated {
		ents = ents[:protocol.MaxDirEntries]
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	fmt.Fprintf(w, "%s\n", real)
	for _, e := range ents {
		child := filepath.Join(real, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		mark := ""
		if !h.allowed(child, e.IsDir()) {
			mark = "  [denied]"
		}
		fmt.Fprintf(w, "%s %10d %s %s%s\n", info.Mode().String(), info.Size(),
			info.ModTime().UTC().Format(time.RFC3339), e.Name(), mark)
	}
	if truncated {
		fmt.Fprintf(w, "[truncated at %d entries]\n", protocol.MaxDirEntries)
	}
	return nil
}

// ---------------------------------------------------------------- capWriter

// capWriter passes through at most limit bytes and then swallows the rest,
// noting the truncation once at the end.
type capWriter struct {
	w         io.Writer
	remaining int
	truncated bool
}

func newCapWriter(w io.Writer, limit int) *capWriter { return &capWriter{w: w, remaining: limit} }

func (c *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	if c.remaining <= 0 {
		c.truncated = true
		return n, nil
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
		c.truncated = true
	}
	m, err := c.w.Write(p)
	c.remaining -= m
	if err != nil {
		return m, err
	}
	return n, nil
}

func (c *capWriter) finish() {
	if c.truncated {
		fmt.Fprintf(c.w, "\n[output truncated at %d bytes]\n", protocol.MaxFileBytes)
	}
}
