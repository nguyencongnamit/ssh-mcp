//go:build linux

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Cgroups places each sandbox in its own cgroup v2 child with pids and
// memory limits, so a fork bomb or a full tmpfs hits the sandbox's ceiling,
// not the ssh-mcp service. It needs a delegated subtree: run under systemd
// with Delegate=yes (deploy/ssh-mcp.service).
type Cgroups struct {
	root      string
	PidsMax   int
	MemoryMax int64
}

// InitCgroups prepares the service's own cgroup for delegation: it moves the
// server into a "server" leaf (cgroup v2 forbids processes in a cgroup that
// hands controllers to children) and enables pids and memory below it.
func InitCgroups(pidsMax int, memoryMax int64) (*Cgroups, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
		}
	}
	if rel == "" {
		return nil, errors.New("not on a cgroup v2 unified hierarchy")
	}
	root := filepath.Join("/sys/fs/cgroup", rel)
	if filepath.Base(root) == "server" { // already initialised (restart within the unit)
		root = filepath.Dir(root)
	}
	leaf := filepath.Join(root, "server")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w (is Delegate=yes set?)", leaf, err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return nil, fmt.Errorf("move server into %s: %w", leaf, err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+pids +memory"), 0); err != nil {
		return nil, fmt.Errorf("enable pids/memory controllers: %w", err)
	}
	return &Cgroups{root: root, PidsMax: pidsMax, MemoryMax: memoryMax}, nil
}

// Cgroup is one sandbox's cgroup.
type Cgroup struct {
	dir string
	fd  *os.File
}

// New creates a limited child cgroup.
func (c *Cgroups) New() (*Cgroup, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	dir := filepath.Join(c.root, "sandbox-"+hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	writes := map[string]string{
		"pids.max":        strconv.Itoa(c.PidsMax),
		"memory.max":      strconv.FormatInt(c.MemoryMax, 10),
		"memory.swap.max": "0",
	}
	for f, v := range writes {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0); err != nil && f != "memory.swap.max" {
			os.Remove(dir)
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	fd, err := os.Open(dir)
	if err != nil {
		os.Remove(dir)
		return nil, err
	}
	return &Cgroup{dir: dir, fd: fd}, nil
}

// Attach makes cmd start inside the cgroup (clone3 CLONE_INTO_CGROUP), so
// there is no window in which the child runs unlimited.
func (g *Cgroup) Attach(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(g.fd.Fd())
}

// Close kills anything left and removes the cgroup.
func (g *Cgroup) Close() {
	_ = os.WriteFile(filepath.Join(g.dir, "cgroup.kill"), []byte("1"), 0)
	g.fd.Close()
	for i := 0; i < 50; i++ {
		if err := os.Remove(g.dir); err == nil || os.IsNotExist(err) {
			return
		}
		syscall.Nanosleep(&syscall.Timespec{Nsec: 20e6}, nil)
	}
}
