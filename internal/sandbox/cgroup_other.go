//go:build !linux

package sandbox

import (
	"errors"
	"os/exec"
)

// Cgroups is Linux-only.
type Cgroups struct {
	PidsMax   int
	MemoryMax int64
}

// Cgroup is Linux-only.
type Cgroup struct{}

// InitCgroups is unsupported off Linux.
func InitCgroups(int, int64) (*Cgroups, error) { return nil, errors.New("cgroups need Linux") }

// New is unsupported off Linux.
func (c *Cgroups) New() (*Cgroup, error) { return nil, errors.New("cgroups need Linux") }

// Attach is a no-op off Linux.
func (g *Cgroup) Attach(*exec.Cmd) {}

// Close is a no-op off Linux.
func (g *Cgroup) Close() {}
