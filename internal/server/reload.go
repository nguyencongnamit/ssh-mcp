package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/nguyencongnamit/ssh-mcp/internal/policy"
	"github.com/nguyencongnamit/ssh-mcp/internal/sandbox"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

// PathSetter receives the new path policy (the CA embeds it in certificates).
type PathSetter interface{ SetPaths(js string) }

// Resetter drops state built from the old path policy (sandbox mirrors).
type Resetter interface{ Reset() }

// Reloader re-reads policy.yaml at run time (on SIGHUP). A file that does
// not parse, or that no longer contains the sandbox prefixes, is refused and
// the running policy stays in force. Every attempt is audited.
type Reloader struct {
	Path            string
	Holder          *policy.Holder
	CA              PathSetter
	Mirrors         Resetter // optional
	SandboxPrefixes []string // checked against the new paths.allow when set
	Store           *store.Store
	Log             *slog.Logger
}

// Reload applies the policy file. It returns an error, and changes nothing,
// if the new policy is invalid.
func (r *Reloader) Reload(ctx context.Context) error {
	b, err := os.ReadFile(r.Path)
	if err == nil {
		err = r.apply(ctx, b)
	}
	if err != nil {
		r.audit(ctx, "error", "", err.Error())
		r.Log.Error("policy reload refused; previous policy stays in force", "err", err)
		return err
	}
	return nil
}

func (r *Reloader) apply(ctx context.Context, b []byte) error {
	np, err := policy.Parse(b, KnownTools)
	if err != nil {
		return err
	}
	if len(r.SandboxPrefixes) > 0 {
		if err := sandbox.CheckPrefixes(r.SandboxPrefixes, np.Paths.Allow); err != nil {
			return err
		}
	}
	newPaths, err := json.Marshal(np.Paths)
	if err != nil {
		return err
	}
	oldPaths, _ := json.Marshal(r.Holder.Load().Paths)
	pathsChanged := string(newPaths) != string(oldPaths)
	// Certificates first, then the server-side check: during the switch the
	// narrower of the two always applies, whether paths widen or narrow.
	if pathsChanged {
		r.CA.SetPaths(string(newPaths))
	}
	r.Holder.Swap(np)
	if pathsChanged && r.Mirrors != nil {
		r.Mirrors.Reset()
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	reason := fmt.Sprintf("%d rules; paths changed: %v", len(np.Rules), pathsChanged)
	r.audit(ctx, "allow", digest, reason)
	r.Log.Info("policy reloaded", "sha256", digest, "rules", len(np.Rules), "paths_changed", pathsChanged)
	return nil
}

func (r *Reloader) audit(ctx context.Context, decision, digest, reason string) {
	args, _ := json.Marshal(map[string]string{"file": r.Path, "sha256": digest})
	if _, err := r.Store.Append(ctx, store.Record{
		Identity: "system:admin", Tool: "policy_reload", Args: string(args),
		Decision: decision, Reason: reason,
	}); err != nil {
		r.Log.Error("audit policy reload", "err", err)
	}
}
