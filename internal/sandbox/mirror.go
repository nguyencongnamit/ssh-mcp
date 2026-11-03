package sandbox

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nguyencongnamit/ssh-mcp/internal/ca"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/transport"
)

// SFTPUser is the read-only SFTP account on targets. Its sshd ForceCommand
// is "ssh-mcp-helper --sftp", which hides every path the policy denies, so
// the mirror never contains denied files in the first place.
const SFTPUser = "agent-sftp"

var (
	regionRe  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	profileRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// Mirrors keeps one read-only sshfs mount per allowed prefix per host, under
// Root/<host-id>/<prefix>.
//
// Mount certificates are short-lived and rewritten on a timer so sshfs's
// reconnect finds a valid one. A mirror idle for IdleTimeout is unmounted and
// its refresh stops; Allowed (the global kill switch) is checked on every
// refresh, and a false answer unmounts everything. Every certificate issued
// is reported through OnIssue so it lands in the audit log.
type Mirrors struct {
	Root         string   // e.g. /var/lib/ssh-mcp/mirrors
	StateDir     string   // key/cert files, 0700
	Prefixes     []string // remote directories to mirror, e.g. /var/log/
	KnownHosts   string   // known_hosts file keyed by host ID
	CA           *ca.CA
	DirectSource string // certificate source-address for direct hosts
	IdleTimeout  time.Duration
	SSHFSBin     string // default "sshfs"
	AWSBin       string // default "aws"
	Log          *slog.Logger
	// Allowed returns false when the global kill switch is set.
	Allowed func(context.Context) bool
	// OnIssue records each mirror certificate (host ID, cert serial).
	OnIssue func(ctx context.Context, hostID string, serial uint64)

	mu    sync.Mutex
	hosts map[string]*mirrorState
	stop  chan struct{}
	once  sync.Once
}

type mirrorState struct {
	mu       sync.Mutex // held while mounting this host only
	host     inventory.Host
	mounted  bool
	lastUsed time.Time
	certAt   time.Time
}

func (m *Mirrors) state(h inventory.Host) *mirrorState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hosts == nil {
		m.hosts = map[string]*mirrorState{}
	}
	st, ok := m.hosts[h.ID]
	if !ok {
		st = &mirrorState{host: h}
		m.hosts[h.ID] = st
	}
	return st
}

// Ensure mounts the host's mirror if needed and returns its root. Only this
// host's lock is held while mounting, so one unreachable host does not stall
// sandbox calls for other hosts.
func (m *Mirrors) Ensure(ctx context.Context, h inventory.Host) (string, error) {
	if !safeName(h.ID) {
		return "", fmt.Errorf("bad host id %q", h.ID)
	}
	if err := validateAWS(h); err != nil {
		return "", err
	}
	m.once.Do(func() { m.stop = make(chan struct{}); go m.refreshLoop() })
	st := m.state(h)
	st.mu.Lock()
	defer st.mu.Unlock()
	root := filepath.Join(m.Root, h.ID)
	if st.mounted && m.allMounted(h.ID) {
		st.lastUsed = time.Now()
		return root, nil
	}
	if err := m.writeCert(ctx, h); err != nil {
		return "", err
	}
	st.certAt = time.Now()
	for _, p := range m.Prefixes {
		mnt := m.mountpoint(h.ID, p)
		if isMountpoint(mnt) {
			continue
		}
		if err := os.MkdirAll(mnt, 0o755); err != nil {
			return "", err
		}
		argv, err := m.sshfsArgs(h, p, mnt)
		if err != nil {
			return "", err
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := exec.CommandContext(cctx, argv[0], argv[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			return "", fmt.Errorf("mount %s:%s: %v: %s", h.ID, p, err, strings.TrimSpace(string(out)))
		}
	}
	st.mounted, st.lastUsed, st.host = true, time.Now(), h
	return root, nil
}

func validateAWS(h inventory.Host) error {
	if h.Region != "" && !regionRe.MatchString(h.Region) {
		return fmt.Errorf("invalid region %q", h.Region)
	}
	if h.Profile != "" && !profileRe.MatchString(h.Profile) {
		return fmt.Errorf("invalid profile %q", h.Profile)
	}
	return nil
}

func (m *Mirrors) mountpoint(id, prefix string) string {
	return filepath.Join(m.Root, id, filepath.FromSlash(strings.Trim(prefix, "/")))
}

func (m *Mirrors) allMounted(id string) bool {
	for _, p := range m.Prefixes {
		if !isMountpoint(m.mountpoint(id, p)) {
			return false
		}
	}
	return true
}

func (m *Mirrors) keyPaths(id string) (key, cert string) {
	return filepath.Join(m.StateDir, id+".key"), filepath.Join(m.StateDir, id+".key-cert.pub")
}

// writeCert issues a fresh SFTP certificate and atomically replaces the key
// and certificate files sshfs's ssh client reads on (re)connect.
func (m *Mirrors) writeCert(ctx context.Context, h inventory.Host) error {
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		return err
	}
	eph, err := m.CA.IssueSFTP("ssh-mcp mirror "+h.ID, transport.SourceAddress(h, m.DirectSource))
	if err != nil {
		return err
	}
	if m.OnIssue != nil {
		m.OnIssue(ctx, h.ID, eph.Cert.Serial)
	}
	block, err := ssh.MarshalPrivateKey(eph.Key, "ssh-mcp mirror "+h.ID)
	if err != nil {
		return err
	}
	keyPath, certPath := m.keyPaths(h.ID)
	if err := atomicWrite(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	return atomicWrite(certPath, ssh.MarshalAuthorizedKey(eph.Cert), 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// refreshLoop ticks every minute so the kill switch and idle timeout act
// quickly; certificates are only renewed once a third of their life is gone.
func (m *Mirrors) refreshLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.refresh(context.Background())
		}
	}
}

// refresh renews certificates for active mirrors, and unmounts idle ones, or
// all of them when the kill switch is on.
func (m *Mirrors) refresh(ctx context.Context) {
	allowed := m.Allowed == nil || m.Allowed(ctx)
	idle := m.IdleTimeout
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	m.mu.Lock()
	states := make([]*mirrorState, 0, len(m.hosts))
	for _, st := range m.hosts {
		states = append(states, st)
	}
	m.mu.Unlock()
	for _, st := range states {
		if !st.mu.TryLock() {
			continue // mounting right now
		}
		if st.mounted {
			if !allowed || time.Since(st.lastUsed) > idle {
				m.unmountHost(st.host.ID)
				st.mounted = false
				m.removeKeys(st.host.ID)
			} else if time.Since(st.certAt) > m.renewAfter() {
				if err := m.writeCert(ctx, st.host); err != nil {
					if m.Log != nil {
						m.Log.Error("refresh mirror certificate", "host", st.host.ID, "err", err)
					}
				} else {
					st.certAt = time.Now()
				}
			}
		}
		st.mu.Unlock()
	}
}

func (m *Mirrors) renewAfter() time.Duration {
	if m.CA.SFTPTTL > 0 {
		return m.CA.SFTPTTL / 3
	}
	return 5 * time.Minute
}

func (m *Mirrors) removeKeys(id string) {
	k, c := m.keyPaths(id)
	os.Remove(k)
	os.Remove(c)
}

// sshfsArgs builds the mount command.
func (m *Mirrors) sshfsArgs(h inventory.Host, remote, mnt string) ([]string, error) {
	keyPath, certPath := m.keyPaths(h.ID)
	bin := m.SSHFSBin
	if bin == "" {
		bin = "sshfs"
	}
	target := SFTPUser + "@" + h.ID + ":" + remote
	opts := []string{
		"ro",
		"reconnect",
		"ServerAliveInterval=15",
		"ServerAliveCountMax=3",
		"IdentityFile=" + keyPath,
		"CertificateFile=" + certPath,
		"IdentitiesOnly=yes",
		"BatchMode=yes",
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=" + m.KnownHosts,
		"GlobalKnownHostsFile=/dev/null",
		"HostKeyAlias=" + h.ID,
		"ControlMaster=no",
	}
	switch h.Transport {
	case "direct":
		host, port, err := net.SplitHostPort(h.Address)
		if err != nil {
			return nil, err
		}
		opts = append(opts, "Hostname="+host, "Port="+port)
	case "ssm", "":
		if err := validateAWS(h); err != nil {
			return nil, err
		}
		aws := m.AWSBin
		if aws == "" {
			aws = "aws"
		}
		pc := aws + " ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"
		if h.Region != "" {
			pc += " --region " + h.Region
		}
		if h.Profile != "" {
			pc += " --profile " + h.Profile
		}
		opts = append(opts, "ProxyCommand="+pc)
	default:
		return nil, fmt.Errorf("unknown transport %q", h.Transport)
	}
	for _, o := range opts {
		if strings.ContainsAny(o, ",\n\r\t") {
			return nil, fmt.Errorf("sshfs option contains a forbidden character: %q", o)
		}
	}
	return []string{bin, target, mnt, "-o", strings.Join(opts, ",")}, nil
}

// Reset unmounts every mirror and discards its certificate. The next
// sandbox call remounts with a freshly issued certificate, so a changed path
// policy applies to mirrors at once instead of at the next renewal.
func (m *Mirrors) Reset() {
	m.mu.Lock()
	states := make([]*mirrorState, 0, len(m.hosts))
	for _, st := range m.hosts {
		states = append(states, st)
	}
	m.mu.Unlock()
	for _, st := range states {
		// Waits for a mount in progress on this host, so it cannot survive
		// the reset with the old certificate.
		st.mu.Lock()
		m.unmountHost(st.host.ID)
		m.removeKeys(st.host.ID)
		st.mounted = false
		st.mu.Unlock()
	}
}

// Close unmounts everything.
func (m *Mirrors) Close() {
	m.mu.Lock()
	if m.stop != nil {
		close(m.stop)
		m.stop = nil
	}
	ids := make([]string, 0, len(m.hosts))
	for id := range m.hosts {
		ids = append(ids, id)
	}
	m.hosts = nil
	m.mu.Unlock()
	for _, id := range ids {
		m.unmountHost(id)
		m.removeKeys(id)
	}
}

func (m *Mirrors) unmountHost(id string) {
	for _, p := range m.Prefixes {
		unmount(m.mountpoint(id, p))
	}
}

func unmount(mnt string) {
	for _, b := range []string{"fusermount3", "fusermount"} {
		if err := exec.Command(b, "-u", "-z", mnt).Run(); err == nil {
			return
		}
	}
}

// isMountpoint checks /proc/self/mounts (Linux).
func isMountpoint(p string) bool {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && unescapeMount(fields[1]) == p {
			return true
		}
	}
	return false
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// ErrPrefixOutsidePolicy is returned by CheckPrefixes.
var ErrPrefixOutsidePolicy = errors.New("sandbox prefix is not inside the policy's allowed paths")

// CheckPrefixes requires every mirrored prefix to sit inside an allowed path,
// so the sandbox can never mirror more than the file tools may read.
func CheckPrefixes(prefixes, allow []string) error {
	for _, p := range prefixes {
		pp := "/" + strings.Trim(p, "/") + "/"
		ok := false
		for _, a := range allow {
			aa := "/" + strings.Trim(a, "/") + "/"
			if aa == "//" || strings.HasPrefix(pp, aa) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrPrefixOutsidePolicy, p)
		}
	}
	return nil
}
