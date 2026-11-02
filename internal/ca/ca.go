// Package ca issues short-lived SSH user certificates.
//
// Live-tools certificates pin force-command to the helper and grant no
// extensions, which in OpenSSH means: no pty, no port/agent/X11 forwarding,
// no user rc. A fresh key pair and certificate is minted per call and never
// written to disk.
package ca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Principals; each target maps them to a local user via
// AuthorizedPrincipalsFile.
const (
	PrincipalLive = "ssh-mcp-live"
	PrincipalSFTP = "ssh-mcp-sftp"
)

// DefaultHelperPath is where bootstrap installs the helper.
const DefaultHelperPath = "/usr/local/libexec/ssh-mcp-helper"

// CA signs certificates.
type CA struct {
	signer ssh.Signer
	// HelperPath is pinned as force-command in live certificates.
	HelperPath string
	// Paths is the server's effective path policy as JSON. It is embedded
	// in every certificate (extension PathsExtension) and enforced by the
	// helper on the target, in both live and SFTP mode.
	Paths   string
	LiveTTL time.Duration
	SFTPTTL time.Duration
	now     func() time.Time
}

// New wraps a signer. Use LoadFile for a key on disk, or pass a KMS-backed
// crypto.Signer through NewFromSigner.
func New(s ssh.Signer) *CA {
	return &CA{signer: s, HelperPath: DefaultHelperPath, LiveTTL: 5 * time.Minute, SFTPTTL: 15 * time.Minute, now: time.Now}
}

// NewFromSigner adapts a crypto.Signer (e.g. AWS KMS ECC_NIST_P256).
func NewFromSigner(cs crypto.Signer) (*CA, error) {
	s, err := ssh.NewSignerFromSigner(cs)
	if err != nil {
		return nil, err
	}
	return New(s), nil
}

// LoadFile loads an OpenSSH private key. The file must not be readable by
// group or others.
func LoadFile(path string) (*CA, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %o are too open (want 0600)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return New(s), nil
}

// GenerateFile writes a new ed25519 CA key (0600) and returns the public key
// line for targets' TrustedUserCAKeys.
func GenerateFile(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "ssh-mcp user CA")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(pemEncode(block)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(s.PublicKey())), nil
}

// PublicKey returns the CA public key in authorized_keys format.
func (c *CA) PublicKey() string { return string(ssh.MarshalAuthorizedKey(c.signer.PublicKey())) }

// Ephemeral is a per-call key pair plus its certificate, held in memory only.
type Ephemeral struct {
	Signer ssh.Signer // certificate signer, ready for ssh.PublicKeys
	Cert   *ssh.Certificate
	Key    ed25519.PrivateKey
}

// PathsExtension must match helper.PathsExtension.
const PathsExtension = "ssh-mcp-paths@ssh-mcp"

// IssueLive mints a key pair and a live-tools certificate. keyID ends up in
// the target's sshd log, so it carries the caller identity and call ID.
// sourceAddr is the CIDR list sshd will see the connection from: the
// server's private IP for direct SSH, loopback for SSM (the SSM agent
// connects to sshd from 127.0.0.1). Empty means unrestricted.
func (c *CA) IssueLive(keyID, sourceAddr string) (*Ephemeral, error) {
	if c.HelperPath == "" {
		return nil, errors.New("helper path not set")
	}
	opts := map[string]string{"force-command": c.HelperPath}
	if sourceAddr != "" {
		opts["source-address"] = sourceAddr
	}
	return c.issue(keyID, PrincipalLive, c.LiveTTL, opts)
}

// IssueSFTP mints a key pair and a read-only-mirror certificate. The target's
// sshd forces "ssh-mcp-helper --sftp" for the mapped user.
func (c *CA) IssueSFTP(keyID, sourceAddr string) (*Ephemeral, error) {
	opts := map[string]string{}
	if sourceAddr != "" {
		opts["source-address"] = sourceAddr
	}
	return c.issue(keyID, PrincipalSFTP, c.SFTPTTL, opts)
}

func (c *CA) issue(keyID, principal string, ttl time.Duration, opts map[string]string) (*Ephemeral, error) {
	if c.Paths == "" {
		return nil, errors.New("CA has no path policy to embed")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var serialBytes [8]byte
	if _, err := rand.Read(serialBytes[:]); err != nil {
		return nil, err
	}
	now := c.now()
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          binary.BigEndian.Uint64(serialBytes[:]),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()), // clock skew
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: opts,
			// No permit-* extensions: no pty, forwarding, agent, X11 or rc.
			Extensions: map[string]string{PathsExtension: c.Paths},
		},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, err
	}
	keySigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{Signer: certSigner, Cert: cert, Key: priv}, nil
}
