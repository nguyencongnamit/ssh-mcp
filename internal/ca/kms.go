package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// KMSConfig selects an AWS KMS key as the CA. The private key never leaves
// KMS; every certificate signature is a kms:Sign call.
type KMSConfig struct {
	// KeyID is a key ARN, alias ARN, key ID or alias/<name>. The key must be
	// KeySpec ECC_NIST_P256 with KeyUsage SIGN_VERIFY.
	KeyID   string `yaml:"key_id"`
	Region  string `yaml:"region"`
	Profile string `yaml:"profile"`
}

var (
	kmsKeyRe     = regexp.MustCompile(`^[A-Za-z0-9:/_.+=@-]{1,1000}$`)
	kmsRegionRe  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	kmsProfileRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// kmsSigner is a crypto.Signer backed by KMS through the AWS CLI, which the
// SSM transport already requires. Arguments are fixed; only the key, region
// and profile come from config, and they are validated.
type kmsSigner struct {
	cfg     KMSConfig
	pub     *ecdsa.PublicKey
	timeout time.Duration
	// run executes the AWS CLI; replaced in tests.
	run func(ctx context.Context, args ...string) ([]byte, error)
}

func awsCLI(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "aws", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("aws %s: %v: %s", args[0]+" "+args[1], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// NewKMS returns a CA whose key lives in AWS KMS.
func NewKMS(ctx context.Context, cfg KMSConfig) (*CA, error) {
	s, err := newKMSSigner(ctx, cfg, awsCLI)
	if err != nil {
		return nil, err
	}
	return NewFromSigner(s)
}

func newKMSSigner(ctx context.Context, cfg KMSConfig, run func(context.Context, ...string) ([]byte, error)) (*kmsSigner, error) {
	if !kmsKeyRe.MatchString(cfg.KeyID) || strings.HasPrefix(cfg.KeyID, "-") {
		return nil, fmt.Errorf("ca_kms.key_id %q is not a KMS key reference", cfg.KeyID)
	}
	if cfg.Region != "" && !kmsRegionRe.MatchString(cfg.Region) {
		return nil, fmt.Errorf("ca_kms.region %q is invalid", cfg.Region)
	}
	if cfg.Profile != "" && !kmsProfileRe.MatchString(cfg.Profile) {
		return nil, fmt.Errorf("ca_kms.profile %q is invalid", cfg.Profile)
	}
	k := &kmsSigner{cfg: cfg, timeout: 10 * time.Second, run: run}
	cctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()
	out, err := k.run(cctx, k.args("kms", "get-public-key", "--key-id", cfg.KeyID, "--output", "json")...)
	if err != nil {
		return nil, err
	}
	var resp struct {
		PublicKey string
		KeySpec   string
		KeyUsage  string
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("kms get-public-key: %w", err)
	}
	if resp.KeySpec != "ECC_NIST_P256" || resp.KeyUsage != "SIGN_VERIFY" {
		return nil, fmt.Errorf("KMS key %s is %s/%s; want ECC_NIST_P256/SIGN_VERIFY", cfg.KeyID, resp.KeySpec, resp.KeyUsage)
	}
	der, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms public key: %w", err)
	}
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("kms public key: %w", err)
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("kms public key is not ECDSA P-256")
	}
	k.pub = ec
	return k, nil
}

func (k *kmsSigner) args(a ...string) []string {
	if k.cfg.Region != "" {
		a = append(a, "--region", k.cfg.Region)
	}
	if k.cfg.Profile != "" {
		a = append(a, "--profile", k.cfg.Profile)
	}
	return a
}

// Public implements crypto.Signer.
func (k *kmsSigner) Public() crypto.PublicKey { return k.pub }

// Sign implements crypto.Signer. digest is the SHA-256 of the data, as
// x/crypto/ssh passes for ecdsa-sha2-nistp256. KMS returns ASN.1 DER, which
// is what the ssh package expects from a crypto.Signer.
func (k *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("kms signer: want a 32-byte SHA-256 digest")
	}
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	out, err := k.run(ctx, k.args("kms", "sign", "--key-id", k.cfg.KeyID,
		"--message", base64.StdEncoding.EncodeToString(digest), "--message-type", "DIGEST",
		"--signing-algorithm", "ECDSA_SHA_256", "--query", "Signature", "--output", "text")...)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return sig, nil
}
