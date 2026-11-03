package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeKMS answers the two AWS CLI calls with a local P-256 key and checks
// the arguments the signer sends.
func fakeKMS(t *testing.T, spec string) (func(context.Context, ...string) ([]byte, error), *int) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	signs := 0
	return func(_ context.Context, args ...string) ([]byte, error) {
		if !slices.Contains(args, "--region") || args[0] != "kms" {
			t.Errorf("unexpected args %v", args)
		}
		switch args[1] {
		case "get-public-key":
			return json.Marshal(map[string]string{"PublicKey": base64.StdEncoding.EncodeToString(der), "KeySpec": spec, "KeyUsage": "SIGN_VERIFY"})
		case "sign":
			signs++
			i := slices.Index(args, "--message")
			if i < 0 || !slices.Contains(args, "DIGEST") || !slices.Contains(args, "ECDSA_SHA_256") {
				t.Errorf("sign args %v", args)
			}
			d, err := base64.StdEncoding.DecodeString(args[i+1])
			if err != nil {
				return nil, err
			}
			sig, err := ecdsa.SignASN1(rand.Reader, key, d)
			if err != nil {
				return nil, err
			}
			return []byte(base64.StdEncoding.EncodeToString(sig) + "\n"), nil
		}
		return nil, errors.New("unexpected call")
	}, &signs
}

func TestKMSCertificatesVerify(t *testing.T) {
	run, signs := fakeKMS(t, "ECC_NIST_P256")
	s, err := newKMSSigner(context.Background(), KMSConfig{KeyID: "alias/ssh-mcp-ca", Region: "eu-west-1"}, run)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFromSigner(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.PublicKey(), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("CA public key %q", c.PublicKey())
	}
	c.Paths = `{"allow":["/var/log/"]}`
	eph, err := c.IssueLive("t", "")
	if err != nil {
		t.Fatal(err)
	}
	if *signs != 1 {
		t.Fatalf("%d kms:Sign calls, want 1", *signs)
	}
	caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(c.PublicKey()))
	checker := ssh.CertChecker{
		IsUserAuthority:          func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(caPub.Marshal()) },
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(eph.Cert.ValidPrincipals[0], eph.Cert); err != nil {
		t.Fatalf("KMS-signed certificate does not verify: %v", err)
	}
}

func TestKMSRejects(t *testing.T) {
	run, _ := fakeKMS(t, "ECC_NIST_P256")
	for name, cfg := range map[string]KMSConfig{
		"option as key": {KeyID: "--debug", Region: "eu-west-1"},
		"space in key":  {KeyID: "alias/a b", Region: "eu-west-1"},
		"bad region":    {KeyID: "alias/a", Region: "eu-west-1; id"},
		"bad profile":   {KeyID: "alias/a", Region: "eu-west-1", Profile: "a b"},
	} {
		if _, err := newKMSSigner(context.Background(), cfg, run); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rsa, _ := fakeKMS(t, "RSA_2048")
	if _, err := newKMSSigner(context.Background(), KMSConfig{KeyID: "alias/a", Region: "eu-west-1"}, rsa); err == nil {
		t.Error("RSA key spec accepted")
	}
	s, _ := newKMSSigner(context.Background(), KMSConfig{KeyID: "alias/a", Region: "eu-west-1"}, run)
	d := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(nil, d[:20], nil); err == nil {
		t.Error("non-SHA-256 digest accepted")
	}
}
