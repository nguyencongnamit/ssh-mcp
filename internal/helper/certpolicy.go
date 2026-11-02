package helper

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
)

// PathsExtension is the certificate extension carrying the server's
// effective path policy as JSON. OpenSSH ignores unknown extensions, so sshd
// accepts it; the helper reads it back from SSH_USER_AUTH (ExposeAuthInfo).
const PathsExtension = "ssh-mcp-paths@ssh-mcp"

// CertPolicy extracts the path policy from the certificate this session
// authenticated with. authInfo is the content of the file named by
// SSH_USER_AUTH; caKeys is the content of TrustedUserCAKeys. The certificate
// signature is re-verified against caKeys, so a forged or substituted file
// cannot widen access.
func CertPolicy(authInfo, caKeys []byte) (*pathpolicy.Policy, error) {
	var cert *ssh.Certificate
	sc := bufio.NewScanner(bytes.NewReader(authInfo))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] != "publickey" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[2])
		if err != nil {
			continue
		}
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		if c, ok := pk.(*ssh.Certificate); ok {
			cert = c
		}
	}
	if cert == nil {
		return nil, errors.New("no certificate in SSH_USER_AUTH")
	}
	trusted := map[string]bool{}
	rest := caKeys
	for len(rest) > 0 {
		pk, _, _, r, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		trusted[string(pk.Marshal())] = true
		rest = r
	}
	if len(trusted) == 0 {
		return nil, errors.New("no trusted CA keys")
	}
	checker := ssh.CertChecker{
		IsUserAuthority:          func(k ssh.PublicKey) bool { return trusted[string(k.Marshal())] },
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if len(cert.ValidPrincipals) == 0 {
		return nil, errors.New("certificate has no principals")
	}
	// CheckCert verifies signature and validity but NOT who signed it; the
	// authority check must be explicit.
	if cert.SignatureKey == nil || !trusted[string(cert.SignatureKey.Marshal())] {
		return nil, errors.New("certificate not signed by a trusted CA")
	}
	if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	js, ok := cert.Permissions.Extensions[PathsExtension]
	if !ok {
		return nil, errors.New("certificate carries no path policy")
	}
	var p pathpolicy.Policy
	dec := json.NewDecoder(strings.NewReader(js))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("certificate path policy: %w", err)
	}
	if len(p.Allow) == 0 {
		return nil, errors.New("certificate path policy allows nothing")
	}
	return &p, nil
}

// LoadCertPolicy reads SSH_USER_AUTH and the CA file. It fails closed: a
// target without ExposeAuthInfo refuses every request.
func LoadCertPolicy(caFile string) (*pathpolicy.Policy, error) {
	path := os.Getenv("SSH_USER_AUTH")
	if path == "" {
		return nil, errors.New("SSH_USER_AUTH not set (enable ExposeAuthInfo for this user)")
	}
	auth, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	return CertPolicy(auth, ca)
}
