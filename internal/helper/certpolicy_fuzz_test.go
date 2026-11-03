package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
)

// FuzzCertPolicy mutates the SSH_USER_AUTH content around one genuinely
// signed certificate. The certificate signature covers the path policy, so
// any input the helper accepts must yield exactly the signed policy: no
// mutation may widen it, and nothing may panic.
func FuzzCertPolicy(f *testing.F) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		f.Fatal(err)
	}
	caSSH, _ := ssh.NewPublicKey(caPub)
	caLine := ssh.MarshalAuthorizedKey(caSSH)

	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userSSH, _ := ssh.NewPublicKey(userPub)
	const signed = `{"allow":["/var/log/"],"deny":["**/*.key"]}`
	cert := &ssh.Certificate{
		Key: userSSH, CertType: ssh.UserCert, ValidPrincipals: []string{"ssh-mcp-live"},
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(24 * time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{PathsExtension: signed}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		f.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(cert.Marshal())
	want := pathpolicy.Policy{Allow: []string{"/var/log/"}, Deny: []string{"**/*.key"}}

	f.Add([]byte("publickey ssh-ed25519-cert-v01@openssh.com " + b64 + "\n"))
	f.Add([]byte("password\npublickey ssh-ed25519-cert-v01@openssh.com " + b64 + " extra\n"))
	f.Add([]byte("publickey ssh-ed25519 " + base64.StdEncoding.EncodeToString(userSSH.Marshal()) + "\n"))
	f.Add([]byte("publickey x !!!\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, authInfo []byte) {
		p, err := CertPolicy(authInfo, caLine)
		if err != nil {
			return
		}
		if !reflect.DeepEqual(*p, want) {
			t.Fatalf("accepted policy %+v differs from the signed one", *p)
		}
	})
}
