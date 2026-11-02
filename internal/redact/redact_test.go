package redact

import (
	"strings"
	"testing"
)

// All values below are fabricated. The AWS pair is AWS's own documentation
// example.
func TestRedactsKnownSecrets(t *testing.T) {
	rd := Default()
	cases := map[string]struct{ in, mustNotContain string }{
		"aws key id":     {"key=AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"},
		"aws secret":     {"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"},
		"private key":    {"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXktdjEAAAAA"},
		"truncated key":  {"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfake", "MIIEowIBAAKCAQEAfake"},
		"jwt":            {"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZXNpZ25hdHVyZWZha2U", "eyJhbGciOiJIUzI1NiJ9"},
		"github":         {"GH=ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000", "ghp_FAKE"},
		"slack":          {"xoxb-0000000000-FAKEfakeFAKE", "xoxb-0000000000"},
		"slack webhook":  {"POST https://hooks.slack.com/services/T000/B000/FAKEFAKE", "hooks.slack.com/services/T000"},
		"bearer header":  {"Authorization: Bearer abcDEF123ghiJKL456mnoPQR", "abcDEF123ghiJKL456mnoPQR"},
		"url creds":      {"DATABASE_URL=postgres://app:Fake-Pass-123@db.internal:5432/app", "Fake-Pass-123"},
		"password=":      {"db.password=hunter2-fake", "hunter2-fake"},
		"quoted secret":  {`client_secret: "s3cr3t value fake"`, "s3cr3t value fake"},
		"json token":     {`{"api_key": "fakeapikey000111"}`, "fakeapikey000111"},
		"env style":      {"export MYSQL_ROOT_PASSWORD=NotARealOne!", "NotARealOne!"},
		"shadow hash":    {"root:$6$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEF0123456789./:19000:0:99999:7:::", "abcdefghijklmnop"},
		"anthropic key":  {"ANTHROPIC=sk-ant-api03-FAKEfakeFAKEfakeFAKEfake", "sk-ant-api03-FAKE"},
		"mysql -p":       {"mysql -uroot -phunter2hunter2 app", "hunter2hunter2"},
		"sshpass":        {"sshpass -p NotReal123 ssh host", "NotReal123"},
		"--password=":    {"psql --password=NotReal123 -h db", "NotReal123"},
		"--token space":  {"cli --token abcNotReal999 run", "abcNotReal999"},
		"env then space": {"DB_PASS hunter2hunter2", "hunter2hunter2"},
		"pgpassword":     {"PGPASSWORD hunter2 psql", "hunter2"},
		"high entropy":   {"session Zx9Qm2Lp7Rt4Vw8Ky1Nb5Hc3Jd6Fg0Sa2Ue in log", "Zx9Qm2Lp7Rt4Vw8Ky1Nb5Hc3Jd6Fg0Sa2Ue"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out, n := rd.Redact(c.in)
			if strings.Contains(out, c.mustNotContain) || n == 0 {
				t.Fatalf("not redacted (n=%d): %q", n, out)
			}
		})
	}
}

func TestKeepsOrdinaryLogLines(t *testing.T) {
	rd := Default()
	keep := []string{
		"2026-11-02T10:00:00+07:00 nginx[123]: GET /health 200 0.002s",
		"Nov 02 10:00:01 host sshd[99]: Accepted publickey for agent-ro from 10.0.0.5",
		"container 3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e started",
		"commit 0123456789abcdef0123456789abcdef01234567",
		"/usr/lib/systemd/system/multi-user.target.wants/nginx.service",
		"authorization failed for user deploy",
		"Filesystem      Size  Used Avail Use% Mounted on",
		"mkdir -p /var/lib/app && find / -perm -4000 -print",
	}
	for _, s := range keep {
		out, n := rd.Redact(s)
		if out != s || n != 0 {
			t.Errorf("over-redacted:\n in: %q\nout: %q", s, out)
		}
	}
}

func TestKeyNameStaysReadable(t *testing.T) {
	out, _ := Default().Redact("db.password=hunter2-fake")
	if out != "db.password=[REDACTED]" {
		t.Fatalf("got %q", out)
	}
}

func TestIdempotent(t *testing.T) {
	rd := Default()
	once, _ := rd.Redact("password=abc123fake token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZXNpZ25hdHVyZWZha2U")
	twice, n := rd.Redact(once)
	if once != twice || n != 0 {
		t.Fatalf("not idempotent (n=%d):\n%q\n%q", n, once, twice)
	}
}
