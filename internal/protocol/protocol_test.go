package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRequestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          ``,
		"not json":       `journal --unit nginx`,
		"shell":          `ls; id`,
		"unknown field":  `{"tool":"ps","cmd":"id"}`,
		"trailing data":  `{"tool":"ps"} {"tool":"ps"}`,
		"missing tool":   `{"args":{}}`,
		"oversized line": `{"tool":"ps","args":{"limit":1}}` + strings.Repeat(" ", MaxRequestBytes),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest([]byte(line)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestNormalizeRejectsInjection(t *testing.T) {
	cases := []struct{ tool, args string }{
		{ToolJournal, `{"unit":"nginx; id"}`},
		{ToolJournal, `{"unit":"-H"}`},
		{ToolJournal, `{"unit":"--output=json"}`},
		{ToolJournal, `{"unit":"../../etc"}`},
		{ToolJournal, `{"unit":"a b"}`},
		{ToolJournal, `{"unit":"$(id)"}`},
		{ToolJournal, `{"unit":"x\nid"}`},
		{ToolJournal, `{"priority":8}`},
		{ToolJournal, `{"priority":-1}`},
		{ToolJournal, `{"since":"yesterday"}`},
		{ToolSystemctlStatus, `{}`},
		{ToolSystemctlStatus, `{"unit":"-l"}`},
		{ToolSystemctlStatus, `{"unit":"nginx","verb":"restart"}`},
		{ToolReadFile, `{"path":"etc/passwd"}`},
		{ToolReadFile, `{"path":""}`},
		{ToolReadFile, `{"path":"/etc/hosts\u0000/x"}`},
		{ToolReadFile, `{"path":"/etc/hosts","offset":-5}`},
		{ToolListDir, `{"path":"~root"}`},
		{ToolHostOverview, `{"x":1}`},
		{"rm", `{}`},
		{"exec", `{"cmd":"id"}`},
	}
	for _, c := range cases {
		t.Run(c.tool+" "+c.args, func(t *testing.T) {
			if _, err := Normalize(c.tool, []byte(c.args)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestNormalizeClamps(t *testing.T) {
	a, err := Normalize(ToolJournal, []byte(`{"unit":"nginx.service","lines":999999,"since_seconds":99999999}`))
	if err != nil {
		t.Fatal(err)
	}
	j := a.(*JournalArgs)
	if j.Lines != MaxJournalLines || j.SinceSeconds != MaxJournalSince {
		t.Fatalf("not clamped: %+v", j)
	}
	a, _ = Normalize(ToolPS, nil)
	if a.(*PSArgs).Limit != DefaultPSRows {
		t.Fatal("default not applied")
	}
	a, _ = Normalize(ToolReadFile, []byte(`{"path":"/var/log/x","length":99999999}`))
	if a.(*FileArgs).Length != MaxFileBytes {
		t.Fatal("length not capped")
	}
}

func TestValidUnit(t *testing.T) {
	for _, ok := range []string{"nginx", "nginx.service", "getty@tty1.service", "sys-devices-x.device", `dev-disk-by\x2duuid.swap`} {
		if !ValidUnit(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-x", "a/b", "a b", "a;b", "a|b", "a`b", strings.Repeat("a", 300)} {
		if ValidUnit(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
