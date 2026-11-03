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

func TestDockerArgs(t *testing.T) {
	v, err := Normalize(ToolDockerPS, []byte(`{"all":true}`))
	if err != nil || !v.(*DockerPSArgs).All {
		t.Fatalf("docker_ps: %v %v", v, err)
	}
	v, err = Normalize(ToolDockerLogs, []byte(`{"container":"web-1.api_2"}`))
	if err != nil {
		t.Fatal(err)
	}
	a := v.(*DockerLogsArgs)
	if a.Lines != DefaultLines || a.SinceSeconds != DefaultSinceSecs {
		t.Fatalf("defaults not applied: %+v", a)
	}
	v, _ = Normalize(ToolDockerLogs, []byte(`{"container":"web","lines":99999,"since_seconds":99999999}`))
	if a := v.(*DockerLogsArgs); a.Lines != MaxJournalLines || a.SinceSeconds != MaxJournalSince {
		t.Fatalf("caps not applied: %+v", a)
	}
	for _, bad := range []string{
		`{"container":"-it"}`, `{"container":".x"}`, `{"container":"a/b"}`, `{"container":"a b"}`,
		`{"container":""}`, `{}`, `{"container":"web","follow":true}`, `{"container":"web;id"}`,
	} {
		if _, err := Normalize(ToolDockerLogs, []byte(bad)); err == nil {
			t.Errorf("docker_logs accepted %s", bad)
		}
	}
	if _, err := Normalize(ToolDockerPS, []byte(`{"filters":"x"}`)); err == nil {
		t.Error("docker_ps accepted an unknown field")
	}
}
