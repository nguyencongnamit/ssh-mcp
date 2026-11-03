package protocol

import (
	"strings"
	"testing"
)

// FuzzParseAndNormalize feeds arbitrary request lines through the same two
// steps the helper runs. Whatever the input, decoding must not panic, and
// anything it accepts must satisfy the invariants the helper relies on before
// it builds an argv.
func FuzzParseAndNormalize(f *testing.F) {
	for _, s := range []string{
		`{"tool":"host_overview"}`,
		`{"tool":"ps","args":{"limit":5}}`,
		`{"tool":"journal","args":{"unit":"nginx.service","since_seconds":60,"priority":3,"lines":10}}`,
		`{"tool":"journal","args":{"unit":"x;id"}}`,
		`{"tool":"journal","args":{"unit":"-o"}}`,
		`{"tool":"systemctl_status","args":{"unit":"ssh@1.service"}}`,
		`{"tool":"read_file","args":{"path":"/var/log/syslog","offset":0,"length":100}}`,
		`{"tool":"read_file","args":{"path":"relative"}}`,
		`{"tool":"tail_file","args":{"path":"/var/log/../etc/shadow","lines":-1}}`,
		`{"tool":"list_dir","args":{"path":"/etc/"}}`,
		`{"tool":"list_dir","args":{"path":"/etc/\u0000x"}}`,
		`{"tool":"ps","args":{"limit":1}}{"tool":"ps"}`,
		`{"tool":"ps","extra":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		req, err := ParseRequest(line)
		if err != nil {
			return
		}
		if len(line) > MaxRequestBytes || req.Tool == "" {
			t.Fatalf("accepted oversize or tool-less request: %q", line)
		}
		v, err := Normalize(req.Tool, req.Args)
		if err != nil {
			return
		}
		checkPath := func(p string) {
			if p == "" || p[0] != '/' || len(p) > MaxPathBytes || strings.IndexByte(p, 0) >= 0 {
				t.Fatalf("accepted bad path %q", p)
			}
		}
		checkUnit := func(u string) {
			if !unitRe.MatchString(u) || strings.HasPrefix(u, "-") || strings.ContainsAny(u, "/ \t\n;|&$`'\"<>(){}*?") {
				t.Fatalf("accepted bad unit %q", u)
			}
		}
		switch a := v.(type) {
		case nil:
		case *PSArgs:
			if a.Limit < 1 || a.Limit > MaxPSRows {
				t.Fatalf("ps limit %d out of range", a.Limit)
			}
		case *JournalArgs:
			if a.Unit != "" {
				checkUnit(a.Unit)
			}
			if a.Priority != nil && (*a.Priority < 0 || *a.Priority > 7) {
				t.Fatalf("priority %d out of range", *a.Priority)
			}
			if a.Lines < 1 || a.Lines > MaxJournalLines || a.SinceSeconds < 1 || a.SinceSeconds > MaxJournalSince {
				t.Fatalf("journal caps not applied: %+v", a)
			}
		case *UnitArgs:
			checkUnit(a.Unit)
			if a.Lines < 1 || a.Lines > MaxStatusLines {
				t.Fatalf("status lines %d out of range", a.Lines)
			}
		case *FileArgs:
			checkPath(a.Path)
			if a.Offset < 0 || a.Length < 1 || a.Length > MaxFileBytes {
				t.Fatalf("read_file bounds not applied: %+v", a)
			}
		case *TailArgs:
			checkPath(a.Path)
			if a.Lines < 1 || a.Lines > MaxTailLines {
				t.Fatalf("tail lines %d out of range", a.Lines)
			}
		case *DirArgs:
			checkPath(a.Path)
		default:
			t.Fatalf("unexpected args type %T", v)
		}
	})
}
