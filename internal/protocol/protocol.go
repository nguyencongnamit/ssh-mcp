// Package protocol defines the wire format between the ssh-mcp server and
// ssh-mcp-helper on a target host.
//
// The server sends ONE line of JSON as the SSH command. Because the SSH
// certificate pins force-command to the helper, sshd never runs that line:
// it hands it to the helper in SSH_ORIGINAL_COMMAND. The helper decodes it
// strictly (unknown fields rejected), validates every argument against the
// rules in this package, and executes a fixed argv. Nothing in a request is
// ever passed to a shell.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// MaxRequestBytes caps the size of a request line.
const MaxRequestBytes = 4096

// Tool names understood by the helper.
const (
	ToolHostOverview    = "host_overview"
	ToolPS              = "ps"
	ToolListeningPorts  = "listening_ports"
	ToolJournal         = "journal"
	ToolSystemctlStatus = "systemctl_status"
	ToolFailedUnits     = "failed_units"
	ToolReadFile        = "read_file"
	ToolTailFile        = "tail_file"
	ToolListDir         = "list_dir"
)

// Limits shared by server-side validation and the helper.
const (
	MaxPSRows        = 200
	MaxJournalLines  = 2000
	MaxJournalSince  = 7 * 24 * 3600 // seconds
	MaxTailLines     = 2000
	MaxDirEntries    = 1000
	MaxFileBytes     = 256 * 1024
	MaxPathBytes     = 1024
	MaxStatusLines   = 200
	DefaultLines     = 200
	DefaultPSRows    = 50
	DefaultSinceSecs = 3600
)

// Request is the single JSON line the server sends.
type Request struct {
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args,omitempty"`
}

// PSArgs for ToolPS.
type PSArgs struct {
	Limit int `json:"limit,omitempty"`
}

// JournalArgs for ToolJournal.
type JournalArgs struct {
	Unit         string `json:"unit,omitempty"`
	SinceSeconds int    `json:"since_seconds,omitempty"`
	Priority     *int   `json:"priority,omitempty"`
	Lines        int    `json:"lines,omitempty"`
}

// UnitArgs for ToolSystemctlStatus.
type UnitArgs struct {
	Unit  string `json:"unit"`
	Lines int    `json:"lines,omitempty"`
}

// FileArgs for ToolReadFile.
type FileArgs struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"`
}

// TailArgs for ToolTailFile.
type TailArgs struct {
	Path  string `json:"path"`
	Lines int    `json:"lines,omitempty"`
}

// DirArgs for ToolListDir.
type DirArgs struct {
	Path string `json:"path"`
}

// unitRe matches systemd unit names. It forbids a leading '-' so a unit can
// never be read as an option, and forbids '/', whitespace and shell
// metacharacters outright.
var unitRe = regexp.MustCompile(`^[A-Za-z0-9_@:.\\][A-Za-z0-9_@:.\\-]{0,254}$`)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid request")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidUnit reports whether s is an acceptable systemd unit name.
func ValidUnit(s string) bool { return unitRe.MatchString(s) }

// DecodeStrict decodes JSON into v, rejecting unknown fields and trailing data.
func DecodeStrict(data []byte, v any) error {
	if len(data) == 0 {
		data = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("%v", err)
	}
	if dec.More() {
		return invalid("trailing data")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return invalid("trailing data")
	}
	return nil
}

// ParseRequest decodes and size-checks a request line.
func ParseRequest(line []byte) (*Request, error) {
	if len(line) == 0 {
		return nil, invalid("empty request")
	}
	if len(line) > MaxRequestBytes {
		return nil, invalid("request exceeds %d bytes", MaxRequestBytes)
	}
	var r Request
	if err := DecodeStrict(line, &r); err != nil {
		return nil, err
	}
	if r.Tool == "" {
		return nil, invalid("missing tool")
	}
	return &r, nil
}

// clamp returns def when v<=0, max when v>max, else v.
func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// Normalize validates args for tool and applies defaults and caps. It returns
// the normalised args value (one of the *Args types, or nil for no-arg tools).
func Normalize(tool string, raw json.RawMessage) (any, error) {
	switch tool {
	case ToolHostOverview, ToolListeningPorts, ToolFailedUnits:
		var empty struct{}
		if err := DecodeStrict(raw, &empty); err != nil {
			return nil, err
		}
		return nil, nil
	case ToolPS:
		var a PSArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		a.Limit = clamp(a.Limit, DefaultPSRows, MaxPSRows)
		return &a, nil
	case ToolJournal:
		var a JournalArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if a.Unit != "" && !ValidUnit(a.Unit) {
			return nil, invalid("bad unit name")
		}
		if a.Priority != nil && (*a.Priority < 0 || *a.Priority > 7) {
			return nil, invalid("priority must be 0-7")
		}
		a.Lines = clamp(a.Lines, DefaultLines, MaxJournalLines)
		a.SinceSeconds = clamp(a.SinceSeconds, DefaultSinceSecs, MaxJournalSince)
		return &a, nil
	case ToolSystemctlStatus:
		var a UnitArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if !ValidUnit(a.Unit) {
			return nil, invalid("bad unit name")
		}
		a.Lines = clamp(a.Lines, 20, MaxStatusLines)
		return &a, nil
	case ToolReadFile:
		var a FileArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if err := checkPathShape(a.Path); err != nil {
			return nil, err
		}
		if a.Offset < 0 {
			return nil, invalid("negative offset")
		}
		if a.Length <= 0 || a.Length > MaxFileBytes {
			a.Length = MaxFileBytes
		}
		return &a, nil
	case ToolTailFile:
		var a TailArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if err := checkPathShape(a.Path); err != nil {
			return nil, err
		}
		a.Lines = clamp(a.Lines, DefaultLines, MaxTailLines)
		return &a, nil
	case ToolListDir:
		var a DirArgs
		if err := DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if err := checkPathShape(a.Path); err != nil {
			return nil, err
		}
		return &a, nil
	default:
		return nil, invalid("unknown tool %q", tool)
	}
}

// checkPathShape rejects paths that are not absolute, too long, or contain
// NUL bytes. Containment (prefix/deny rules, symlinks) is checked by the
// helper against the real filesystem.
func checkPathShape(p string) error {
	if p == "" || p[0] != '/' {
		return invalid("path must be absolute")
	}
	if len(p) > MaxPathBytes {
		return invalid("path too long")
	}
	if bytes.IndexByte([]byte(p), 0) >= 0 {
		return invalid("path contains NUL")
	}
	return nil
}
