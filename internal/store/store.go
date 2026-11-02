// Package store keeps ssh-mcp's state in one SQLite file: the hash-chained
// audit log, the kill switch, and bot tokens (hashed).
//
// The audit table is append-only: SQLite triggers abort any UPDATE or DELETE,
// and each record carries the SHA-256 of the previous record, so editing the
// file out-of-band breaks the chain and `ssh-mcp audit verify` reports it.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, keeps the binary CGO-free
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  call        INTEGER NOT NULL DEFAULT 0,
  ts          TEXT NOT NULL,
  identity    TEXT NOT NULL,
  display     TEXT NOT NULL DEFAULT '',
  client      TEXT NOT NULL,
  host        TEXT NOT NULL,
  tool        TEXT NOT NULL,
  args        TEXT NOT NULL,
  decision    TEXT NOT NULL,
  rule        TEXT NOT NULL,
  reason      TEXT NOT NULL,
  exit_status TEXT NOT NULL,
  bytes_out   INTEGER NOT NULL,
  redactions  INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS disabled (
  key    TEXT PRIMARY KEY,
  at     TEXT NOT NULL,
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  name    TEXT PRIMARY KEY,
  hash    TEXT NOT NULL UNIQUE,
  owner   TEXT NOT NULL,
  created TEXT NOT NULL,
  expires TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
`

// GlobalKill is the kill-switch key that disables every identity.
const GlobalKill = "*"

// Store wraps the database.
type Store struct {
	db  *sql.DB
	mu  sync.Mutex // serialises audit appends so the chain is linear
	now func() time.Time
	key []byte // HMAC key for the audit chain; nil = plain SHA-256
}

// SetAuditKey switches the chain to HMAC-SHA256 with key. Someone who can
// write the database but does not hold the key can no longer rebuild a
// consistent chain after editing or deleting records. Keep the key outside
// the data directory (e.g. a root-owned file or a secrets manager).
func (s *Store) SetAuditKey(key []byte) { s.key = key }

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ---------------------------------------------------------------- audit

// Record is one audit entry.
type Record struct {
	ID         int64  `json:"id"`
	Call       int64  `json:"call"` // ID of the call's "allow" record (0 if refused before one)
	TS         string `json:"ts"`
	Identity   string `json:"identity"`
	Display    string `json:"display"`
	Client     string `json:"client"`
	Host       string `json:"host"`
	Tool       string `json:"tool"`
	Args       string `json:"args"`
	Decision   string `json:"decision"` // allow | deny | error
	Rule       string `json:"rule"`
	Reason     string `json:"reason"`
	ExitStatus string `json:"exit_status"`
	BytesOut   int64  `json:"bytes_out"`
	Redactions int64  `json:"redactions"`
	DurationMS int64  `json:"duration_ms"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
}

// hashOf covers every field except ID and Hash.
func (s *Store) hashOf(r Record) string {
	c := r
	c.ID, c.Hash = 0, ""
	b, _ := json.Marshal(c)
	if s.key != nil {
		m := hmac.New(sha256.New, s.key)
		m.Write(b)
		return "h1:" + hex.EncodeToString(m.Sum(nil))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Append writes r to the chain and returns it with TS, PrevHash, Hash set.
func (s *Store) Append(ctx context.Context, r Record) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback() //nolint:errcheck
	prev := ""
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	r.TS = s.now().UTC().Format(time.RFC3339Nano)
	r.PrevHash = prev
	r.Hash = s.hashOf(r)
	res, err := tx.ExecContext(ctx, `INSERT INTO audit
	  (call,ts,identity,display,client,host,tool,args,decision,rule,reason,exit_status,bytes_out,redactions,duration_ms,prev_hash,hash)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Call, r.TS, r.Identity, r.Display, r.Client, r.Host, r.Tool, r.Args, r.Decision, r.Rule, r.Reason,
		r.ExitStatus, r.BytesOut, r.Redactions, r.DurationMS, r.PrevHash, r.Hash)
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, tx.Commit()
}

const recordCols = `id,call,ts,identity,display,client,host,tool,args,decision,rule,reason,exit_status,bytes_out,redactions,duration_ms,prev_hash,hash`

func scanRecord(sc interface{ Scan(...any) error }) (Record, error) {
	var r Record
	err := sc.Scan(&r.ID, &r.Call, &r.TS, &r.Identity, &r.Display, &r.Client, &r.Host, &r.Tool, &r.Args, &r.Decision,
		&r.Rule, &r.Reason, &r.ExitStatus, &r.BytesOut, &r.Redactions, &r.DurationMS, &r.PrevHash, &r.Hash)
	return r, err
}

// Since returns records with id > after, oldest first, at most limit.
func (s *Store) Since(ctx context.Context, after int64, limit int) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordCols+` FROM audit WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Tail returns the last n records, oldest first.
func (s *Store) Tail(ctx context.Context, n int) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordCols+` FROM (SELECT * FROM audit ORDER BY id DESC LIMIT ?) ORDER BY id`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Verify walks the whole chain. It returns the number of records checked and
// the first broken record ID (0 if intact).
func (s *Store) Verify(ctx context.Context) (n int64, brokenAt int64, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordCols+` FROM audit ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return n, 0, err
		}
		n++
		if r.PrevHash != prev || s.hashOf(r) != r.Hash {
			return n, r.ID, nil
		}
		prev = r.Hash
	}
	return n, 0, rows.Err()
}

// SeenIdentity reports whether key appears in the audit log (used to warn
// about kill-switch typos).
func (s *Store) SeenIdentity(ctx context.Context, key string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit WHERE identity=?`, key).Scan(&n)
	return n > 0, err
}

// ---------------------------------------------------------------- kill switch

// Disable blocks key (an identity key, or GlobalKill).
func (s *Store) Disable(ctx context.Context, key, reason string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO disabled(key,at,reason) VALUES(?,?,?)
	  ON CONFLICT(key) DO UPDATE SET at=excluded.at, reason=excluded.reason`,
		key, s.now().UTC().Format(time.RFC3339), reason)
	return err
}

// Enable lifts a block.
func (s *Store) Enable(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM disabled WHERE key=?`, key)
	return err
}

// IsDisabled reports whether key or the global switch is set. It reads the
// database on every call so a CLI `kill` in another process takes effect on
// the very next tool call.
func (s *Store) IsDisabled(ctx context.Context, key string) (bool, string, error) {
	var reason string
	err := s.db.QueryRowContext(ctx, `SELECT reason FROM disabled WHERE key=? OR key=? LIMIT 1`, key, GlobalKill).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return true, "kill-switch lookup failed", err // fail closed
	}
	return true, reason, nil
}

// ---------------------------------------------------------------- tokens

// TokenPrefix marks ssh-mcp bot tokens so secret scanners can find leaks.
const TokenPrefix = "smcp_"

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// CreateToken issues a new bot token. The plaintext is returned once and
// never stored.
func (s *Store) CreateToken(ctx context.Context, name, owner string, ttl time.Duration) (string, error) {
	if name == "" || strings.ContainsAny(name, " \t\n:") {
		return "", errors.New("token name must be non-empty with no spaces or colons")
	}
	if ttl <= 0 || ttl > 90*24*time.Hour {
		return "", errors.New("token ttl must be between 1s and 90 days")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	now := s.now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO tokens(name,hash,owner,created,expires) VALUES(?,?,?,?,?)`,
		name, hashToken(tok), owner, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return tok, nil
}

// RevokeToken revokes a bot token by name.
func (s *Store) RevokeToken(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked=1 WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no token named %q", name)
	}
	return nil
}

// ErrBadToken is returned for unknown, expired or revoked tokens.
var ErrBadToken = errors.New("invalid, expired or revoked token")

// LookupToken returns the bot name and expiry for a plaintext token.
func (s *Store) LookupToken(ctx context.Context, tok string) (string, time.Time, error) {
	if !strings.HasPrefix(tok, TokenPrefix) {
		return "", time.Time{}, ErrBadToken
	}
	h := hashToken(tok)
	var name, stored, exp string
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT name,hash,expires,revoked FROM tokens WHERE hash=?`, h).Scan(&name, &stored, &exp, &revoked)
	if err != nil {
		return "", time.Time{}, ErrBadToken
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(h)) != 1 || revoked != 0 {
		return "", time.Time{}, ErrBadToken
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil || !s.now().Before(t) {
		return "", time.Time{}, ErrBadToken
	}
	return name, t, nil
}

// TokenInfo is a listing row (no secret material).
type TokenInfo struct {
	Name, Owner, Created, Expires string
	Revoked                       bool
}

// ListTokens lists bot tokens.
func (s *Store) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,owner,created,expires,revoked FROM tokens ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var t TokenInfo
		var rv int
		if err := rows.Scan(&t.Name, &t.Owner, &t.Created, &t.Expires, &rv); err != nil {
			return nil, err
		}
		t.Revoked = rv != 0
		out = append(out, t)
	}
	return out, rows.Err()
}
