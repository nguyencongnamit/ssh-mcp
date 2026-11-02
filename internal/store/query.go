package store

import (
	"context"
	"strings"
	"time"
)

// Filter selects audit records for the console.
type Filter struct {
	Identity string
	Host     string
	Tool     string
	Decision string
	Before   int64 // records with id < Before (0 = newest)
	Limit    int
}

// Query returns matching records, newest first.
func (s *Store) Query(ctx context.Context, f Filter) ([]Record, error) {
	var where []string
	var args []any
	add := func(col, v string) {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	add("identity", f.Identity)
	add("host", f.Host)
	add("tool", f.Tool)
	add("decision", f.Decision)
	if f.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, f.Before)
	}
	q := `SELECT ` + recordCols + ` FROM audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
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

// Get returns one record.
func (s *Store) Get(ctx context.Context, id int64) (Record, error) {
	return scanRecord(s.db.QueryRowContext(ctx, `SELECT `+recordCols+` FROM audit WHERE id = ?`, id))
}

// Stats counts records by decision since t.
type Stats struct {
	Calls, Denied, Errors, Redactions int64
	Identities, Hosts                 int64
}

// StatsSince summarises activity since t.
func (s *Store) StatsSince(ctx context.Context, t time.Time) (Stats, error) {
	var st Stats
	ts := t.UTC().Format(time.RFC3339Nano)
	err := s.db.QueryRowContext(ctx, `SELECT
	  COALESCE(SUM(decision='allow'),0), COALESCE(SUM(decision='deny'),0), COALESCE(SUM(decision='error'),0),
	  COALESCE(SUM(redactions),0),
	  COUNT(DISTINCT CASE WHEN identity NOT LIKE 'system:%' AND identity NOT LIKE 'console:%' THEN identity END),
	  COUNT(DISTINCT CASE WHEN host <> '' THEN host END)
	  FROM audit WHERE ts >= ?`, ts).Scan(&st.Calls, &st.Denied, &st.Errors, &st.Redactions, &st.Identities, &st.Hosts)
	return st, err
}

// IdentitySeen is one caller as seen in the audit log.
type IdentitySeen struct {
	Key, Display, LastSeen string
	Calls, Denied          int64
}

// Identities lists every caller that has appeared, most recent first.
func (s *Store) Identities(ctx context.Context) ([]IdentitySeen, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT identity, MAX(display), MAX(ts),
	  SUM(decision='allow'), SUM(decision='deny')
	  FROM audit WHERE identity <> '' AND identity NOT LIKE 'system:%' AND identity NOT LIKE 'console:%'
	  GROUP BY identity ORDER BY MAX(ts) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdentitySeen
	for rows.Next() {
		var i IdentitySeen
		if err := rows.Scan(&i.Key, &i.Display, &i.LastSeen, &i.Calls, &i.Denied); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// HostActivity is the last activity on one host.
type HostActivity struct {
	LastSeen string
	Calls    int64
}

// HostActivity maps host ID to its last activity.
func (s *Store) HostActivity(ctx context.Context) (map[string]HostActivity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, MAX(ts), SUM(decision IN ('allow','deny')) FROM audit WHERE host <> '' GROUP BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HostActivity{}
	for rows.Next() {
		var h string
		var a HostActivity
		if err := rows.Scan(&h, &a.LastSeen, &a.Calls); err != nil {
			return nil, err
		}
		out[h] = a
	}
	return out, rows.Err()
}

// Disabled is one kill-switch entry.
type Disabled struct{ Key, At, Reason string }

// ListDisabled returns all kill-switch entries.
func (s *Store) ListDisabled(ctx context.Context) ([]Disabled, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, at, reason FROM disabled ORDER BY at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Disabled
	for rows.Next() {
		var d Disabled
		if err := rows.Scan(&d.Key, &d.At, &d.Reason); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Bucket is one hour of activity.
type Bucket struct {
	Start                            time.Time
	Allowed, Denied, Errors, Redacts int64
}

// Hourly returns n one-hour buckets ending at the current hour (oldest
// first), always n long so charts have a stable x axis.
func (s *Store) Hourly(ctx context.Context, n int) ([]Bucket, error) {
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-time.Duration(n-1) * time.Hour)
	rows, err := s.db.QueryContext(ctx, `SELECT substr(ts,1,13),
	  SUM(decision='allow'), SUM(decision='deny'), SUM(decision='error'), SUM(redactions)
	  FROM audit WHERE ts >= ? AND identity NOT LIKE 'system:%' AND identity NOT LIKE 'console:%'
	  GROUP BY substr(ts,1,13)`, start.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHour := map[string]Bucket{}
	for rows.Next() {
		var k string
		var b Bucket
		if err := rows.Scan(&k, &b.Allowed, &b.Denied, &b.Errors, &b.Redacts); err != nil {
			return nil, err
		}
		byHour[k] = b
	}
	out := make([]Bucket, n)
	for i := range out {
		t := start.Add(time.Duration(i) * time.Hour)
		b := byHour[t.Format("2006-01-02T15")]
		b.Start = t
		out[i] = b
	}
	return out, rows.Err()
}

// StatsBetween summarises activity in [from, to).
func (s *Store) StatsBetween(ctx context.Context, from, to time.Time) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `SELECT
	  COALESCE(SUM(decision='allow'),0), COALESCE(SUM(decision='deny'),0), COALESCE(SUM(decision='error'),0),
	  COALESCE(SUM(redactions),0),
	  COUNT(DISTINCT CASE WHEN identity NOT LIKE 'system:%' AND identity NOT LIKE 'console:%' THEN identity END),
	  COUNT(DISTINCT CASE WHEN host <> '' THEN host END)
	  FROM audit WHERE ts >= ? AND ts < ?`,
		from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano)).
		Scan(&st.Calls, &st.Denied, &st.Errors, &st.Redactions, &st.Identities, &st.Hosts)
	return st, err
}

// Count is a label with a number.
type Count struct {
	Label, Display string
	N              int64
}

// TopN ranks tools, identities or hosts by allowed calls since t.
func (s *Store) TopN(ctx context.Context, by string, since time.Time, n int) ([]Count, error) {
	col := map[string]string{"tool": "tool", "identity": "identity", "host": "host"}[by]
	if col == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+col+`, MAX(display), COUNT(*) FROM audit
	  WHERE ts >= ? AND decision IN ('allow','deny') AND `+col+` <> ''
	  AND identity NOT LIKE 'system:%' AND identity NOT LIKE 'console:%'
	  GROUP BY `+col+` ORDER BY COUNT(*) DESC LIMIT ?`, since.UTC().Format(time.RFC3339Nano), n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Label, &c.Display, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HostHourly returns 24 hourly call counts per host.
func (s *Store) HostHourly(ctx context.Context, n int) (map[string][]int64, error) {
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-time.Duration(n-1) * time.Hour)
	rows, err := s.db.QueryContext(ctx, `SELECT host, substr(ts,1,13), COUNT(*) FROM audit
	  WHERE ts >= ? AND host <> '' AND decision IN ('allow','deny') GROUP BY host, substr(ts,1,13)`, start.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]int64{}
	for rows.Next() {
		var h, k string
		var c int64
		if err := rows.Scan(&h, &k, &c); err != nil {
			return nil, err
		}
		t, err := time.Parse("2006-01-02T15", k)
		if err != nil {
			continue
		}
		i := int(t.Sub(start) / time.Hour)
		if i < 0 || i >= n {
			continue
		}
		if out[h] == nil {
			out[h] = make([]int64, n)
		}
		out[h][i] = c
	}
	return out, rows.Err()
}

// CallTrail returns every record of one call (its allow record plus the
// result, refusal or error that references it), oldest first.
func (s *Store) CallTrail(ctx context.Context, r Record) ([]Record, error) {
	call := r.Call
	if r.Decision == "allow" {
		call = r.ID
	}
	if call == 0 {
		return []Record{r}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordCols+` FROM audit WHERE id = ? OR call = ? ORDER BY id`, call, call)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		x, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
