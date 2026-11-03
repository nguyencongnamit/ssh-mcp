// Package dockerproxy is a read-only gate in front of the Docker API.
//
// The Docker socket is root-equivalent, so agent-ro never touches it. On
// hosts that opt in, a small service (ssh-mcp-helper --docker-proxy, running
// as a user in the docker group) listens on a socket that only agent-ro may
// open, and answers exactly two questions:
//
//	GET /containers            running (or all) containers, reduced to
//	                           id, names, image, state, status, created, ports
//	GET /containers/{id}/logs  the last N lines since T, never follow
//
// It does not forward requests. It parses and validates the incoming one,
// then builds a fresh upstream request from the validated values only. Any
// other method, path or parameter is refused. Labels, command lines,
// environment and mounts never leave the proxy.
package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

// DefaultUpstream is the Docker Engine socket.
const DefaultUpstream = "/var/run/docker.sock"

// DefaultListen is where the helper's docker tools connect.
const DefaultListen = "/run/ssh-mcp/docker.sock"

// MaxLogBytes caps a logs response read from upstream.
const MaxLogBytes = 4 << 20

// Container is the reduced view returned for GET /containers.
type Container struct {
	ID      string   `json:"id"`
	Names   []string `json:"names"`
	Image   string   `json:"image"`
	State   string   `json:"state"`
	Status  string   `json:"status"`
	Created int64    `json:"created"`
	Ports   []string `json:"ports"`
}

// Proxy serves the read-only API.
type Proxy struct {
	// Upstream dials the Docker Engine API.
	Upstream func(ctx context.Context) (net.Conn, error)
	client   *http.Client
}

// New returns a Proxy for the Docker socket at path.
func New(path string) *Proxy {
	return &Proxy{Upstream: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
}

var logsPath = regexp.MustCompile(`^/containers/([^/]+)/logs$`)

// Handler returns the HTTP handler.
func (p *Proxy) Handler() http.Handler {
	p.client = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return p.Upstream(ctx) },
			DisableKeepAlives: true,
		},
	}
	return http.HandlerFunc(p.serve)
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only proxy: only GET", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, "..") || r.ContentLength > 0 {
		http.Error(w, "refused", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/containers":
		if !onlyKeys(q, "all") {
			http.Error(w, "refused parameter", http.StatusForbidden)
			return
		}
		p.containers(w, r.Context(), q.Get("all") == "1")
	case logsPath.MatchString(r.URL.Path):
		id := logsPath.FindStringSubmatch(r.URL.Path)[1]
		if !protocol.ValidContainer(id) || !onlyKeys(q, "tail", "since") {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		tail, err1 := strconv.Atoi(q.Get("tail"))
		since, err2 := strconv.ParseInt(q.Get("since"), 10, 64)
		if err1 != nil || err2 != nil || tail < 1 || tail > protocol.MaxJournalLines || since < 0 {
			http.Error(w, "refused parameter", http.StatusForbidden)
			return
		}
		p.logs(w, r.Context(), id, tail, since)
	default:
		http.Error(w, "refused", http.StatusForbidden)
	}
}

func onlyKeys(q url.Values, allowed ...string) bool {
	for k, v := range q {
		if len(v) != 1 {
			return false
		}
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if !ok {
			return false
		}
	}
	return true
}

func (p *Proxy) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := url.URL{Scheme: "http", Host: "docker", Path: path, RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return p.client.Do(req)
}

func (p *Proxy) containers(w http.ResponseWriter, ctx context.Context, all bool) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	resp, err := p.get(ctx, "/containers/json", q)
	if err != nil {
		http.Error(w, "docker unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "docker returned "+resp.Status, http.StatusBadGateway)
		return
	}
	var raw []struct {
		ID      string `json:"Id"`
		Names   []string
		Image   string
		State   string
		Status  string
		Created int64
		Ports   []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxLogBytes)).Decode(&raw); err != nil {
		http.Error(w, "bad docker response", http.StatusBadGateway)
		return
	}
	out := make([]Container, 0, len(raw))
	for _, c := range raw {
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		var ports []string
		for _, pt := range c.Ports {
			if pt.PublicPort != 0 {
				ports = append(ports, fmt.Sprintf("%s:%d->%d/%s", pt.IP, pt.PublicPort, pt.PrivatePort, pt.Type))
			} else {
				ports = append(ports, fmt.Sprintf("%d/%s", pt.PrivatePort, pt.Type))
			}
		}
		names := make([]string, 0, len(c.Names))
		for _, n := range c.Names {
			names = append(names, strings.TrimPrefix(n, "/"))
		}
		out = append(out, Container{ID: id, Names: names, Image: c.Image, State: c.State, Status: c.Status, Created: c.Created, Ports: ports})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (p *Proxy) logs(w http.ResponseWriter, ctx context.Context, id string, tail int, since int64) {
	q := url.Values{
		"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "follow": {"0"},
		"tail": {strconv.Itoa(tail)}, "since": {strconv.FormatInt(since, 10)},
	}
	resp, err := p.get(ctx, "/containers/"+url.PathEscape(id)+"/logs", q)
	if err != nil {
		http.Error(w, "docker unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		http.Error(w, "no such container", http.StatusNotFound)
		return
	default:
		http.Error(w, "docker returned "+resp.Status, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	_, _ = io.Copy(w, io.LimitReader(resp.Body, MaxLogBytes))
}
