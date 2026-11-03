package helper

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/dockerproxy"
	"github.com/nguyencongnamit/ssh-mcp/internal/protocol"
)

// dockerGet asks the read-only Docker proxy (never the Docker socket).
func (h *Helper) dockerGet(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	sock := h.DockerSocket
	if sock == "" {
		sock = dockerproxy.DefaultListen
	}
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
	u := url.URL{Scheme: "http", Host: "docker-proxy", Path: path, RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return nil, errDockerOff
		}
		return nil, err
	}
	return resp, nil
}

var errDockerOff = errors.New("docker tools are not enabled on this host (no ssh-mcp docker proxy; see docs/deployment.md)")

func (h *Helper) dockerPS(ctx context.Context, w io.Writer, a *protocol.DockerPSArgs) error {
	q := url.Values{}
	if a.All {
		q.Set("all", "1")
	}
	resp, err := h.dockerGet(ctx, "/containers", q)
	if err != nil {
		fmt.Fprintln(w, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fmt.Fprintf(w, "docker proxy: %s: %s", resp.Status, b)
		return nil
	}
	var cs []dockerproxy.Container
	if err := json.NewDecoder(io.LimitReader(resp.Body, protocol.MaxFileBytes)).Decode(&cs); err != nil {
		return fmt.Errorf("docker proxy response: %w", err)
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER ID\tNAMES\tIMAGE\tSTATE\tSTATUS\tCREATED\tPORTS")
	for _, c := range cs {
		created := time.Unix(c.Created, 0).UTC().Format(time.RFC3339)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, strings.Join(c.Names, ","), c.Image, c.State, c.Status, created, strings.Join(c.Ports, ", "))
	}
	return tw.Flush()
}

func (h *Helper) dockerLogs(ctx context.Context, w io.Writer, a *protocol.DockerLogsArgs) error {
	since := h.Now().Add(-time.Duration(a.SinceSeconds) * time.Second).Unix()
	q := url.Values{"tail": {strconv.Itoa(a.Lines)}, "since": {strconv.FormatInt(since, 10)}}
	resp, err := h.dockerGet(ctx, "/containers/"+url.PathEscape(a.Container)+"/logs", q)
	if err != nil {
		fmt.Fprintln(w, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fmt.Fprintf(w, "docker proxy: %s: %s", resp.Status, b)
		return nil
	}
	body := io.LimitReader(resp.Body, dockerproxy.MaxLogBytes)
	if strings.Contains(resp.Header.Get("Content-Type"), "multiplexed") {
		return demux(w, body)
	}
	_, err = io.Copy(w, body) // TTY containers: raw stream
	return err
}

// demux writes the payload of Docker's multiplexed stream (8-byte header:
// stream type, 3 zero bytes, big-endian length) and marks stderr lines.
func demux(w io.Writer, r io.Reader) error {
	br := bufio.NewReader(r)
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if n > dockerproxy.MaxLogBytes {
			return errors.New("docker log frame too large")
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(br, frame); err != nil {
			return nil
		}
		if hdr[0] == 2 {
			for _, line := range strings.SplitAfter(string(frame), "\n") {
				if line != "" {
					fmt.Fprint(w, "[stderr] "+line)
				}
			}
			continue
		}
		if _, err := w.Write(frame); err != nil {
			return err
		}
	}
}
