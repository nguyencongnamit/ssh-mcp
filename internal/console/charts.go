package console

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

// Charts are rendered on the server as inline SVG: no chart library, no
// CDN, nothing for the CSP to allow. Colors come from CSS custom properties
// (--s-allow, --s-deny, --s-error), validated for both themes and for
// colour-vision deficiency in stack order errors -> allowed -> refused.

// niceMax returns a y-axis maximum that is four steps of a round integer
// (1, 2, 5 x 10^k), so every gridline label is a whole number.
func niceMax(v float64) float64 {
	if v <= 4 {
		return 4
	}
	raw := v / 4
	exp := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		step := m * exp
		if step != math.Trunc(step) {
			continue
		}
		if step >= raw {
			return step * 4
		}
	}
	return 10 * exp * 4
}

// roundedTop draws a bar segment whose top corners are rounded (the data end).
func roundedTop(x, y, w, h, r float64) string {
	if h <= 0 {
		return ""
	}
	if r > h {
		r = h
	}
	if r > w/2 {
		r = w / 2
	}
	return fmt.Sprintf("M%.1f %.1fV%.1fQ%.1f %.1f %.1f %.1fH%.1fQ%.1f %.1f %.1f %.1fV%.1fZ",
		x, y+h, y+r, x, y, x+r, y, x+w-r, x+w, y, x+w, y+r, y+h)
}

// activityChart is the stacked hourly bar chart.
func activityChart(buckets []store.Bucket, loc *time.Location) template.HTML {
	const W, H, left, right, top, bottom = 720.0, 270.0, 34.0, 4.0, 10.0, 26.0
	plotW, plotH := W-left-right, H-top-bottom
	maxV := 0.0
	for _, b := range buckets {
		maxV = math.Max(maxV, float64(b.Allowed+b.Denied+b.Errors))
	}
	ymax := niceMax(maxV)
	y := func(v float64) float64 { return top + plotH - v/ymax*plotH }

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="Agent calls per hour, last 24 hours">`, W, H)
	// Recessive grid with left-axis values.
	for i := 0; i <= 4; i++ {
		v := ymax * float64(i) / 4
		yy := y(v)
		fmt.Fprintf(&sb, `<line class="grid" x1="%.0f" x2="%.0f" y1="%.1f" y2="%.1f"/>`, left, W-right, yy, yy)
		fmt.Fprintf(&sb, `<text class="axis" x="%.0f" y="%.1f" text-anchor="end">%s</text>`, left-8, yy+4, fmtNum(v))
	}
	n := float64(len(buckets))
	slot := plotW / n
	bw := slot * 0.62
	for i, b := range buckets {
		x := left + float64(i)*slot + (slot-bw)/2
		segs := []struct {
			v   int64
			cls string
		}{{b.Errors, "s-error"}, {b.Allowed, "s-allow"}, {b.Denied, "s-deny"}}
		base := 0.0
		lastIdx := -1
		for j, s := range segs {
			if s.v > 0 {
				lastIdx = j
			}
		}
		for j, s := range segs {
			if s.v == 0 {
				continue
			}
			y0, y1 := y(base+float64(s.v)), y(base)
			h := y1 - y0
			if base > 0 {
				h -= 2 // 2px surface gap between stacked segments
			}
			if h < 1 {
				h = 1
			}
			if j == lastIdx {
				fmt.Fprintf(&sb, `<path class="%s" d="%s"/>`, s.cls, roundedTop(x, y0, bw, h, 4))
			} else {
				fmt.Fprintf(&sb, `<rect class="%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f"/>`, s.cls, x, y0, bw, h)
			}
			base += float64(s.v)
		}
		t := b.Start.In(loc)
		tip := fmt.Sprintf("%s–%s · %d allowed · %d refused · %d errors", t.Format("15:04"), t.Add(time.Hour).Format("15:04"), b.Allowed, b.Denied, b.Errors)
		// Hit target: the full column, wider than the bar.
		fmt.Fprintf(&sb, `<rect class="hit" x="%.1f" y="%.0f" width="%.1f" height="%.0f" data-tip="%s"/>`,
			left+float64(i)*slot, top, slot, plotH, html.EscapeString(tip))
		if i%3 == 0 || i == len(buckets)-1 {
			label := t.Format("15:04")
			if i == len(buckets)-1 {
				label = "now"
			}
			fmt.Fprintf(&sb, `<text class="axis" x="%.1f" y="%.0f" text-anchor="middle">%s</text>`, x+bw/2, H-8, label)
		}
	}
	fmt.Fprintf(&sb, `<line class="baseline" x1="%.0f" x2="%.0f" y1="%.1f" y2="%.1f"/>`, left, W-right, y(0), y(0))
	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// sparkline draws a small trend line with a soft area and an end marker.
func sparkline(vals []int64, cls string) template.HTML {
	const W, H, pad = 120.0, 32.0, 3.0
	if len(vals) < 2 {
		return ""
	}
	maxV := 1.0
	for _, v := range vals {
		maxV = math.Max(maxV, float64(v))
	}
	step := (W - 2*pad) / float64(len(vals)-1)
	pts := make([]string, len(vals))
	var lx, ly float64
	for i, v := range vals {
		lx = pad + float64(i)*step
		ly = H - pad - float64(v)/maxV*(H-2*pad)
		pts[i] = fmt.Sprintf("%.1f,%.1f", lx, ly)
	}
	line := strings.Join(pts, " ")
	area := fmt.Sprintf("%.1f,%.1f %s %.1f,%.1f", pad, H-pad, line, lx, H-pad)
	return template.HTML(fmt.Sprintf(`<svg class="spark %s" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" aria-hidden="true"><polygon class="area" points="%s"/><polyline class="line" points="%s"/><path class="end" d="M%.1f %.1fh0"/></svg>`,
		cls, W, H, area, line, lx, ly))
}

func fmtNum(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.0fk", v/1e3)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	case v == math.Trunc(v):
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

// delta describes the change from prev to cur for a KPI tile.
type delta struct {
	Glyph, Text, Tone string
}

func mkDelta(cur, prev int64, upIsBad bool) delta {
	if cur == prev {
		return delta{"·", "same as previous 24h", "flat"}
	}
	g := "▲"
	if cur < prev {
		g = "▼"
	}
	var text string
	if prev == 0 {
		text = fmt.Sprintf("%+d vs previous 24h", cur-prev)
	} else {
		text = fmt.Sprintf("%+.0f%% vs previous 24h", float64(cur-prev)/float64(prev)*100)
	}
	tone := "flat"
	if upIsBad {
		if cur > prev {
			tone = "bad"
		} else {
			tone = "good"
		}
	}
	return delta{g, text, tone}
}
