#!/usr/bin/env python3
"""Generates docs/assets/architecture-{light,dark}.svg.

Run from the repo root: python3 docs/assets/gen_architecture.py
Hand-placed layout; edit the coordinates below, not the SVG output.
"""
from html import escape
from pathlib import Path

THEMES = {
    "light": dict(bg="#ffffff", frame="#e2e8f0", group="#f8fafc", groupline="#cbd5e1",
                  box="#ffffff", boxline="#cbd5e1", title="#0f172a", text="#1e293b",
                  sub="#64748b", label="#475569", brand="#1f66f1", brandsoft="#eaf1fe",
                  out="#64748b", danger="#dc2626", dangersoft="#fef2f2"),
    "dark": dict(bg="#0b1220", frame="#1e293b", group="#0f172a", groupline="#334155",
                 box="#111a2e", boxline="#334155", title="#f8fafc", text="#e2e8f0",
                 sub="#94a3b8", label="#94a3b8", brand="#4d8bff", brandsoft="#132544",
                 out="#94a3b8", danger="#f05252", dangersoft="#2a1215"),
}

W, H = 1280, 660
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


def render(t):
    o = []
    a = o.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
      f'role="img" aria-label="ssh-mcp architecture: agents call the ssh-mcp server, which checks identity and '
      f'policy, then runs typed tools on the target through a forced helper, or free-form search in a '
      f'no-network sandbox over a read-only mirror. Output is redacted and every call is audited.">')
    a(f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      f'<path d="M0 0L10 5L0 10z" fill="{t["brand"]}"/></marker>'
      f'<marker id="ao" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      f'<path d="M0 0L10 5L0 10z" fill="{t["out"]}"/></marker></defs>')
    a(f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="16" fill="{t["bg"]}" stroke="{t["frame"]}"/>')

    # Title + legend
    a(f'<text x="32" y="40" font-family="{MONO}" font-size="18" font-weight="700" fill="{t["title"]}">ssh-mcp · architecture</text>')
    lx = 880
    a(f'<line x1="{lx}" y1="34" x2="{lx+34}" y2="34" stroke="{t["brand"]}" stroke-width="2" marker-end="url(#ah)"/>')
    a(f'<text x="{lx+44}" y="39" font-family="{SANS}" font-size="13" fill="{t["label"]}">request</text>')
    a(f'<line x1="{lx+120}" y1="34" x2="{lx+154}" y2="34" stroke="{t["out"]}" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#ao)"/>')
    a(f'<text x="{lx+164}" y="39" font-family="{SANS}" font-size="13" fill="{t["label"]}">output / record</text>')

    def group(x, y, w, h, title):
        a(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{t["group"]}" stroke="{t["groupline"]}"/>')
        a(f'<text x="{x+18}" y="{y+28}" font-family="{MONO}" font-size="12" font-weight="700" letter-spacing="1.5" fill="{t["sub"]}">{escape(title.upper())}</text>')

    def box(x, y, w, h, title, lines=(), accent=False, danger=False, tsize=15):
        fill = t["brandsoft"] if accent else (t["dangersoft"] if danger else t["box"])
        line = t["brand"] if accent else (t["danger"] if danger else t["boxline"])
        a(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{line}" stroke-width="{1.5 if accent or danger else 1}"/>')
        n = len(lines)
        block = tsize + 6 + n * 17
        ty = y + (h - block) / 2 + tsize
        a(f'<text x="{x+w/2}" y="{ty:.0f}" text-anchor="middle" font-family="{SANS}" font-size="{tsize}" font-weight="650" fill="{t["text"]}">{escape(title)}</text>')
        for i, ln in enumerate(lines):
            a(f'<text x="{x+w/2}" y="{ty+22+i*17:.0f}" text-anchor="middle" font-family="{SANS}" font-size="12.5" fill="{t["sub"]}">{escape(ln)}</text>')

    def path(pts, out=False, label=None, lpos=None, anchor="middle"):
        d = "M" + " L".join(f"{x} {y}" for x, y in pts)
        col = t["out"] if out else t["brand"]
        dash = ' stroke-dasharray="5 4"' if out else ""
        mk = "ao" if out else "ah"
        a(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="2"{dash} stroke-linejoin="round" marker-end="url(#{mk})"/>')
        if label:
            x, y = lpos
            a(f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-family="{SANS}" font-size="12.5" font-weight="600" fill="{t["label"]}">{escape(label)}</text>')

    # Groups
    group(24, 64, 224, 572, "Callers")
    group(276, 64, 660, 572, "ssh-mcp server")
    group(964, 64, 292, 572, "Each Linux target")

    # Callers
    box(40, 122, 192, 72, "Claude Code / Desktop", ["people · OIDC"], tsize=14)
    box(40, 222, 192, 72, "Bots & CI agents", ["scoped bot tokens"], tsize=14)
    box(40, 548, 192, 72, "Admin console", ["review · stop · revoke"], tsize=14)

    # Server pipeline (column A)
    box(300, 122, 180, 72, "Authenticate", ["OIDC · hashed tokens"])
    box(300, 222, 180, 72, "Kill switch", ["per identity or all"])
    box(300, 322, 180, 72, "Policy", ["who × host tags × tool"], accent=True)
    path([(390, 194), (390, 222)])
    path([(390, 294), (390, 322)])

    # Lanes
    a(f'<text x="548" y="114" font-family="{MONO}" font-size="11" font-weight="700" letter-spacing="1.2" fill="{t["brand"]}">LIVE PATH · TYPED TOOLS</text>')
    box(548, 122, 364, 100, "Per-call SSH certificate", ["5-minute TTL · forced command · no pty or forwarding",
                                                          "path policy signed into the certificate"])
    a(f'<text x="600" y="306" font-family="{MONO}" font-size="11" font-weight="700" letter-spacing="1.2" fill="{t["brand"]}">SANDBOX PATH · FREE-FORM SEARCH</text>')
    box(600, 314, 160, 86, "bubblewrap", ["no network · no caps", "pids + memory capped"], tsize=14)
    box(784, 314, 128, 86, "sshfs mirror", ["read-only"], tsize=14)

    path([(480, 357), (600, 357)])                      # policy -> sandbox
    path([(520, 357), (520, 172), (548, 172)])          # policy -> live
    path([(760, 357), (784, 357)])                      # sandbox -> mirror

    # Output + audit bands
    box(300, 452, 612, 64, "Output pipeline", ["size cap  →  secret redaction  →  untrusted-data fence"])
    box(300, 548, 612, 72, "Audit log", ["every decision and result · hash-chained · append-only · HMAC-keyed",
                                         "output itself is never stored"])
    path([(572, 222), (572, 452)], out=True)            # live output
    path([(680, 400), (680, 452)], out=True)            # sandbox output
    path([(606, 516), (606, 548)], out=True)            # output -> audit
    path([(300, 484), (136, 484), (136, 294)], out=True, label="redacted results", lpos=(144, 476), anchor="start")
    path([(300, 584), (232, 584)], out=True)            # audit -> console

    # Callers -> server
    path([(232, 146), (300, 146)])
    path([(232, 258), (262, 258), (262, 180), (300, 180)])
    a(f'<text x="42" y="110" font-family="{SANS}" font-size="12.5" font-weight="600" fill="{t["label"]}">connect over MCP · HTTPS</text>')

    # Target
    box(980, 122, 260, 100, "agent-ro → ssh-mcp-helper", ["fixed argv per tool · no shell",
                                                          "symlink-safe reads · refuses root"], tsize=14)
    box(980, 314, 260, 86, "agent-sftp → helper --sftp", ["read-only SFTP", "denied paths do not exist"], tsize=14)
    path([(912, 172), (980, 172)])
    path([(912, 357), (980, 357)])
    a(f'<text x="982" y="112" font-family="{SANS}" font-size="12.5" font-weight="600" fill="{t["label"]}">SSH over SSM, direct or jump host</text>')
    a(f'<text x="982" y="304" font-family="{SANS}" font-size="12.5" font-weight="600" fill="{t["label"]}">SFTP over the same transport</text>')

    # sshd guarantees
    a(f'<rect x="980" y="440" width="260" height="180" rx="10" fill="{t["box"]}" stroke="{t["boxline"]}" stroke-dasharray="4 4"/>')
    a(f'<text x="998" y="470" font-family="{SANS}" font-size="14" font-weight="650" fill="{t["text"]}">Enforced by Linux + sshd</text>')
    for i, ln in enumerate(["non-root, no sudo, no password",
                            "helper forced for both users",
                            "certificates from this CA only",
                            "no pty · no forwarding · no agent",
                            "port 22 can stay closed (SSM)"]):
        a(f'<circle cx="1003" cy="{494+i*24}" r="3" fill="{t["brand"]}"/>')
        a(f'<text x="1014" y="{498+i*24}" font-family="{SANS}" font-size="12.5" fill="{t["sub"]}">{escape(ln)}</text>')

    a('</svg>')
    return "\n".join(o) + "\n"


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    for name, theme in THEMES.items():
        (here / f"architecture-{name}.svg").write_text(render(theme))
        print(f"wrote architecture-{name}.svg")
