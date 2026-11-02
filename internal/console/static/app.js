// ssh-mcp console behaviour. No inline JS anywhere, so the CSP can forbid it.
(() => {
  const $ = (s, el = document) => el.querySelector(s);

  // Confirm destructive forms.
  document.addEventListener("submit", (e) => {
    const msg = e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Clickable rows and list items.
  document.addEventListener("click", (e) => {
    if (e.target.closest("a,button,input,form,select,label")) return;
    const row = e.target.closest("[data-href]");
    if (row) window.location = row.getAttribute("data-href");
  });

  // Theme toggle.
  document.addEventListener("click", (e) => {
    if (!e.target.closest("[data-theme-toggle]")) return;
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("ssh-mcp-theme", next);
  });

  // Chart tooltips (data-tip on hit targets).
  const tip = $("[data-tooltip]");
  document.addEventListener("mousemove", (e) => {
    const t = e.target.closest("[data-tip]");
    if (!t) { tip.hidden = true; return; }
    tip.textContent = t.getAttribute("data-tip");
    tip.hidden = false;
    const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 12);
    tip.style.left = x + "px";
    tip.style.top = (e.clientY - tip.offsetHeight - 12) + "px";
  });

  // Command palette.
  const pal = $("[data-palette]"), input = $("[data-palette-input]"), list = $("[data-palette-list]");
  let items = [];
  try { items = JSON.parse($("#palette-data").textContent || "[]") || []; } catch (_) {}
  let sel = 0, shown = [];
  const score = (q, s) => {
    s = s.toLowerCase();
    if (!q) return 1;
    const i = s.indexOf(q);
    if (i >= 0) return 100 - i;
    let p = 0;
    for (const ch of q) { p = s.indexOf(ch, p); if (p < 0) return 0; p++; }
    return 10;
  };
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    shown = items.map((it) => [score(q, it.l + " " + it.h), it]).filter((x) => x[0] > 0)
      .sort((a, b) => b[0] - a[0]).slice(0, 12).map((x) => x[1]);
    sel = Math.min(sel, Math.max(shown.length - 1, 0));
    list.replaceChildren(...(shown.length ? shown.map((it, i) => {
      const li = document.createElement("li");
      if (i === sel) li.className = "on";
      const a = document.createElement("span"); a.textContent = it.l;
      const b = document.createElement("small"); b.textContent = it.h;
      li.append(a, b);
      li.addEventListener("click", () => (window.location = it.u));
      li.addEventListener("mousemove", () => { if (sel !== i) { sel = i; draw(); } });
      return li;
    }) : [Object.assign(document.createElement("li"), { className: "none", textContent: "No matches" })]));
  };
  const open = () => { pal.hidden = false; input.value = ""; sel = 0; draw(); input.focus(); };
  const close = () => { pal.hidden = true; };
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-palette-open]")) open();
    else if (e.target === pal) close();
  });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); pal.hidden ? open() : close(); return; }
    if (e.key === "/" && pal.hidden && !e.target.closest("input,textarea")) { e.preventDefault(); open(); return; }
    if (pal.hidden) return;
    if (e.key === "Escape") close();
    else if (e.key === "ArrowDown") { sel = Math.min(sel + 1, shown.length - 1); draw(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
    else if (e.key === "Enter" && shown[sel]) window.location = shown[sel].u;
  });
  input.addEventListener("input", () => { sel = 0; draw(); });

  // Live updates: re-fetch the page and swap <main> in place, unless the
  // user is typing, has the palette open, or paused it.
  const live = $("[data-live-indicator]");
  const enabled = document.body.dataset.live === "1";
  let paused = localStorage.getItem("ssh-mcp-live") === "off";
  if (!enabled) live.hidden = true;
  const paint = () => { live.classList.toggle("paused", paused); live.lastChild.textContent = paused ? "Paused" : "Live"; };
  paint();
  live.addEventListener("click", () => { paused = !paused; localStorage.setItem("ssh-mcp-live", paused ? "off" : "on"); paint(); });
  const busy = () => !pal.hidden || (document.activeElement && document.activeElement.closest("main input, main select")) || document.hidden;
  if (enabled) setInterval(async () => {
    if (paused || busy()) return;
    try {
      const res = await fetch(location.href, { credentials: "same-origin", cache: "no-store" });
      if (!res.ok) return;
      const doc = new DOMParser().parseFromString(await res.text(), "text/html");
      const next = doc.getElementById("content");
      if (next && !busy()) {
        $("#content").replaceWith(next);
        live.classList.add("flash");
        setTimeout(() => live.classList.remove("flash"), 600);
      }
    } catch (_) {}
  }, 10000);
})();
