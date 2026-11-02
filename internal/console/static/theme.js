// Applied before first paint so there is no theme flash.
(function () {
  var t = localStorage.getItem("ssh-mcp-theme");
  if (!t) t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", t);
})();
