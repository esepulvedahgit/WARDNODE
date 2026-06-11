/**
 * wnPasswordPolicy() — factory Alpine.js para el medidor de fortaleza.
 * Los 5 requisitos deben coincidir exactamente con password_policy.py.
 * Uso: <form x-data="wnPasswordPolicy()"> ... </form>
 */
function wnPasswordPolicy() {
  return {
    pw: "",
    confirm: "",
    reqs: [
      { id: "length", label: "Al menos 12 caracteres",  re: (v) => v.length >= 12 },
      { id: "upper",  label: "Una letra mayúscula",      re: (v) => /[A-Z]/.test(v) },
      { id: "lower",  label: "Una letra minúscula",      re: (v) => /[a-z]/.test(v) },
      { id: "digit",  label: "Un número",                re: (v) => /\d/.test(v) },
      { id: "symbol", label: "Un símbolo (!@#$%^&*…)",   re: (v) => /[^A-Za-z0-9]/.test(v) },
    ],
    get score()  { return this.reqs.filter((r) => r.re(this.pw)).length; },   // 0‒5
    get match()  { return this.pw.length > 0 && this.pw === this.confirm; },
    get allOk()  { return this.score === this.reqs.length && this.match; },
    get level() {
      if (!this.pw)          return { label: "—",         cls: "is-empty"  };
      if (this.score <= 2)   return { label: "Débil",     cls: "is-weak"   };
      if (this.score === 3)  return { label: "Aceptable", cls: "is-fair"   };
      if (this.score === 4)  return { label: "Buena",     cls: "is-good"   };
      return                        { label: "Fuerte",    cls: "is-strong" };
    },
  };
}

document.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("js-ready");

  // Mobile sidebar toggle
  const toggle  = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
    document.addEventListener("click", (e) => {
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && e.target !== toggle) {
        sidebar.classList.remove("open");
      }
    });
  }
});

document.body.addEventListener("htmx:configRequest", (event) => {
  const method = event.detail.verb.toUpperCase();
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    return;
  }

  const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
  if (csrfToken) {
    event.detail.headers["X-CSRFToken"] = csrfToken;
  }
});
