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
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && !toggle.contains(e.target)) {
        sidebar.classList.remove("open");
      }
    });
  }

  // Desktop sidebar icon-only mode (el panel nunca se oculta, solo se angosta)
  const iconToggle = document.getElementById("sidebarIconToggle");
  if (iconToggle && sidebar) {
    const ICON_MODE_KEY = "wn-sidebar-icon-mode";
    const setIcon = (isIconMode) => {
      iconToggle.querySelector("i").className = isIconMode
        ? "bi bi-chevron-double-right"
        : "bi bi-chevron-double-left";
      iconToggle.title = isIconMode ? "Expandir menú" : "Reducir menú a iconos";
    };
    const startsIconMode = localStorage.getItem(ICON_MODE_KEY) === "1";
    sidebar.classList.toggle("icon-mode", startsIconMode);
    setIcon(startsIconMode);
    iconToggle.addEventListener("click", () => {
      const isIconMode = sidebar.classList.toggle("icon-mode");
      localStorage.setItem(ICON_MODE_KEY, isIconMode ? "1" : "0");
      setIcon(isIconMode);
    });

    // Tooltip con el nombre completo de cada ítem, solo visible en modo iconos.
    const tooltip = document.createElement("div");
    tooltip.className = "sidebar-icon-tooltip";
    document.body.appendChild(tooltip);
    sidebar.querySelectorAll(".nav-link-item").forEach((link) => {
      const label = link.querySelector("span");
      if (!label) return;
      link.addEventListener("mouseenter", () => {
        if (!sidebar.classList.contains("icon-mode")) return;
        const rect = link.getBoundingClientRect();
        tooltip.textContent = label.textContent;
        tooltip.style.left = `${rect.right + 10}px`;
        tooltip.style.top = `${rect.top + rect.height / 2}px`;
        tooltip.classList.add("show");
      });
      link.addEventListener("mouseleave", () => tooltip.classList.remove("show"));
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
