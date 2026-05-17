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
