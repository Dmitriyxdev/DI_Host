// static/js/app.js
(() => {
  "use strict";

  // ---- iOS: disable double-tap zoom (Smart Zoom) ----
  (() => {
    let lastTouchEnd = 0;

    document.addEventListener(
      "touchend",
      (e) => {
        const t = e.target;
        if (t && (t.closest("input, textarea, select") || t.isContentEditable)) return;

        const now = Date.now();
        if (now - lastTouchEnd <= 300) e.preventDefault();
        lastTouchEnd = now;
      },
      { passive: false }
    );
  })();

  const $ = (sel) => document.querySelector(sel);

  // ---- footer year ----
  const yearEl = $("#year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  // ---- dropdown (settings) ----
  const dropdown = $("#settingsDropdown");
  const dropdownBtn = dropdown?.querySelector(".dropdown-toggle");

  function setDropdownOpen(isOpen) {
    if (!dropdown || !dropdownBtn) return;
    dropdown.classList.toggle("is-open", isOpen);
    dropdownBtn.setAttribute("aria-expanded", String(isOpen));
  }

  if (dropdown && dropdownBtn) {
    dropdownBtn.addEventListener("click", (e) => {
      e.preventDefault();
      setDropdownOpen(!dropdown.classList.contains("is-open"));
    });

    document.addEventListener("click", (e) => {
      if (!dropdown.contains(e.target)) setDropdownOpen(false);
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") setDropdownOpen(false);
    });
  }
})();
