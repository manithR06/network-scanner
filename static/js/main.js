// ── Auto-hide alerts after 5 seconds ─────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
  // Auto hide flash alerts
  setTimeout(function () {
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach(function (alert) {
      alert.style.transition = "opacity 0.5s";
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 500);
    });
  }, 5000);

  // Highlight active nav link
  const currentPath = window.location.pathname;
  document.querySelectorAll(".nav-link").forEach((link) => {
    if (link.getAttribute("href") === currentPath) {
      link.classList.add("active");
    }
  });

  // Add loading spinner to any form button on click
  document.querySelectorAll('button[type="submit"]').forEach((btn) => {
    btn.addEventListener("click", function () {
      const original = btn.innerHTML;
      btn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
      btn.disabled = true;
      setTimeout(() => {
        btn.innerHTML = original;
        btn.disabled = false;
      }, 10000);
    });
  });
});

// ── Format numbers with commas ────────────────────────────────────
function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// ── Copy text to clipboard ────────────────────────────────────────
function copyToClipboard(text) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      showToast("Copied to clipboard!", "success");
    })
    .catch(() => {
      showToast("Failed to copy", "danger");
    });
}

// ── Show a toast notification ─────────────────────────────────────
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `alert alert-${type} position-fixed`;
  toast.style.cssText =
    "bottom:20px; right:20px; z-index:9999; min-width:200px;";
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.5s";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 500);
  }, 3000);
}

// ── Confirm before deleting anything ─────────────────────────────
function confirmDelete(message) {
  return confirm(message || "Are you sure you want to delete this?");
}

// ── Format date string nicely ─────────────────────────────────────
function formatDate(dateStr) {
  if (!dateStr) return "-";
  const d = new Date(dateStr);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString();
}

// ── Get risk badge HTML ───────────────────────────────────────────
function getRiskBadge(level) {
  const colors = {
    critical: "danger",
    high: "warning",
    medium: "info",
    low: "success",
  };
  const color = colors[level.toLowerCase()] || "secondary";
  return `<span class="badge bg-${color}">${level.toUpperCase()}</span>`;
}
EOF;
