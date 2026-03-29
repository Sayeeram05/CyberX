/* ===== Email Validation v3.0 — Page JavaScript ===== */

document.addEventListener("DOMContentLoaded", function () {
  // ── Form loading state ──────────────────────────────────
  var form = document.getElementById("emailValidationForm");
  if (form) {
    form.addEventListener("submit", function () {
      var loader = document.getElementById("loadingIndicator");
      var btn = document.getElementById("submitBtn");
      if (loader) loader.style.display = "block";
      if (btn) {
        btn.disabled = true;
        btn.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> <span>Validating\u2026</span>';
      }
    });

    // Real-time format hint
    var emailInput = document.getElementById("email");
    if (emailInput) {
      var hintEl = document.getElementById("formatHint");
      emailInput.addEventListener("input", function () {
        var val = emailInput.value.trim();
        if (!hintEl || !val) {
          if (hintEl) hintEl.style.display = "none";
          return;
        }
        var pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (val.length > 3 && val.includes("@")) {
          hintEl.style.display = "flex";
          if (pattern.test(val)) {
            hintEl.className = "format-hint valid";
            hintEl.innerHTML =
              '<i class="fas fa-check-circle"></i> <span>Valid format</span>';
          } else {
            hintEl.className = "format-hint invalid";
            hintEl.innerHTML =
              '<i class="fas fa-info-circle"></i> <span>Check format: user@domain.com</span>';
          }
        } else {
          hintEl.style.display = "none";
        }
      });
    }
  }

  // ── Risk-gauge arc animation ────────────────────────────
  var arc = document.getElementById("riskArc");
  if (arc) {
    var score = parseFloat(arc.getAttribute("data-risk-score")) || 0;
    var total = 236; // half-circle arc length
    var offset = total - (score / 100) * total;
    setTimeout(function () {
      arc.style.strokeDashoffset = offset;
    }, 300);
  }

  // ── Animated score counter ──────────────────────────────
  var gaugeValue = document.querySelector(".risk-gauge-value");
  if (gaugeValue) {
    var targetScore = parseFloat(gaugeValue.getAttribute("data-score")) || 0;
    var current = 0;
    var duration = 1200;
    var startTime = null;

    function animateScore(timestamp) {
      if (!startTime) startTime = timestamp;
      var progress = Math.min((timestamp - startTime) / duration, 1);
      // ease-out cubic
      var eased = 1 - Math.pow(1 - progress, 3);
      current = Math.round(eased * targetScore);
      gaugeValue.textContent = current;
      if (progress < 1) {
        requestAnimationFrame(animateScore);
      }
    }

    setTimeout(function () {
      requestAnimationFrame(animateScore);
    }, 200);
  }

  // ── Component-bar width animation (staggered) ──────────
  var bars = document.querySelectorAll(".comp-bar-fill");
  bars.forEach(function (bar, i) {
    var targetWidth = bar.getAttribute("data-width");
    if (targetWidth) {
      bar.style.width = "0%";
      setTimeout(function () {
        bar.style.width = targetWidth + "%";
      }, 400 + i * 120);
    }
  });

  // ── Confidence ring animation ───────────────────────────
  var rings = document.querySelectorAll(".ring-fill");
  rings.forEach(function (ring) {
    var pct = parseFloat(ring.getAttribute("data-percent")) || 0;
    var circumference = 2 * Math.PI * 20; // r=20
    var offset = circumference - (pct / 100) * circumference;
    ring.style.strokeDasharray = circumference;
    ring.style.strokeDashoffset = circumference;
    setTimeout(function () {
      ring.style.strokeDashoffset = offset;
    }, 400);
  });

  // ── Scroll to results if present ────────────────────────
  var resultsSection = document.querySelector(".results-section");
  if (resultsSection) {
    setTimeout(function () {
      resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 200);
  }

  // ── Error banner auto-scroll ────────────────────────────
  var errorBanner = document.querySelector(".error-banner");
  if (errorBanner && !resultsSection) {
    setTimeout(function () {
      errorBanner.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 200);
  }
});
