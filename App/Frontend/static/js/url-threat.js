/* ===== URL Threat Detection v3.0 — Page JavaScript ===== */
document.addEventListener("DOMContentLoaded", function () {

  /* ── Form loading state ── */
  var form = document.getElementById("urlScanForm");
  if (form) {
    form.addEventListener("submit", function () {
      var loading = document.getElementById("loadingIndicator");
      var btn     = document.getElementById("submitBtn");
      if (loading) loading.style.display = "block";
      if (btn) {
        btn.disabled = true;
        btn.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> <span>Scanning\u2026</span>';
      }
    });
  }

  /* ── URL format hint ── */
  var urlInput   = document.getElementById("url");
  var formatHint = document.getElementById("formatHint");
  if (urlInput && formatHint) {
    urlInput.addEventListener("input", function () {
      var v = urlInput.value.trim();
      if (!v) { formatHint.style.display = "none"; return; }
      formatHint.style.display = "flex";
      var ok =
        /^(https?:\/\/)?[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+/.test(v) ||
        /^(https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(v);
      formatHint.className = "format-hint " + (ok ? "valid" : "invalid");
      formatHint.innerHTML = ok
        ? '<i class="fas fa-check-circle"></i> Valid URL format'
        : '<i class="fas fa-info-circle"></i> Enter a valid URL (e.g. example.com)';
    });
  }

  /* ── Threat gauge arc animation ── */
  var arc = document.getElementById("threatArc");
  if (arc) {
    var score = parseFloat(arc.getAttribute("data-threat-score") || "0");
    var total = parseFloat(arc.style.strokeDasharray) || 264;
    var offset = total - (score / 100) * total;
    setTimeout(function () { arc.style.strokeDashoffset = offset; }, 300);
  }

  /* ── Animated score counter ── */
  var gaugeValue = document.querySelector(".threat-gauge-value");
  if (gaugeValue) {
    var target = parseInt(gaugeValue.getAttribute("data-score") || "0", 10);
    if (target > 0) {
      var startVal  = 0;
      var duration  = 1200;
      var startTime = null;
      function animateCounter(ts) {
        if (!startTime) startTime = ts;
        var elapsed  = ts - startTime;
        var progress = Math.min(elapsed / duration, 1);
        var ease     = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        gaugeValue.textContent = Math.round(startVal + (target - startVal) * ease);
        if (progress < 1) requestAnimationFrame(animateCounter);
      }
      setTimeout(function () { requestAnimationFrame(animateCounter); }, 400);
    }
  }

  /* ── Component bar animations ── */
  var bars = document.querySelectorAll(".comp-bar-fill[data-width]");
  bars.forEach(function (bar, i) {
    setTimeout(function () {
      bar.style.width = bar.getAttribute("data-width") + "%";
    }, 600 + i * 120);
  });

  /* ── Confidence bar animations (model cards) ── */
  var confBars = document.querySelectorAll(".confidence-fill[data-width]");
  confBars.forEach(function (bar, i) {
    setTimeout(function () {
      bar.style.width = bar.getAttribute("data-width") + "%";
    }, 800 + i * 150);
  });

  /* ── Age bar animation ── */
  var ageBars = document.querySelectorAll(".age-bar-fill[data-width]");
  ageBars.forEach(function (bar) {
    setTimeout(function () {
      bar.style.width = bar.getAttribute("data-width") + "%";
    }, 700);
  });

  /* ── Scroll to results ── */
  var resultsSection = document.querySelector(".results-section");
  if (resultsSection) {
    setTimeout(function () {
      resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 200);
  }

  /* ── Error banner scroll ── */
  var errorBanner = document.querySelector(".error-banner");
  if (errorBanner && !resultsSection) {
    setTimeout(function () {
      errorBanner.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 200);
  }

});
