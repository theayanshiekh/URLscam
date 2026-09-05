document.addEventListener("DOMContentLoaded", () => {
  // Tab Switching
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanels.forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.getAttribute("data-tab");
      document.getElementById(target).classList.add("active");
    });
  });

  // Presets
  const urlInput = document.getElementById("target-url");
  document.querySelectorAll(".chip").forEach(chip => {
    chip.addEventListener("click", () => {
      urlInput.value = chip.getAttribute("data-url");
      document.getElementById("single-scan-form").dispatchEvent(new Event("submit"));
    });
  });

  // Single URL Scan
  const singleForm = document.getElementById("single-scan-form");
  const singleResult = document.getElementById("single-result");
  const btnScan = document.getElementById("btn-scan");

  singleForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    btnScan.querySelector(".btn-text").textContent = "Analyzing...";
    btnScan.disabled = true;

    try {
      const resp = await fetch("/api/v1/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, include_features: true, include_explainability: true })
      });

      const data = await resp.json();
      if (!resp.ok) {
        alert(data.message || "Error analyzing URL");
        return;
      }

      renderSingleResult(data);
    } catch (err) {
      alert("Network error contacting detection API: " + err.message);
    } finally {
      btnScan.querySelector(".btn-text").textContent = "Analyze URL";
      btnScan.disabled = false;
    }
  });

  function renderSingleResult(data) {
    singleResult.classList.remove("hidden");

    // Verdict & Badge
    const levelBadge = document.getElementById("res-level-badge");
    levelBadge.textContent = data.risk_level || (data.is_flagged ? "DANGEROUS" : "SAFE");
    levelBadge.className = "risk-badge risk-" + (data.risk_level ? data.risk_level.toLowerCase() : (data.is_flagged ? "critical" : "safe"));

    document.getElementById("res-verdict").textContent = data.verdict || (data.is_flagged ? "SUSPICIOUS / FRAUD" : "CLEAN");
    document.getElementById("res-url").textContent = data.url;
    document.getElementById("res-advice").textContent = data.recommendation || "No immediate action required.";
    document.getElementById("res-latency").textContent = data.latency_ms || 0;

    // Gauge
    const probPct = Math.round(data.probability * 100);
    const gauge = document.getElementById("gauge-circle");
    document.getElementById("gauge-score").textContent = probPct + "%";
    
    if (data.is_flagged || probPct >= 74) {
      gauge.style.borderColor = "var(--danger)";
      gauge.style.color = "var(--danger)";
    } else if (probPct >= 45) {
      gauge.style.borderColor = "var(--warning)";
      gauge.style.color = "var(--warning)";
    } else {
      gauge.style.borderColor = "var(--success)";
      gauge.style.color = "var(--success)";
    }

    // Indicators
    const indContainer = document.getElementById("indicators-list");
    indContainer.innerHTML = "";
    const indicators = data.indicators || [];
    document.getElementById("ind-count").textContent = indicators.length;

    if (indicators.length === 0) {
      indContainer.innerHTML = "<p style='color: var(--text-secondary); font-size: 0.85rem;'>No elevated threat heuristics flagged.</p>";
    } else {
      indicators.forEach(ind => {
        const card = document.createElement("div");
        card.className = `indicator-card severity-${ind.severity}`;
        card.innerHTML = `
          <div class="ind-title">${ind.title}</div>
          <div class="ind-desc">${ind.description}</div>
        `;
        indContainer.appendChild(card);
      });
    }

    // Features Table
    const tbody = document.getElementById("features-tbody");
    tbody.innerHTML = "";
    if (data.features) {
      Object.entries(data.features).forEach(([key, val]) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${key}</code></td>
          <td><strong>${val}</strong></td>
          <td style="color: var(--text-secondary); font-size: 0.8rem;">${describeFeature(key, val)}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  function describeFeature(name, val) {
    const descriptions = {
      url_length: "Total character count in full URL string",
      domain_length: "Character count of parsed hostname",
      path_length: "Character count of URI path",
      query_length: "Character count of query parameters",
      num_dots: "Total periods (subdomains, extensions)",
      num_hyphens: "Total hyphens (often used for brand impersonation)",
      num_underscores: "Total underscore characters",
      num_slashes: "Total slash delimiters in path",
      num_digits: "Raw count of numeric digits across URL",
      num_special_chars: "Special symbol count (!*();:@&=+$,?%#[])",
      num_params: "Number of query parameter keys",
      num_subdomains: "Subdomain hierarchy depth",
      digit_ratio: "Proportion of URL characters that are numeric digits",
      special_char_ratio: "Proportion of URL characters that are special symbols",
      shannon_entropy: "Information randomness metric (DGA/random strings)",
      has_ip_address: "1 if host is a raw IPv4 address, 0 otherwise",
      has_https: "1 if scheme is secure HTTPS, 0 otherwise",
      has_at_symbol: "1 if '@' delimiter is present (credential spoofing)",
      has_double_slash: "1 if redundant '//' occurs in path",
      has_shortener: "1 if hostname is a known shortener (bit.ly, etc.)",
      suspicious_word_count: "Count of sensitive keywords (login, verify, bank, etc.)",
      starts_with_https: "1 if URL begins with 'https', 0 otherwise",
      hostname_has_digits: "1 if hostname contains digits, 0 otherwise",
      tld_length: "Character count of Top-Level Domain suffix",
    };
    return descriptions[name] || "";
  }

  // Toggle Features Accordion
  const toggleFeaturesBtn = document.getElementById("toggle-features-btn");
  const featuresTableContainer = document.getElementById("features-table-container");
  toggleFeaturesBtn.addEventListener("click", () => {
    featuresTableContainer.classList.toggle("hidden");
    const isHidden = featuresTableContainer.classList.contains("hidden");
    toggleFeaturesBtn.querySelector(".arrow").textContent = isHidden ? "▼" : "▲";
  });

  // Batch Scanner
  const batchForm = document.getElementById("batch-scan-form");
  const btnBatchScan = document.getElementById("btn-batch-scan");
  const batchSummary = document.getElementById("batch-summary");
  const batchResults = document.getElementById("batch-results-container");
  const batchTbody = document.getElementById("batch-tbody");

  batchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawText = document.getElementById("batch-urls-input").value;
    const urls = rawText.split("\n").map(u => u.trim()).filter(u => u.length > 0);

    if (urls.length === 0) {
      alert("Please enter at least one URL to scan.");
      return;
    }

    btnBatchScan.textContent = `Scanning ${urls.length} URLs...`;
    btnBatchScan.disabled = true;

    try {
      const resp = await fetch("/api/v1/check-urls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls, include_explainability: true })
      });
      const data = await resp.json();
      if (!resp.ok) {
        alert(data.message || "Batch scan failed");
        return;
      }

      renderBatchResults(data);
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      btnBatchScan.textContent = "Scan Batch Matrix";
      btnBatchScan.disabled = false;
    }
  });

  document.getElementById("btn-clear-batch").addEventListener("click", () => {
    document.getElementById("batch-urls-input").value = "";
    batchSummary.classList.add("hidden");
    batchResults.classList.add("hidden");
  });

  function renderBatchResults(data) {
    batchSummary.classList.remove("hidden");
    batchResults.classList.remove("hidden");

    const summary = data.summary || {};
    document.getElementById("b-metric-total").textContent = summary.total || 0;
    document.getElementById("b-metric-flagged").textContent = summary.flagged_count || 0;
    document.getElementById("b-metric-clean").textContent = summary.safe_count || 0;
    document.getElementById("b-metric-avg").textContent = Math.round((summary.avg_probability || 0) * 100) + "%";

    batchTbody.innerHTML = "";
    (data.results || []).forEach(res => {
      const tr = document.createElement("tr");
      const badgeClass = res.risk_level ? res.risk_level.toLowerCase() : (res.is_flagged ? "critical" : "safe");
      tr.innerHTML = `
        <td><span class="badge ${res.is_flagged ? 'badge-danger' : 'badge-success'}">${res.is_flagged ? 'FLAGGED' : 'CLEAN'}</span></td>
        <td><span class="risk-badge risk-${badgeClass}">${res.risk_level || 'UNKNOWN'}</span></td>
        <td><strong>${Math.round(res.probability * 100)}%</strong></td>
        <td><code style="word-break: break-all;">${res.url}</code></td>
        <td style="color: var(--text-secondary); font-size: 0.8rem;">${(res.indicators || []).map(i => i.title).join(", ") || "None"}</td>
      `;
      batchTbody.appendChild(tr);
    });
  }

  // Feedback Modal
  const modal = document.getElementById("feedback-modal");
  const btnOpenFeedback = document.getElementById("btn-open-feedback");
  const closeModal = document.getElementById("close-modal");
  const feedbackForm = document.getElementById("feedback-form");

  btnOpenFeedback.addEventListener("click", () => {
    document.getElementById("fb-url").value = urlInput.value;
    modal.classList.remove("hidden");
  });

  closeModal.addEventListener("click", () => modal.classList.add("hidden"));
  window.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });

  feedbackForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = document.getElementById("fb-url").value;
    const reported_as = document.getElementById("fb-type").value;
    const notes = document.getElementById("fb-notes").value;

    try {
      const resp = await fetch("/api/v1/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, reported_as, notes })
      });
      const res = await resp.json();
      if (resp.ok) {
        alert("Thank you! Feedback recorded for model retraining.");
        modal.classList.add("hidden");
        document.getElementById("fb-notes").value = "";
      } else {
        alert(res.message || "Error submitting feedback");
      }
    } catch (err) {
      alert("Error: " + err.message);
    }
  });
});
