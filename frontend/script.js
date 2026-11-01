/**
 * ThreatLens -- Frontend Logic
 * Handles scan requests, result rendering, feature display, history management.
 * Preserves all original API/localStorage behaviour; extends for new UI interactions.
 */

// -- Config --
const API_BASE    = window.location.origin;
const PREDICT_URL = `${API_BASE}/api/v1/predict`;
const HISTORY_KEY   = "threatlens_history";
const HISTORY_LIMIT = 10;

// Migrate legacy localStorage key from previous branding
(function migrateLegacyHistory() {
  const legacy = localStorage.getItem("urlshield_history");
  if (legacy && !localStorage.getItem("threatlens_history")) {
    localStorage.setItem("threatlens_history", legacy);
    localStorage.removeItem("urlshield_history");
  }
})();

// -- Feature display metadata --
const FEATURE_META = {
  URLLength:                  { label: "URL Length",      unit: "chars",  maxRef: 200, warnHigh: true },
  DomainLength:               { label: "Domain Length",   unit: "chars",  maxRef: 60,  warnHigh: false },
  TLDLength:                  { label: "TLD Length",      unit: "chars",  maxRef: 10,  warnHigh: false },
  NoOfSubDomain:              { label: "Subdomains",      unit: "",       maxRef: 5,   warnHigh: true },
  IsHTTPS:                    { label: "HTTPS",           unit: "",       binary: true, positiveVal: 1 },
  URLEntropy:                 { label: "URL Entropy",     unit: "bits",   maxRef: 6,   warnHigh: true },
  DomainEntropy:              { label: "Domain Entropy",  unit: "bits",   maxRef: 5,   warnHigh: true },
  NoOfDegitsInURL:            { label: "Digits in URL",   unit: "",       maxRef: 20,  warnHigh: true },
  DigitRatioInURL:            { label: "Digit Ratio",     unit: "",       maxRef: 0.5, warnHigh: true, isRatio: true },
  NoOfHyphensInURL:           { label: "Hyphens",         unit: "",       maxRef: 8,   warnHigh: true },
  NoOfOtherSpecialCharsInURL: { label: "Special Chars",   unit: "",       maxRef: 10,  warnHigh: true },
  IsIPAddress:                { label: "IP Address",      unit: "",       binary: true, positiveVal: 0 },
  HasPunycode:                { label: "Punycode",        unit: "",       binary: true, positiveVal: 0 },
  IsSuspiciousTLD:            { label: "Suspicious TLD",  unit: "",       binary: true, positiveVal: 0 },
  SuspiciousKeywordCount:     { label: "Phish Keywords",  unit: "",       maxRef: 5,   warnHigh: true },
  BrandInSubdomain:           { label: "Brand Spoof",     unit: "",       binary: true, positiveVal: 0 },
  HasAtSign:                  { label: "@ Sign",          unit: "",       binary: true, positiveVal: 0 },
  HasHexEncoding:             { label: "Hex Encoding",    unit: "",       binary: true, positiveVal: 0 },
  URLDepth:                   { label: "URL Depth",       unit: "levels", maxRef: 8,   warnHigh: false },
  NoOfEqualsInURL:            { label: "= Signs",         unit: "",       maxRef: 6,   warnHigh: false },
  NoOfQMarkInURL:             { label: "Query Marks",     unit: "",       maxRef: 3,   warnHigh: false },
  NoOfAmpersandInURL:         { label: "& Signs",         unit: "",       maxRef: 5,   warnHigh: false },
};

// -- DOM refs --
const $ = id => document.getElementById(id);

const urlInput        = $("urlInput");
const scanBtn         = $("scanBtn");
const scanStatusText  = $("scanStatusText");
const scanProgress    = $("scanProgress");
const resultsSection  = $("resultsArea");

const verdictBadge    = $("verdictBadge");
const scannedUrl      = $("scannedUrl");
const riskLevelVal    = $("riskLevelVal");
const confidenceVal   = $("confidenceVal");
const httpsVal        = $("httpsVal");
const verdictCard     = $("verdictCard");
const verdictSummary  = $("verdictSummary");

const cpFill          = $("cpFill");
const gaugePercent    = $("gaugePercent");
const riskBarFill     = $("riskBarFill");

const explanationsList = $("explanationsList");
const featuresGrid    = $("featuresGrid");
const historyList     = $("historyList");

// Progress step elements
const progressSteps = [1, 2, 3, 4, 5].map(i => $(`step${i}`));

// -- Circular progress circumference (r=50, approx 314.16) --
const CP_CIRCUMFERENCE = 2 * Math.PI * 50;

// -- Enter key --
urlInput.addEventListener("keydown", e => { if (e.key === "Enter") checkURL(); });

// -- Mobile menu --
const mobileMenuBtn = $("mobileMenuBtn");
const mobileMenu    = $("mobileMenu");

if (mobileMenuBtn && mobileMenu) {
  mobileMenuBtn.addEventListener("click", () => {
    const open = mobileMenu.classList.toggle("open");
    mobileMenuBtn.classList.toggle("open", open);
    mobileMenuBtn.setAttribute("aria-expanded", String(open));
    mobileMenu.setAttribute("aria-hidden", String(!open));
  });
  mobileMenu.querySelectorAll("a").forEach(a => {
    a.addEventListener("click", () => {
      mobileMenu.classList.remove("open");
      mobileMenuBtn.classList.remove("open");
      mobileMenuBtn.setAttribute("aria-expanded", "false");
      mobileMenu.setAttribute("aria-hidden", "true");
    });
  });
}

// -- Scroll into scanner section when CTA clicked --
document.querySelectorAll('a[href="#scanner"]').forEach(a => {
  a.addEventListener("click", e => {
    e.preventDefault();
    const target = document.querySelector("#scanner");
    if (target) { target.scrollIntoView({ behavior: "smooth" }); urlInput.focus(); }
  });
});

// -- DOMContentLoaded --
document.addEventListener("DOMContentLoaded", () => {
  renderHistory();
  const h = loadHistory();
  if (h.length > 0) {
    resultsSection.classList.add("visible");
    resultsSection.removeAttribute("aria-hidden");
  }
});

// ================================================================
// MAIN SCAN FUNCTION
// ================================================================
async function checkURL() {
  const url = urlInput.value.trim();

  if (!url) {
    urlInput.focus();
    const wrap = $("scannerFieldWrap");
    if (wrap) { wrap.style.borderColor = "var(--danger)"; setTimeout(() => (wrap.style.borderColor = ""), 1200); }
    return;
  }

  showResults();
  setScanningState(url);
  startProgressAnimation();

  try {
    const response = await fetch(PREDICT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server error ${response.status}`);
    }

    const data = await response.json();
    stopProgressAnimation(true);
    renderResult(url, data);
    addToHistory(url, data);
  } catch (err) {
    stopProgressAnimation(false);
    renderError(err.message);
    console.error("ThreatLens scan error:", err);
  }
}

// -- Show/hide results section --
function showResults() {
  resultsSection.classList.add("visible");
  resultsSection.removeAttribute("aria-hidden");
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 100);
}

// -- Animated progress steps --
let progressTimer = null;
const STEP_LABELS = [
  "Checking domain...",
  "Analyzing URL structure...",
  "Inspecting phishing indicators...",
  "Evaluating risk score...",
  "Generating explanation...",
];

function startProgressAnimation() {
  scanProgress.classList.add("visible");
  scanProgress.removeAttribute("aria-hidden");
  progressSteps.forEach(s => { s.className = "progress-step"; });

  let current = 0;
  activateStep(current);

  progressTimer = setInterval(() => {
    if (current < progressSteps.length - 1) {
      markStepDone(current);
      current++;
      activateStep(current);
      if (scanStatusText) scanStatusText.textContent = STEP_LABELS[current] || "Analyzing...";
    }
  }, 600);
}

function activateStep(i) {
  if (progressSteps[i]) progressSteps[i].classList.add("active");
}

function markStepDone(i) {
  if (progressSteps[i]) {
    progressSteps[i].classList.remove("active");
    progressSteps[i].classList.add("done");
  }
}

function stopProgressAnimation(success) {
  clearInterval(progressTimer);
  if (success) {
    progressSteps.forEach(s => { s.classList.remove("active"); s.classList.add("done"); });
  }
  setTimeout(() => {
    scanProgress.classList.remove("visible");
    scanProgress.setAttribute("aria-hidden", "true");
  }, 600);
}

// ================================================================
// STATE: SCANNING
// ================================================================
function setScanningState(url) {
  scanBtn.classList.add("loading");
  scanBtn.disabled = true;
  if (scanStatusText) scanStatusText.textContent = STEP_LABELS[0];

  verdictCard.className = "result-card verdict-card scanning-pulse";
  verdictBadge.textContent = "Scanning...";
  verdictBadge.className = "result-verdict-badge";

  scannedUrl.textContent = url;
  riskLevelVal.textContent = "--";
  confidenceVal.textContent = "--";
  httpsVal.textContent = "--";
  httpsVal.className = "meta-pill-val";
  verdictSummary.innerHTML = "Extracting URL features and running ML inference...";

  setCircularProgress(0);
  riskBarFill.style.width = "0%";
  gaugePercent.style.color = "";

  explanationsList.innerHTML = `<li class="expl-item expl-neutral"><span class="expl-dot"></span>Analysing URL patterns...</li>`;
  featuresGrid.innerHTML = `<div class="feat-placeholder">Extracting features...</div>`;
}

// ================================================================
// STATE: RESULT
// ================================================================
function renderResult(url, data) {
  scanBtn.classList.remove("loading");
  scanBtn.disabled = false;

  const pred  = (data.prediction || "safe").toLowerCase();
  const score = Math.max(0, Math.min(data.risk_score || 0, 1));
  const pct   = (score * 100).toFixed(1);

  // Verdict badge + header
  verdictCard.className = `result-card verdict-card state-${pred}`;
  verdictBadge.textContent = capitalise(pred);
  verdictBadge.className = `result-verdict-badge ${pred}`;

  scannedUrl.textContent = url;

  riskLevelVal.textContent = data.risk_level || "--";
  riskLevelVal.className = `meta-pill-val ${pred}`;

  confidenceVal.textContent = `${pct}%`;
  confidenceVal.className = `meta-pill-val ${pred}`;

  const isHttps = data.features && data.features.IsHTTPS === 1;
  httpsVal.textContent = isHttps ? "Yes (HTTPS)" : "No (HTTP)";
  httpsVal.className = `meta-pill-val ${isHttps ? "https-yes" : "https-no"}`;

  const summaries = {
    safe:       "<strong>No strong malicious signals detected.</strong> The URL structure looks normal. Always verify the sender and context before clicking.",
    suspicious: "<strong>Treat with caution.</strong> Multiple risk indicators detected. Verify the domain's legitimacy and avoid entering credentials.",
    malicious:  "<strong>High risk -- do not visit this URL.</strong> Strong phishing or malware delivery patterns detected. Do not enter personal data or download files.",
  };
  verdictSummary.innerHTML = summaries[pred] || summaries.safe;

  // Circular progress
  setCircularProgress(score * 100);
  gaugePercent.textContent = `${pct}%`;
  gaugePercent.style.color = scoreColor(score);
  riskBarFill.style.width = `${pct}%`;

  if (cpFill) {
    cpFill.style.stroke = scoreColor(score);
  }

  // Explanations
  const reasons = Array.isArray(data.reasons) ? data.reasons :
                  Array.isArray(data.explanations) ? data.explanations : [];

  explanationsList.innerHTML = reasons.length
    ? reasons.map((r, i) => {
        const text = String(r);
        const isPositive = /https|normal|low risk|no (strong|phishing|suspicious)/i.test(text);
        const isNegative = /phishing|malicious|risk|obfuscat|suspicious|danger|attack|ip address|punycode|brand/i.test(text);
        const cls = isPositive ? "expl-positive" : isNegative ? "expl-negative" : "expl-neutral";
        return `<li class="expl-item ${cls}" style="animation-delay:${i * 0.06}s"><span class="expl-dot"></span>${escapeHtml(text)}</li>`;
      }).join("")
    : `<li class="expl-placeholder">No explanation returned.</li>`;

  renderFeatures(data.features || {});
}

// ================================================================
// STATE: ERROR
// ================================================================
function renderError(message) {
  scanBtn.classList.remove("loading");
  scanBtn.disabled = false;

  verdictCard.className = "result-card verdict-card state-malicious";
  verdictBadge.textContent = "Error";
  verdictBadge.className = "result-verdict-badge malicious";
  verdictSummary.innerHTML = `<strong>Connection failed.</strong> ${escapeHtml(message || "Make sure the backend API is running.")}`;
  explanationsList.innerHTML = `<li class="expl-item expl-negative"><span class="expl-dot"></span>Backend unreachable -- start the API server and try again.</li>`;
  featuresGrid.innerHTML = `<div class="feat-placeholder">--</div>`;
}

// ================================================================
// CIRCULAR PROGRESS
// ================================================================
function setCircularProgress(pct) {
  if (!cpFill) return;
  const offset = CP_CIRCUMFERENCE - (pct / 100) * CP_CIRCUMFERENCE;
  cpFill.style.strokeDasharray  = CP_CIRCUMFERENCE;
  cpFill.style.strokeDashoffset = offset;
}

// ================================================================
// FEATURE ANALYSIS GRID
// ================================================================
function renderFeatures(features) {
  const entries = Object.entries(FEATURE_META)
    .filter(([key]) => key in features)
    .map(([key, meta]) => ({ key, meta, value: features[key] }));

  if (!entries.length) {
    featuresGrid.innerHTML = `<div class="feat-placeholder">No feature data returned.</div>`;
    return;
  }

  featuresGrid.innerHTML = entries.map(({ key, meta, value }) => {
    const numVal = parseFloat(value) || 0;
    let displayVal = numVal;
    let flagged = false;
    let positive = false;
    let barWidth = 0;

    if (meta.binary) {
      displayVal = numVal === 1 ? "Yes" : "No";
      flagged  = (meta.positiveVal === 0 && numVal === 1) || (meta.positiveVal === 1 && numVal !== 1);
      positive = (meta.positiveVal === 1 && numVal === 1) || (meta.positiveVal === 0 && numVal !== 1);
      barWidth = numVal === 1 ? 100 : 0;
    } else if (meta.isRatio) {
      displayVal = (numVal * 100).toFixed(1) + "%";
      flagged = meta.warnHigh && numVal > (meta.maxRef * 0.6);
      barWidth = Math.min(100, (numVal / meta.maxRef) * 100);
    } else {
      displayVal = Number.isInteger(numVal) ? numVal : numVal.toFixed(3);
      if (meta.unit) displayVal += ` ${meta.unit}`;
      flagged  = meta.warnHigh && numVal > (meta.maxRef * 0.6);
      positive = !meta.warnHigh && numVal > 0;
      barWidth = Math.min(100, (numVal / (meta.maxRef || 1)) * 100);
    }

    const valClass = flagged ? "flagged" : positive ? "positive" : "";

    return `
      <div class="feat-item">
        <div class="feat-name" title="${escapeHtml(key)}">${escapeHtml(meta.label)}</div>
        <div class="feat-value ${valClass}">${escapeHtml(String(displayVal))}</div>
        <div class="feat-bar"><div class="feat-bar-fill" style="width:${barWidth.toFixed(1)}%"></div></div>
      </div>`;
  }).join("");
}

// ================================================================
// SCAN HISTORY (localStorage)
// ================================================================
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); }
  catch { return []; }
}

function saveHistory(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

function addToHistory(url, data) {
  const items = loadHistory();
  if (items.length && items[0].url === url) {
    items[0] = buildHistoryItem(url, data);
  } else {
    items.unshift(buildHistoryItem(url, data));
  }
  saveHistory(items.slice(0, HISTORY_LIMIT));
  renderHistory();
}

function buildHistoryItem(url, data) {
  return { url, prediction: (data.prediction || "safe").toLowerCase(), risk_score: data.risk_score || 0, ts: Date.now() };
}

function renderHistory() {
  const items = loadHistory();
  if (!items.length) {
    historyList.innerHTML = `<div class="history-placeholder">Your last 10 scans will appear here.</div>`;
    return;
  }
  historyList.innerHTML = items.map((item, i) => {
    const pct = ((item.risk_score || 0) * 100).toFixed(1);
    const age = timeAgo(item.ts);
    return `
      <div class="history-item" role="listitem" tabindex="0"
           aria-label="Scan result: ${escapeHtml(item.url)} -- ${capitalise(item.prediction)}"
           onclick="reScanFromHistory(${i})"
           onkeydown="if(event.key==='Enter')reScanFromHistory(${i})">
        <span class="hist-dot ${item.prediction}" aria-hidden="true"></span>
        <span class="hist-url" title="${escapeHtml(item.url)}">${escapeHtml(truncateUrl(item.url, 55))}</span>
        <span class="hist-badge ${item.prediction}">${capitalise(item.prediction)}</span>
        <span class="hist-score" title="${age}">${pct}%</span>
      </div>`;
  }).join("");
}

function reScanFromHistory(index) {
  const items = loadHistory();
  if (items[index]) { urlInput.value = items[index].url; checkURL(); }
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
}

// ================================================================
// UTILITIES
// ================================================================
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function capitalise(str) { return str.charAt(0).toUpperCase() + str.slice(1); }

function truncateUrl(url, max) { return url.length > max ? url.slice(0, max) + "..." : url; }

function scoreColor(score) {
  if (score >= 0.75) return "#EF4444";
  if (score >= 0.40) return "#F59E0B";
  return "#22C55E";
}

function timeAgo(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}
