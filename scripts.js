const $ = (id) => document.getElementById(id);

const yearEl = $("year");
yearEl.textContent = new Date().getFullYear();

const analyzeBtn = $("analyzeBtn");
const clearBtn = $("clearBtn");
const input = $("inputText");

const scoreNum = $("scoreNum");
const verdictPill = $("verdictPill");
const reasonsEl = $("reasons");
const confidenceEl = $("confidence");
const signalsHitEl = $("signalsHit");
const linksFoundEl = $("linksFound");

const ring = document.querySelector(".ring");

// ---- Heuristic signals ----
// Weight is how much it pushes risk score.
// Each signal has a label used in the UI.
const SIGNALS = [
  { key: "urgency", weight: 14, label: "Urgency / pressure language" },
  { key: "credential", weight: 18, label: "Asks for passwords / codes / login" },
  { key: "money", weight: 16, label: "Payment / gift cards / crypto request" },
  { key: "impersonation", weight: 14, label: "Impersonation language (bank, IRS, support)" },
  { key: "shortlink", weight: 12, label: "Shortened or obfuscated link" },
  { key: "link_mismatch", weight: 16, label: "Suspicious link or misleading domain" },
  { key: "threat", weight: 12, label: "Threats: account closed / legal action" },
  { key: "weird_format", weight: 8, label: "Odd formatting (ALL CAPS / many symbols)" },
  { key: "typos", weight: 10, label: "Suspicious spelling patterns / typos" },
  { key: "attachments", weight: 10, label: "Mentions attachments or opening files" },
];

function clamp(n, min, max){ return Math.max(min, Math.min(max, n)); }

function extractLinks(text){
  // capture http(s) and bare domains
  const urlRegex = /\bhttps?:\/\/[^\s)]+/gi;
  const bareRegex = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s)]*)?/gi;

  const urls = new Set();
  (text.match(urlRegex) || []).forEach(u => urls.add(u));
  (text.match(bareRegex) || []).forEach(u => {
    // avoid double-counting if already included with scheme
    if (![...urls].some(x => x.includes(u))) urls.add(u);
  });

  return [...urls];
}

function normalizeForCheck(s){
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

function countWeirdChars(text){
  const matches = text.match(/[^a-zA-Z0-9\s]/g);
  return matches ? matches.length : 0;
}

function hasTyposLikePatterns(text){
  // simple heuristic: repeated punctuation, lots of random caps, obvious misspell-ish patterns
  const t = text;
  const repeated = /([!?.,])\1{2,}/.test(t);
  const randomCaps = /[a-z][A-Z][a-z]/.test(t);
  const commonBad = /\b(verifcation|updte|acount|passw0rd|securrity|paymnt)\b/i.test(t);
  return repeated || randomCaps || commonBad;
}

function domainLooksSuspicious(url){
  // flags common tricks: @ in URL, many hyphens, punycode, IP-based host, long subdomain chains
  const u = url.toLowerCase();
  if (u.includes("@")) return true;
  if (u.includes("xn--")) return true;
  if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(u)) return true; // IP
  const host = u.replace(/^https?:\/\//, "").split("/")[0];
  const parts = host.split(".");
  if (parts.length >= 4) return true; // deep subdomain chain
  if ((host.match(/-/g) || []).length >= 3) return true;
  return false;
}

function isShortener(url){
  const u = url.toLowerCase();
  const shorteners = [
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rebrand.ly",
    "rb.gy","shorturl.at"
  ];
  return shorteners.some(d => u.includes(d));
}

function scoreText(raw){
  const text = normalizeForCheck(raw);
  const reasons = [];
  let score = 0;
  let hits = 0;

  const links = extractLinks(raw);
  const linksFound = links.length;

  // Signal checks
  const checks = {
    urgency: /\b(urgent|immediately|asap|act now|final notice|limited time|today only|within \d+ (?:min|mins|minutes|hour|hours))\b/i.test(raw),
    credential: /\b(password|passcode|verification code|2fa|otp|security code|login|sign in|confirm your identity)\b/i.test(raw),
    money: /\b(gift card|wire|bitcoin|crypto|payment|pay now|refund|invoice|cash app|venmo|zelle)\b/i.test(raw),
    impersonation: /\b(bank|irs|apple|microsoft|google|amazon|paypal|usps|fedex|dhl|support team|help desk)\b/i.test(raw),
    threat: /\b(account (?:locked|suspended|disabled|closed)|legal action|warrant|arrest|penalty|lawsuit)\b/i.test(raw),
    attachments: /\b(open the attachment|attached|pdf attached|download (?:the )?file|docu?ment attached)\b/i.test(raw),
    weird_format: (countWeirdChars(raw) > 25) || (raw === raw.toUpperCase() && raw.length > 40),
    typos: hasTyposLikePatterns(raw),
    shortlink: links.some(isShortener),
    link_mismatch: links.some(domainLooksSuspicious),
  };

  for (const s of SIGNALS){
    if (checks[s.key]){
      score += s.weight;
      hits += 1;
      reasons.push(s.label);
    }
  }

  // Link count adds a little risk
  if (linksFound >= 2) { score += 6; reasons.push("Multiple links present"); hits += 1; }
  if (linksFound >= 4) { score += 6; reasons.push("Many links present"); hits += 1; }

  // If message includes a link AND credential request, boost (common combo)
  if (checks.credential && linksFound >= 1) { score += 10; reasons.push("Link + credential request combo"); hits += 1; }

  // Clamp + compute a confidence estimate (simple)
  score = clamp(Math.round(score), 0, 100);

  // Confidence: more signals and longer text increases confidence slightly
  const lengthBoost = clamp(Math.floor(raw.length / 120), 0, 4);
  const confidence = clamp(55 + hits * 6 + lengthBoost * 3, 55, 92);

  // Verdict
  let verdict = "Low";
  if (score >= 75) verdict = "High";
  else if (score >= 40) verdict = "Medium";

  // Unique reasons only
  const uniqueReasons = [...new Set(reasons)];

  return { score, verdict, reasons: uniqueReasons, confidence, hits, linksFound };
}

function setVerdictUI(verdict){
  verdictPill.textContent = verdict;
  // No custom colors; use emoji + text for clarity
  if (verdict === "High") verdictPill.textContent = "High ⚠️";
  if (verdict === "Medium") verdictPill.textContent = "Medium ⚡";
  if (verdict === "Low") verdictPill.textContent = "Low ✅";
}

function setScoreUI(score){
  scoreNum.textContent = String(score);
  ring.style.setProperty("--p", `${score}%`);
}

function renderReasons(reasons){
  reasonsEl.innerHTML = "";
  if (!reasons.length){
    const li = document.createElement("li");
    li.textContent = "No strong phishing signals detected. Still verify independently.";
    reasonsEl.appendChild(li);
    return;
  }
  reasons.slice(0, 9).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  });
}

function analyze(){
  const raw = input.value || "";
  if (!raw.trim()){
    setScoreUI(0);
    setVerdictUI("—");
    renderReasons(["Paste a message above to analyze."]);
    confidenceEl.textContent = "—";
    signalsHitEl.textContent = "0";
    linksFoundEl.textContent = "0";
    return;
  }

  const res = scoreText(raw);
  setScoreUI(res.score);
  setVerdictUI(res.verdict);
  renderReasons(res.reasons);
  confidenceEl.textContent = `${res.confidence}%`;
  signalsHitEl.textContent = String(res.hits);
  linksFoundEl.textContent = String(res.linksFound);
}

analyzeBtn.addEventListener("click", analyze);
clearBtn.addEventListener("click", () => {
  input.value = "";
  analyze();
});

input.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
});

// Initial UI state
analyze();
