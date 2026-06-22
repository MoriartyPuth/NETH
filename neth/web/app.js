const $ = (s) => document.querySelector(s);
const ICONS = { 0: "✅", 1: "⚠️", 2: "⛔" };
const ALERT = { 0: "alert-success", 1: "alert-warning", 2: "alert-error" };
const BADGE = { 0: "badge-success", 1: "badge-warning", 2: "badge-error" };
const LABELS = { 0: "SAFE", 1: "SUSPICIOUS", 2: "BLOCKED" };
let lastAnalysis = null;   // {input_type, excerpt, score} for feedback

// --- health badge ---
fetch("/health").then((r) => r.json()).then((d) => {
  const b = $("#health");
  b.textContent = "● online v" + d.version;
  b.classList.remove("badge-ghost");
  b.classList.add("badge-success");
}).catch(() => { $("#health").textContent = "● offline"; });

// --- tabs ---
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("tab-active"));
    tab.classList.add("tab-active");
    document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
    $("#panel-" + tab.dataset.tab).classList.remove("hidden");
    $("#result").classList.add("hidden");
  });
});

// --- run buttons ---
document.querySelectorAll(".run").forEach((btn) => {
  btn.addEventListener("click", () => run(btn));
});

async function run(btn) {
  const endpoint = btn.dataset.endpoint;
  btn.disabled = true;
  btn.classList.add("loading");
  const label = btn.textContent;
  try {
    let res, excerpt = "";
    if (endpoint === "text") {
      excerpt = $("#text-input").value;
      res = await postJSON("/api/analyze/text", { text: excerpt });
    } else if (endpoint === "khqr") {
      excerpt = $("#khqr-input").value;
      res = await postJSON("/api/analyze/khqr", { payload: excerpt });
    } else {
      const f = $("#image-input").files[0];
      if (!f) { alert("Choose an image first."); return; }
      excerpt = f.name;
      const fd = new FormData();
      fd.append("file", f);
      res = await (await fetch("/api/analyze/image", { method: "POST", body: fd })).json();
    }
    lastAnalysis = { input_type: endpoint, excerpt: excerpt.slice(0, 280), score: res.score };
    render(res);
  } catch (e) {
    render({ score: 1, summary: "Request failed", signals: [{ engine: "client", score: 1, reason: String(e) }] });
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
    btn.textContent = label;
  }
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

function render(v) {
  const sc = Math.max(v.score, 0);
  const signals = (v.signals || []).map((s) => {
    const dot = s.score < 0 ? "badge-ghost" : BADGE[s.score];
    const meta = [];
    if (s.matches && s.matches.length) meta.push("markers: " + s.matches.join(", "));
    if (s.urls && s.urls.length) meta.push("urls: " + s.urls.join(", "));
    if (s.registered_name) meta.push("registered: " + s.registered_name);
    if (s.fields && s.fields.account_id) meta.push("account: " + s.fields.account_id);
    if (s.qr_count) meta.push("QR codes found: " + s.qr_count);
    return `<div class="py-3 border-b border-base-300 last:border-0">
        <div class="flex items-center gap-2 text-xs uppercase tracking-wide opacity-60">
          <span class="badge badge-xs ${dot}"></span>${s.engine} · ${s.status || ""}</div>
        <div class="mt-1 text-[15px] leading-relaxed">${escapeHtml(s.reason_km || "")}</div>
        <div class="text-xs opacity-50 mt-0.5">${escapeHtml(s.reason)}</div>
        ${meta.length ? `<div class="text-xs opacity-50 mt-1 break-all">${escapeHtml(meta.join(" · "))}</div>` : ""}
      </div>`;
  }).join("");

  $("#result").innerHTML = `
    <div class="alert ${ALERT[sc]} rounded-none flex items-center gap-3">
      <span class="text-3xl">${ICONS[sc]}</span>
      <div>
        <div class="text-lg font-semibold">${escapeHtml(v.summary_km || LABELS[sc])}</div>
        <div class="text-xs opacity-70">${escapeHtml(v.summary || "")}</div>
      </div>
    </div>
    <div class="bg-base-100 px-4">${signals}</div>
    <div class="bg-base-100 p-4 flex flex-wrap items-center gap-2 text-sm border-t border-base-300">
      <span class="opacity-70">លទ្ធផលនេះខុសមែនទេ? / Wrong result?</span>
      <button class="fb btn btn-xs btn-outline" data-label="safe">ពិតជាមានសុវត្ថិភាព</button>
      <button class="fb btn btn-xs btn-outline" data-label="scam">ពិតជាការបោកប្រាស់</button>
    </div>`;
  document.querySelectorAll(".fb").forEach((b) =>
    b.addEventListener("click", () => sendFeedback(b)));
  $("#result").classList.remove("hidden");
  $("#result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function sendFeedback(btn) {
  if (!lastAnalysis) return;
  btn.disabled = true;
  try {
    await postJSON("/api/feedback", {
      input_type: lastAnalysis.input_type,
      input_excerpt: lastAnalysis.excerpt,
      predicted_score: lastAnalysis.score,
      correct_label: btn.dataset.label,
      note: "",
    });
    document.querySelector(".fb").parentElement.innerHTML =
      "<span class='opacity-70'>អរគុណ! យើងបានកត់ត្រាការរាយការណ៍របស់អ្នក។ / Thanks — recorded.</span>";
  } catch (e) {
    btn.disabled = false;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
