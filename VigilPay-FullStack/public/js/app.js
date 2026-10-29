import { ALERTS, SAMPLE_TEXT, EMERGENCY_PLANS, QUIZ, GUIDES, LOCAL_REPORTS, TRANSLATIONS } from "./data.js";
import { analyzeText, parseQrPayload, localUrlAnalysis } from "./analyzer.js";
import { initBackend, backendStatus, getSession, getProfile, onAuthChange, signIn, signUp, signOut, searchApprovedReports, submitCommunityReport, fetchModerationQueue, moderateReport } from "./supabase.js";
import { initMotion, refreshMotionTargets, animateRouteChange, setButtonLoading } from "./motion.js";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHTML = (value = "") => String(value).replace(/[&<>'"]/g, (char) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", "'":"&#39;", '"':"&quot;" }[char]));
const money = (value) => new Intl.NumberFormat("en-IN", { style:"currency", currency:"INR", maximumFractionDigits:0 }).format(Number(value) || 0);
const state = { route:"home", authMode:"signin", session:null, profile:null, quizIndex:0, quizScore:0, quizLocked:false, guideCategory:"All", tracker:[], chart:null, qrPayload:"" };

function toast(title, message = "", type = "success") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<b>${escapeHTML(title)}</b>${message ? `<span>${escapeHTML(message)}</span>` : ""}`;
  $("#toastStack").append(el);
  setTimeout(() => el.remove(), 4300);
}

function setRoute(route, updateHash = true) {
  const target = $(`[data-page="${route}"]`) ? route : "home";
  animateRouteChange(() => {
    state.route = target;
    $$(".page").forEach((page) => page.classList.toggle("active", page.dataset.page === target));
    $$(".nav-link").forEach((link) => link.classList.toggle("active", link.dataset.route === target));
    if (updateHash) history.replaceState(null, "", `#${target}`);
    $("#sidebar").classList.remove("open");
    $("#menuButton").setAttribute("aria-expanded", "false");
    window.scrollTo({ top:0, behavior:"smooth" });
  });
  if (target === "tracker") renderTracker();
  if (target === "community") loadCommunityReports();
  if (target === "admin") loadAdminQueue();
  requestAnimationFrame(refreshMotionTargets);
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("vigilpay_theme", theme);
  $("#themeButton").textContent = theme === "dark" ? "☀" : "◐";
  if (state.chart) renderTracker();
}

function setLanguage(lang) {
  const dictionary = TRANSLATIONS[lang] || TRANSLATIONS.en;
  document.documentElement.lang = lang;
  $$('[data-i18n]').forEach((node) => {
    if (dictionary[node.dataset.i18n]) node.textContent = dictionary[node.dataset.i18n];
  });
  localStorage.setItem("vigilpay_language", lang);
}

function renderHome() {
  $("#alertFeed").innerHTML = ALERTS.map((item) => `<div class="alert-item"><span>${item.icon}</span><div><strong>${escapeHTML(item.title)}</strong><small>${escapeHTML(item.detail)}</small></div><time>${escapeHTML(item.age)}</time></div>`).join("");
  updateReadiness();
}

function updateReadiness() {
  const checks = $$(".readiness-check");
  if (state.quizScore > 0) checks[1].checked = true;
  if (localStorage.getItem("vigilpay_emergency_plan")) checks[2].checked = true;
  checks[3].checked = Boolean(state.session);
  const score = checks.filter((box) => box.checked).length * 25;
  $("#readinessScore").textContent = score;
  $("#readinessLabel").textContent = `${score}%`;
  $("#readinessRing").style.setProperty("--value", score);
}

function renderRiskResult(result, target) {
  if (result.error) {
    target.className = "panel result-panel empty-state";
    target.innerHTML = `<div class="empty-visual">!</div><h3>More detail needed</h3><p>${escapeHTML(result.error)}</p>`;
    return;
  }
  target.className = "panel result-panel risk-result";
  target.innerHTML = `
    <div class="risk-top"><div class="risk-score risk-${result.level}" style="--risk:${result.score}"><strong>${result.score}</strong></div><div class="risk-summary"><span class="risk-badge ${result.level}">${result.level} risk</span><h3>${escapeHTML(result.title)}</h3><p>${escapeHTML(result.summary)}</p></div></div>
    <div class="signal-list">${result.matches.length ? result.matches.map((m) => `<div class="signal-item"><span>${m.icon}</span><div><b>${escapeHTML(m.category)}</b><br>${escapeHTML(m.message)}</div></div>`).join("") : '<div class="signal-item"><span>✓</span><div><b>No strong rule match</b><br>Keep verifying independently; fraud messages can avoid common wording.</div></div>'}</div>
    <div class="action-list">${result.actions.map((action,index) => `<div class="action-step"><span>${index+1}</span><div>${escapeHTML(action)}</div></div>`).join("")}</div>
    ${result.level === "high" ? '<button class="button button-danger full-button" data-route="emergency">Open emergency mode</button>' : ""}`;
  $$('[data-route]', target).forEach((button) => button.addEventListener("click", () => setRoute(button.dataset.route)));
}

function setupChecker() {
  $$("#inputTypeTabs button").forEach((button) => button.addEventListener("click", () => {
    $$("#inputTypeTabs button").forEach((b) => b.classList.remove("active"));
    button.classList.add("active");
  }));
  $$(".sample-chip").forEach((button) => button.addEventListener("click", () => { $("#scamInput").value = SAMPLE_TEXT[button.dataset.sample]; }));
  $("#analyzeButton").addEventListener("click", runScamAnalysis);
}

async function runScamAnalysis() {
  const text=$("#scamInput").value, button=$("#analyzeButton"), usePython=$("#pythonAnalysis").checked;
  if(!usePython){ renderRiskResult(analyzeText(text),$("#scamResult")); refreshMotionTargets(); return; }
  setButtonLoading(button,true,"Python analysis");
  try {
    const response=await fetch("/api/python-analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.error||"Python service unavailable.");
    renderRiskResult(result,$("#scamResult"));
    toast("Python deep scan complete","Analysed by your server-side risk engine.");
  } catch(error) {
    renderRiskResult(analyzeText(text),$("#scamResult"));
    toast("Used private local scan",`${error.message} Local analysis completed instead.`,"error");
  } finally { setButtonLoading(button,false,"Analyse risk"); refreshMotionTargets(); }
}

function renderUrlResult(result) {
  const slot = $("#urlResult");
  if (result.error) { slot.innerHTML = `<article class="panel url-card"><strong>Could not inspect this link</strong><p class="url-note">${escapeHTML(result.error)}</p></article>`; return; }
  slot.innerHTML = `<article class="panel url-card"><div class="url-head"><div class="domain-lock"><span class="kicker">Inspected without opening</span><strong>${escapeHTML(result.hostname)}</strong><small>${escapeHTML(result.normalizedUrl)}</small></div><span class="risk-badge ${result.level}">${result.score}/100 · ${result.level}</span></div><div class="signal-list">${result.signals.length ? result.signals.map((signal) => `<div class="signal-item"><span>!</span><div>${escapeHTML(signal)}</div></div>`).join("") : '<div class="signal-item"><span>✓</span><div>No obvious structural warning signs were detected.</div></div>'}</div><p class="url-note">${escapeHTML(result.note)} A low score is not proof of safety; verify the organization and domain independently.</p></article>`;
}

async function checkUrl() {
  const input = $("#urlInput").value.trim();
  if (!input) return toast("Add a link", "Paste a URL or domain first.", "error");
  const button = $("#urlCheckButton");
  setButtonLoading(button, true, "Inspecting link");
  try {
    const response = await fetch("/api/url-check", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:input }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Link check failed.");
    renderUrlResult(result);
  } catch {
    renderUrlResult(localUrlAnalysis(input));
  } finally { setButtonLoading(button, false, "Inspect link"); }
}

function renderQrResult(result) {
  const target = $("#qrResult");
  if (result.error) { target.className = "panel result-panel empty-state"; target.innerHTML = `<div class="empty-visual">!</div><h3>Could not read QR</h3><p>${escapeHTML(result.error)}</p>`; return; }
  target.className = "panel result-panel risk-result";
  target.innerHTML = `<div class="risk-summary"><span class="risk-badge ${result.level}">${escapeHTML(result.type)} QR</span><h3>${escapeHTML(result.title)}</h3><p>${escapeHTML(result.warning)}</p></div><div class="payload-grid">${result.fields.map(([label,value]) => `<div><small>${escapeHTML(label)}</small><strong>${escapeHTML(value)}</strong></div>`).join("")}</div>${result.type === "url" ? '<button class="button button-secondary full-button" id="sendQrToUrl">Inspect this website link</button>' : ""}<p class="url-note">A QR code cannot take money by itself. Always read the payment screen and approve only a transaction you intend to make.</p>`;
  $("#sendQrToUrl")?.addEventListener("click", () => { $("#urlInput").value = result.raw; setRoute("link-checker"); setTimeout(checkUrl, 100); });
}

async function decodeQrFile(file) {
  if (!file) return;
  if (!window.jsQR) return toast("QR scanner unavailable", "The QR library could not load. Paste the raw payload instead.", "error");
  const image = new Image();
  const objectUrl = URL.createObjectURL(file);
  image.onload = () => {
    const canvas = $("#qrCanvas");
    const max = 1400;
    const scale = Math.min(1, max / Math.max(image.width, image.height));
    canvas.width = Math.round(image.width * scale); canvas.height = Math.round(image.height * scale);
    const context = canvas.getContext("2d", { willReadFrequently:true });
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    const pixels = context.getImageData(0,0,canvas.width,canvas.height);
    const code = window.jsQR(pixels.data,pixels.width,pixels.height,{ inversionAttempts:"attemptBoth" });
    URL.revokeObjectURL(objectUrl);
    if (!code) return renderQrResult({ error:"No readable QR code was found. Try a clearer, tightly cropped image." });
    state.qrPayload = code.data; $("#qrRaw").value = code.data; renderQrResult(parseQrPayload(code.data));
  };
  image.onerror = () => { URL.revokeObjectURL(objectUrl); renderQrResult({ error:"The selected image could not be opened." }); };
  image.src = objectUrl;
}

async function runOcr() {
  const file = $("#screenshotFile").files[0];
  if (!file) return toast("Choose a screenshot", "Select a clear image first.", "error");
  if (!window.Tesseract) return toast("OCR unavailable", "The OCR library could not load. Try again with an internet connection.", "error");
  const progress = $("#ocrProgress"); progress.classList.remove("hidden");
  const button = $("#ocrButton"); button.disabled = true; button.textContent = "Reading screenshot…";
  try {
    const result = await window.Tesseract.recognize(file, "eng", { logger: (message) => {
      const percent = Math.round((message.progress || 0) * 100);
      $("#ocrProgressBar").style.width = `${percent}%`;
      $("#ocrStatus").textContent = `${message.status || "Processing"} ${percent}%`;
    }});
    const text = result.data.text.trim();
    const analysis = analyzeText(text);
    renderRiskResult(analysis, $("#ocrResult"));
    if (!analysis.error) $("#ocrResult").insertAdjacentHTML("afterbegin", `<details class="signal-item"><summary><b>Extracted text</b> — review OCR</summary><p>${escapeHTML(text.slice(0,2000))}</p></details>`);
  } catch (error) { renderRiskResult({ error:error.message || "OCR could not read this image." }, $("#ocrResult")); }
  finally { setButtonLoading(button, false, "Extract & analyse"); }
}

function setupEmergency() {
  $$("[data-emergency]").forEach((button) => button.addEventListener("click", () => {
    $$("[data-emergency]").forEach((b) => b.classList.toggle("active", b === button));
    const plan = EMERGENCY_PLANS[button.dataset.emergency];
    localStorage.setItem("vigilpay_emergency_plan", button.dataset.emergency);
    $("#emergencyPlan").innerHTML = `<div class="plan-title"><div><span class="kicker">Prioritized plan</span><h3>${escapeHTML(plan.title)}</h3><p>${escapeHTML(plan.subtitle)}</p></div><a class="button button-danger" href="tel:1930">Call 1930</a></div><div class="timeline">${plan.steps.map(([n,title,detail]) => `<div class="timeline-step"><span>${escapeHTML(n)}</span><div><strong>${escapeHTML(title)}</strong><small>${escapeHTML(detail)}</small></div></div>`).join("")}</div>`;
    updateReadiness();
  }));
}

function reportCard(item, admin = false) {
  return `<article class="report-card"><div class="report-top"><span class="report-type">${escapeHTML(item.identifier_type)}</span><span class="count-badge">${admin ? escapeHTML(item.status) : `${Number(item.report_count||1)} report${Number(item.report_count||1)===1?"":"s"}`}</span></div><h3>${escapeHTML(item.identifier_display || item.identifier)}</h3><p><strong>${escapeHTML(item.report_type)}</strong><br>${escapeHTML(item.description)}</p><footer><span>User-reported · not confirmed</span><time>${new Date(item.created_at).toLocaleDateString("en-IN")}</time></footer>${admin ? `<div class="form-actions"><button class="button button-secondary" data-moderate="rejected" data-id="${item.id}">Reject</button><button class="button button-primary" data-moderate="approved" data-id="${item.id}">Approve</button></div>` : ""}</article>`;
}

async function loadCommunityReports(query = "") {
  const target = $("#communityResults"); target.innerHTML = '<div class="empty-list">Loading reports…</div>';
  try {
    const remote = await searchApprovedReports(query);
    const reports = remote === null ? LOCAL_REPORTS.filter((item) => !query || `${item.identifier} ${item.report_type}`.toLowerCase().includes(query.toLowerCase())) : remote;
    $("#communityMode").textContent = remote === null ? "Local preview data · connect Supabase for live reports" : "Live moderated community database";
    target.innerHTML = reports.length ? reports.map((item) => reportCard(item)).join("") : '<div class="empty-list">No moderated reports matched that search. No result does not mean the identifier is safe.</div>';
  } catch (error) { target.innerHTML = `<div class="empty-list">Could not load reports: ${escapeHTML(error.message)}</div>`; }
}

async function handleCommunitySubmit(event) {
  event.preventDefault();
  const message = $("#communityFormMessage"); message.textContent = "Submitting…"; message.className = "form-message";
  try {
    const form = Object.fromEntries(new FormData(event.currentTarget));
    await submitCommunityReport(form);
    message.textContent = "Submitted for moderation. It is not public yet."; message.className = "form-message success";
    event.currentTarget.reset();
    setTimeout(() => closeModal("reportModal"), 1200);
  } catch (error) { message.textContent = error.message; message.className = "form-message error"; if (/Sign in/i.test(error.message)) openModal("authModal"); }
}

function setupAgreement() {
  $("#agreementForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const id = `VP-${Date.now().toString(36).toUpperCase()}`;
    $("#agreementPreview").innerHTML = `<div class="agreement-doc"><span class="doc-icon">✓</span><h3>VigilPay Safe Trade Agreement</h3><p class="doc-meta">Reference ${id} · ${new Date().toLocaleString("en-IN")}</p><p><strong>${escapeHTML(data.role)}</strong> plans to trade <strong>${escapeHTML(data.item)}</strong>${data.amount ? ` for <strong>${money(data.amount)}</strong>` : ""} with <strong>${escapeHTML(data.party || "the other party")}</strong>.</p><p>${escapeHTML(data.plan || "The item will be inspected and identity verified before payment.")}</p><ul class="terms-list"><li>✓ Neither party will ask for a UPI PIN, OTP, CVV or password.</li><li>✓ A QR code will never be used to “receive” money.</li><li>✓ Payment occurs only after independent verification and inspection.</li><li>✓ Any change in account, price or delivery plan requires re-verification.</li></ul><div class="signature-row"><span>${escapeHTML(data.role)} signature / date</span><span>Other party signature / date</span></div><button class="button button-secondary full-button" id="printAgreement">Print / save PDF</button><p class="url-note">This is a safety checklist, not legal advice, escrow or proof of identity.</p></div>`;
    $("#printAgreement").addEventListener("click", () => window.print());
  });
}

function renderQuiz() {
  const item = QUIZ[state.quizIndex];
  state.quizLocked = false;
  $("#quizScore").textContent = state.quizScore;
  $("#quizCard").innerHTML = `<div class="quiz-progress">Scenario ${state.quizIndex+1} of ${QUIZ.length}</div><div class="scenario-box"><small>${escapeHTML(item.channel)}</small><p>${escapeHTML(item.text)}</p></div><div class="quiz-options">${item.options.map((option,index) => `<button class="quiz-option" data-answer="${index}"><span>${String.fromCharCode(65+index)}</span>${escapeHTML(option)}</button>`).join("")}</div><div id="quizFeedback"></div>`;
  $$(".quiz-option").forEach((button) => button.addEventListener("click", () => answerQuiz(Number(button.dataset.answer))));
}

function answerQuiz(answer) {
  if (state.quizLocked) return;
  state.quizLocked = true;
  const item = QUIZ[state.quizIndex];
  const correct = answer === item.answer;
  if (correct) state.quizScore += 20;
  $$(".quiz-option").forEach((button) => { const index = Number(button.dataset.answer); if (index === item.answer) button.classList.add("correct"); else if (index === answer) button.classList.add("wrong"); button.disabled = true; });
  $("#quizScore").textContent = state.quizScore;
  const last = state.quizIndex === QUIZ.length - 1;
  $("#quizFeedback").innerHTML = `<div class="quiz-feedback"><strong>${correct ? "Correct—good catch." : "Not quite."}</strong>${escapeHTML(item.explain)}</div><button class="button button-primary" id="nextQuiz">${last ? "Finish drill" : "Next scenario"}</button>`;
  $("#nextQuiz").addEventListener("click", () => {
    if (last) { toast("Drill complete", `Safety score: ${state.quizScore}/100`); state.quizIndex=0; updateReadiness(); }
    else state.quizIndex++;
    renderQuiz();
  });
}

function renderGuides() {
  const search = $("#guideSearch").value.toLowerCase();
  const filtered = GUIDES.filter((g) => (state.guideCategory === "All" || g.category === state.guideCategory) && `${g.title} ${g.summary} ${g.flags.join(" ")}`.toLowerCase().includes(search));
  $("#guideGrid").innerHTML = filtered.length ? filtered.map((guide) => `<article class="guide-card"><span class="guide-icon">${guide.icon}</span><h3>${escapeHTML(guide.title)}</h3><p>${escapeHTML(guide.summary)}</p><ul class="red-flags">${guide.flags.map((flag) => `<li>${escapeHTML(flag)}</li>`).join("")}</ul></article>`).join("") : '<div class="empty-list">No guides match that search.</div>';
}

function setupGuides() {
  const categories = ["All", ...new Set(GUIDES.map((guide) => guide.category))];
  $("#guideFilters").innerHTML = categories.map((category) => `<button class="${category === "All" ? "active" : ""}" data-category="${category}">${category}</button>`).join("");
  $$("#guideFilters button").forEach((button) => button.addEventListener("click", () => { state.guideCategory=button.dataset.category; $$("#guideFilters button").forEach((b)=>b.classList.toggle("active",b===button)); renderGuides(); }));
  $("#guideSearch").addEventListener("input", renderGuides);
  renderGuides();
}

function loadTracker() {
  try { state.tracker = JSON.parse(localStorage.getItem("vigilpay_tracker") || "[]"); } catch { state.tracker = []; }
}

function renderTracker() {
  const totals = { attempt:0,lost:0,recovered:0,prevented:0 };
  state.tracker.forEach((item) => { if (item.outcome === "attempt") totals.attempt++; else totals[item.outcome] += Number(item.amount)||0; });
  $("#statAttempts").textContent = totals.attempt; $("#statLost").textContent=money(totals.lost); $("#statRecovered").textContent=money(totals.recovered); $("#statPrevented").textContent=money(totals.prevented);
  $("#trackerList").innerHTML = state.tracker.length ? state.tracker.slice().reverse().slice(0,8).map((item) => `<div class="tracker-item"><div><strong>${escapeHTML(item.type)}</strong><small>${escapeHTML(item.outcome)} · ${new Date(item.date).toLocaleDateString("en-IN")}</small></div><b>${money(item.amount)}</b></div>`).join("") : '<div class="empty-list">No private records yet.</div>';
  if (!window.Chart) return;
  if (state.chart) state.chart.destroy();
  const styles = getComputedStyle(document.documentElement);
  state.chart = new window.Chart($("#riskChart"), { type:"bar", data:{ labels:["Lost","Recovered","Prevented"], datasets:[{ data:[totals.lost,totals.recovered,totals.prevented], backgroundColor:["#ff6e74","#70b9ff","#49efb5"], borderRadius:8, borderSkipped:false }] }, options:{ responsive:true, plugins:{ legend:{display:false} }, scales:{ x:{ grid:{display:false}, ticks:{color:styles.getPropertyValue("--muted")} }, y:{ beginAtZero:true, grid:{color:styles.getPropertyValue("--line")}, ticks:{color:styles.getPropertyValue("--muted"),callback:(v)=>`₹${v}`} } } } });
}

function setupTracker() {
  $("#trackerForm").addEventListener("submit", (event) => { event.preventDefault(); const data=Object.fromEntries(new FormData(event.currentTarget)); data.date=new Date().toISOString(); state.tracker.push(data); localStorage.setItem("vigilpay_tracker",JSON.stringify(state.tracker)); event.currentTarget.reset(); closeModal("trackerModal"); renderTracker(); toast("Incident saved", "Stored privately in this browser."); });
  $("#clearTracker").addEventListener("click", () => { if (!confirm("Clear all locally stored tracker records?")) return; state.tracker=[]; localStorage.removeItem("vigilpay_tracker"); renderTracker(); });
}

function getIncidentData(form) {
  const data = Object.fromEntries(new FormData(form));
  data.evidence = new FormData(form).getAll("evidence");
  return data;
}

function buildIncidentLines(data) {
  return ["VIGILPAY INCIDENT SUMMARY",`Generated: ${new Date().toLocaleString("en-IN")}`,"",`Incident date: ${data.date || "Not provided"}`,`Amount lost: ${money(data.amount)}`,`Payment method: ${data.method}`,`Transaction reference: ${data.reference || "Not provided"}`,`Reported identifier: ${data.identifier || "Not provided"}`,`Bank / app: ${data.provider || "Not provided"}`,"","What happened:",data.summary,"","Evidence saved:",data.evidence.length ? data.evidence.map((x)=>`- ${x}`).join("\n") : "- None selected","","Immediate reminder: For cyber financial fraud in India, call 1930 and report at cybercrime.gov.in.","Never include passwords, OTPs, PINs, CVVs or full card numbers in a shared report."];
}

function downloadIncidentPdf(data) {
  if (!window.jspdf?.jsPDF) { window.print(); return toast("PDF library unavailable", "Opened the browser print dialog instead.", "error"); }
  const doc = new window.jspdf.jsPDF();
  doc.setFillColor(7,16,14); doc.rect(0,0,210,28,"F"); doc.setTextColor(73,239,181); doc.setFontSize(20); doc.text("VigilPay Incident Summary",14,18);
  doc.setTextColor(25,35,32); doc.setFontSize(10);
  const lines = buildIncidentLines(data).flatMap((line) => doc.splitTextToSize(line,180));
  let y=40; for (const line of lines) { if (y>280) { doc.addPage(); y=18; } doc.text(line,14,y); y+=6; }
  doc.save(`VigilPay-Incident-${new Date().toISOString().slice(0,10)}.pdf`);
}

function setupIncidentReport() {
  const date = new Date(); date.setMinutes(date.getMinutes()-date.getTimezoneOffset()); $("#incidentForm [name=date]").value=date.toISOString().slice(0,16);
  $("#incidentForm").addEventListener("submit", (event) => { event.preventDefault(); downloadIncidentPdf(getIncidentData(event.currentTarget)); });
  $("#printReport").addEventListener("click", () => window.print());
}

function openModal(id) { $(`#${id}`).classList.remove("hidden"); document.body.style.overflow="hidden"; }
function closeModal(id) { $(`#${id}`).classList.add("hidden"); document.body.style.overflow=""; }

async function refreshAuth(session = null) {
  state.session = session || await getSession();
  state.profile = state.session ? await getProfile() : null;
  $("#authButton").textContent = state.session ? (state.profile?.display_name || "Account") : "Sign in";
  $("#adminNav").classList.toggle("hidden", state.profile?.role !== "admin");
  updateReadiness();
}

async function handleAuth(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  const message = $("#authMessage"); message.textContent="Working…"; message.className="form-message";
  try {
    const result = state.authMode === "signin" ? await signIn(data.email,data.password) : await signUp(data.email,data.password);
    if (state.authMode === "signup" && !result.session) { message.textContent="Check your email to confirm the account, then sign in."; message.className="form-message success"; return; }
    await refreshAuth(result.session); closeModal("authModal"); toast("Signed in", "Your Supabase session is active.");
  } catch (error) { message.textContent=error.message; message.className="form-message error"; }
}

async function loadAdminQueue() {
  const target=$("#adminQueue"); target.innerHTML='<div class="empty-list">Loading moderation queue…</div>';
  if (state.profile?.role !== "admin") { target.innerHTML='<div class="empty-list">Administrator access is required.</div>'; return; }
  try { const reports=await fetchModerationQueue(); target.innerHTML=reports.length?reports.map((item)=>reportCard(item,true)).join(""):'<div class="empty-list">The moderation queue is clear.</div>'; $$("[data-moderate]",target).forEach((button)=>button.addEventListener("click",async()=>{ try { await moderateReport(button.dataset.id,button.dataset.moderate); toast("Report updated",`Marked ${button.dataset.moderate}.`); loadAdminQueue(); } catch(error){toast("Update failed",error.message,"error");} })); } catch(error){target.innerHTML=`<div class="empty-list">${escapeHTML(error.message)}</div>`;}
}

function setupModalsAndAuth() {
  $$("[data-close-modal]").forEach((button)=>button.addEventListener("click",()=>closeModal(button.dataset.closeModal)));
  $$(".modal-backdrop").forEach((modal)=>modal.addEventListener("click",(event)=>{if(event.target===modal)closeModal(modal.id);}));
  $("#authButton").addEventListener("click",async()=>{ if(state.session){try{await signOut();await refreshAuth(null);toast("Signed out");}catch(error){toast("Could not sign out",error.message,"error");}} else openModal("authModal"); });
  $$("#authTabs button").forEach((button)=>button.addEventListener("click",()=>{state.authMode=button.dataset.authMode;$$("#authTabs button").forEach((b)=>b.classList.toggle("active",b===button));$("#authTitle").textContent=state.authMode==="signin"?"Welcome back":"Create your VigilPay account";}));
  $("#authForm").addEventListener("submit",handleAuth);
  $("#openReportModal").addEventListener("click",()=>openModal("reportModal"));
  $("#openTrackerModal").addEventListener("click",()=>openModal("trackerModal"));
  $("#communityReportForm").addEventListener("submit",handleCommunitySubmit);
}

function setupGlobalEvents() {
  $$('[data-route]').forEach((node)=>node.addEventListener("click",(event)=>{ if(node.tagName==="A")event.preventDefault(); setRoute(node.dataset.route); }));
  $("#menuButton").addEventListener("click",()=>{const sidebar=$("#sidebar");sidebar.classList.toggle("open");$("#menuButton").setAttribute("aria-expanded",String(sidebar.classList.contains("open")));});
  $("#themeButton").addEventListener("click",()=>setTheme(document.documentElement.dataset.theme==="dark"?"light":"dark"));
  $("#languageSelect").addEventListener("change",(event)=>setLanguage(event.target.value));
  $("#urlCheckButton").addEventListener("click",checkUrl); $("#urlInput").addEventListener("keydown",(event)=>{if(event.key==="Enter")checkUrl();});
  $("#qrFile").addEventListener("change",(event)=>decodeQrFile(event.target.files[0]));
  $("#qrInspectButton").addEventListener("click",()=>renderQrResult(parseQrPayload($("#qrRaw").value||state.qrPayload)));
  $("#ocrButton").addEventListener("click",runOcr);
  $("#communitySearchButton").addEventListener("click",()=>loadCommunityReports($("#communitySearch").value));
  $("#communitySearch").addEventListener("keydown",(event)=>{if(event.key==="Enter")loadCommunityReports(event.target.value);});
}

async function init() {
  initMotion();
  const theme=localStorage.getItem("vigilpay_theme")||"dark"; setTheme(theme);
  const language=localStorage.getItem("vigilpay_language")||"en"; $("#languageSelect").value=language; setLanguage(language);
  renderHome(); setupChecker(); setupEmergency(); setupAgreement(); renderQuiz(); setupGuides(); loadTracker(); setupTracker(); setupIncidentReport(); setupModalsAndAuth(); setupGlobalEvents();
  setRoute(location.hash.slice(1)||"home",false);
  await initBackend();
  await refreshAuth();
  onAuthChange((session)=>refreshAuth(session));
  if (!backendStatus().configured) $("#communityMode").textContent="Local preview data · connect Supabase for live reports";
  refreshMotionTargets();
}

init().catch((error)=>toast("VigilPay could not start",error.message,"error"));
