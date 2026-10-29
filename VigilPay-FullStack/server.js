import http from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("./public", import.meta.url));
const argValue = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : "";
};
const PORT = Number(process.env.PORT || argValue("--port") || 3000);
const HOST = process.env.HOST || argValue("--host") || "0.0.0.0";
const isProduction = process.env.NODE_ENV === "production";
const requestLog = new Map();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8"
};

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(body));
}

function secureHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https://*.supabase.co https://safebrowsing.googleapis.com; worker-src 'self' blob: https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'"
  );
}

function rateLimited(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const key = forwarded || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const recent = (requestLog.get(key) || []).filter((time) => now - time < 60_000);
  recent.push(now);
  requestLog.set(key, recent);
  return recent.length > 30;
}

function normalizeUrl(input) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("Enter a URL to inspect.");
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const parsed = new URL(withScheme);
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS links are supported.");
  return parsed;
}

function localUrlSignals(parsed) {
  const host = parsed.hostname.toLowerCase();
  const full = parsed.href.toLowerCase();
  const signals = [];
  let score = 0;
  if (parsed.protocol === "http:") { signals.push("The link does not use HTTPS."); score += 20; }
  if (/\d{1,3}(\.\d{1,3}){3}/.test(host)) { signals.push("The link uses a raw IP address instead of a normal domain."); score += 30; }
  if (host.split(".").length > 4) { signals.push("The link uses an unusually deep subdomain."); score += 12; }
  if (host.includes("xn--")) { signals.push("The domain uses Punycode and may imitate another name."); score += 22; }
  if ((full.match(/%[0-9a-f]{2}/gi) || []).length > 4) { signals.push("The link contains heavy URL encoding."); score += 14; }
  if (full.length > 180) { signals.push("The link is unusually long."); score += 10; }
  const bait = ["verify", "kyc", "urgent", "reward", "gift", "refund", "block", "suspend", "login", "secure", "claim", "update"];
  const found = bait.filter((word) => full.includes(word));
  if (found.length) { signals.push(`High-pressure terms in the link: ${found.slice(0, 4).join(", ")}.`); score += Math.min(24, found.length * 6); }
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"];
  if (shorteners.includes(host)) { signals.push("This is a shortened link; its final destination is hidden."); score += 24; }
  const brandWords = ["paytm", "phonepe", "googlepay", "gpay", "amazon", "flipkart", "sbi", "hdfc", "icici", "axisbank"];
  const brand = brandWords.find((word) => host.includes(word));
  if (brand && !host.endsWith(`${brand}.com`) && !["sbi.co.in", "onlinesbi.sbi", "axisbank.com", "icicibank.com", "hdfcbank.com", "paytm.com", "phonepe.com"].some((d) => host === d || host.endsWith(`.${d}`))) {
    signals.push("The domain contains a brand-like word but is not recognized as that brand's primary domain.");
    score += 28;
  }
  return { score: Math.min(100, score), signals };
}

async function googleSafeBrowsingCheck(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) return { configured: false, flagged: false, matches: [] };
  const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: { clientId: "vigilpay", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    }),
    signal: AbortSignal.timeout(6500)
  });
  if (!response.ok) throw new Error(`Safe Browsing returned ${response.status}`);
  const data = await response.json();
  return { configured: true, flagged: Array.isArray(data.matches) && data.matches.length > 0, matches: data.matches || [] };
}

async function readBody(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 20_000) throw new Error("Request body is too large.");
  }
  return body ? JSON.parse(body) : {};
}

function serveFile(req, res) {
  let pathname = decodeURIComponent(new URL(req.url, `http://${req.headers.host || "localhost"}`).pathname);
  if (pathname === "/") pathname = "/index.html";
  const safePath = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  let filePath = join(ROOT, safePath);
  if (!filePath.startsWith(ROOT)) return sendJson(res, 403, { error: "Forbidden" });
  if (!existsSync(filePath) || statSync(filePath).isDirectory()) filePath = join(ROOT, "index.html");
  secureHeaders(res);
  res.setHeader("Content-Type", MIME[extname(filePath).toLowerCase()] || "application/octet-stream");
  res.setHeader("Cache-Control", isProduction && extname(filePath) !== ".html" ? "public, max-age=86400" : "no-cache");
  createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (url.pathname === "/api/health") return sendJson(res, 200, { ok: true, service: "vigilpay", timestamp: new Date().toISOString() });
    if (url.pathname === "/api/config") {
      return sendJson(res, 200, {
        supabaseUrl: process.env.SUPABASE_URL || "",
        supabaseKey: process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || "",
        safeBrowsingConfigured: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY)
      });
    }
    if (url.pathname === "/api/url-check" && req.method === "POST") {
      if (rateLimited(req)) return sendJson(res, 429, { error: "Too many checks. Please wait a minute." });
      const body = await readBody(req);
      const parsed = normalizeUrl(body.url);
      const local = localUrlSignals(parsed);
      let reputation = { configured: false, flagged: false, matches: [] };
      let reputationError = "";
      try { reputation = await googleSafeBrowsingCheck(parsed.href); }
      catch (error) { reputationError = "The reputation service could not be reached; heuristic checks still ran."; }
      const score = reputation.flagged ? Math.max(95, local.score) : local.score;
      return sendJson(res, 200, {
        normalizedUrl: parsed.href,
        hostname: parsed.hostname,
        score,
        level: score >= 70 ? "high" : score >= 30 ? "suspicious" : "low",
        signals: local.signals,
        reputation: { configured: reputation.configured, flagged: reputation.flagged },
        note: reputationError || (reputation.configured ? "Checked against Google Safe Browsing." : "Reputation API not configured; result is based on visible link signals only.")
      });
    }
    if (url.pathname === "/api/python-analyze" && req.method === "POST") {
      if (rateLimited(req)) return sendJson(res, 429, { error: "Too many checks. Please wait a minute." });
      const body = await readBody(req);
      if (String(body.text || "").trim().length < 8) return sendJson(res, 400, { error: "Add a little more detail first." });
      const host = process.env.PYTHON_ANALYSIS_HOST;
      const port = process.env.PYTHON_ANALYSIS_PORT;
      const directUrl = process.env.PYTHON_ANALYSIS_URL;
      const endpoint = directUrl ? `${directUrl.replace(/\/$/, "")}/analyze` : host ? `http://${host}${port ? `:${port}` : ""}/analyze` : "";
      if (!endpoint) return sendJson(res, 503, { error: "The optional Python analysis service is not configured." });
      const analysisResponse = await fetch(endpoint, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ text:body.text }), signal:AbortSignal.timeout(8000) });
      const analysis = await analysisResponse.json();
      if (!analysisResponse.ok) return sendJson(res, analysisResponse.status, { error:analysis.detail || "Python analysis failed." });
      return sendJson(res, 200, analysis);
    }
    if (url.pathname.startsWith("/api/")) return sendJson(res, 404, { error: "API route not found." });
    serveFile(req, res);
  } catch (error) {
    sendJson(res, 400, { error: error.message || "Request failed." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`VigilPay running on http://${HOST}:${PORT}`);
});
