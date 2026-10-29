const RULES = [
  { category: "Credential theft", weight: 34, icon: "••", pattern: /\b(otp|one[ -]?time password|upi pin|pin number|cvv|card pin|password|passcode|security code)\b/i, message: "They are asking for a secret credential. Legitimate support should not ask you to disclose it." },
  { category: "Remote access", weight: 35, icon: "⌁", pattern: /\b(anydesk|teamviewer|quicksupport|remote access|screen share|share your screen|install (this|the) app)\b/i, message: "Remote-control or screen-sharing software can expose your device and banking activity." },
  { category: "Forced urgency", weight: 16, icon: "⌛", pattern: /\b(urgent|immediately|right now|act now|within \d+ (minute|hour)|today only|last chance|account (will be )?blocked|disconnect(ed|ion)? tonight)\b/i, message: "The message uses a deadline to stop you from verifying independently." },
  { category: "Fear & authority", weight: 24, icon: "!", pattern: /\b(police|cbi|customs|court|arrest|illegal (parcel|package|drugs)|tax authority|cyber cell|money laundering|warrant|trafficking)\b/i, message: "It invokes authority or punishment to create panic." },
  { category: "Secrecy & isolation", weight: 22, icon: "◌", pattern: /\b(do not tell|don'?t tell|keep (this|it) secret|stay on (the )?(call|line)|do not hang up|don'?t hang up|no one else)\b/i, message: "The sender wants to isolate you from people who could help verify the story." },
  { category: "Payment to receive", weight: 38, icon: "▦", pattern: /(scan (this|the|my) qr|enter (your )?upi pin).{0,80}(receive|get|refund)|\b(receive|get|refund).{0,80}(scan (this|the|my) qr|enter (your )?upi pin)/i, message: "You do not scan a payment QR or enter a UPI PIN to receive money." },
  { category: "Advance fee", weight: 24, icon: "₹", pattern: /\b(registration fee|processing fee|security deposit|refundable (fee|deposit)|unlock (the )?(task|payment|withdrawal)|pay (first|to release)|clearance fee)\b/i, message: "An upfront payment is being demanded before a reward, job, refund or withdrawal." },
  { category: "Too-good-to-be-true offer", weight: 14, icon: "✦", pattern: /\b(guaranteed (profit|return|income)|earn ₹?\s?[\d,]+ (daily|per day)|lottery|prize|free gift|cashback reward|double your money)\b/i, message: "The offer promises unusually easy or guaranteed money." },
  { category: "Off-platform move", weight: 10, icon: "↗", pattern: /\b(telegram|whatsapp only|outside the app|private group|secret group)\b/i, message: "The conversation is being moved away from the original platform or official channel." },
  { category: "Suspicious link", weight: 16, icon: "↗", pattern: /https?:\/\/\S+|\b[a-z0-9-]+\.(help|top|click|live|xyz|work|shop|info)\b/i, message: "The text contains a link that should be verified separately before opening." },
  { category: "Identity harvesting", weight: 22, icon: "◉", pattern: /\b(send|share|upload).{0,35}\b(aadhaar|aadhar|pan card|passport|selfie|bank statement|card photo)\b/i, message: "Sensitive identity documents or images are being requested." }
];

export function analyzeText(text) {
  const clean = String(text || "").trim();
  if (clean.length < 8) return { error: "Add a little more detail so VigilPay can analyse the situation." };
  const matches = RULES.filter((rule) => rule.pattern.test(clean));
  let score = matches.reduce((sum, item) => sum + item.weight, 0);
  if (matches.length >= 3) score += 8;
  score = Math.min(100, score);
  const level = score >= 70 ? "high" : score >= 30 ? "suspicious" : "low";
  const title = level === "high" ? "High-risk scam pattern" : level === "suspicious" ? "Suspicious—verify first" : "No strong scam pattern detected";
  const summary = level === "high"
    ? "Stop contact and do not send money, codes or documents. Verify using an official channel you find independently."
    : level === "suspicious"
      ? "Pause the transaction. The message contains warning signs that deserve independent verification."
      : "The text did not match strong rules, but that does not prove it is safe. Check identity and payment details independently.";
  const actions = buildActions(matches, level);
  return { score, level, title, summary, matches, actions };
}

function buildActions(matches, level) {
  const categories = new Set(matches.map((m) => m.category));
  const actions = [];
  if (categories.has("Payment to receive")) actions.push("Do not scan the QR or enter your UPI PIN. Check your own app for an incoming credit instead.");
  if (categories.has("Credential theft")) actions.push("Do not share the OTP, PIN, CVV or password. If already shared, use Emergency Mode now.");
  if (categories.has("Remote access")) actions.push("Do not install or open the remote-access app. If installed, disconnect the device from the internet.");
  if (categories.has("Fear & authority")) actions.push("End the call. Contact the claimed organization using a number from its official website—not one they provided.");
  if (categories.has("Suspicious link")) actions.push("Copy the link into VigilPay’s Link Inspector without opening it.");
  if (level !== "low") actions.push("Ask a trusted person to review the situation before taking any action.");
  if (!actions.length) actions.push("Verify the sender through a second, trusted channel and never rely on caller ID alone.");
  return actions.slice(0, 4);
}

export function parseQrPayload(value) {
  const raw = String(value || "").trim();
  if (!raw) return { error: "Upload a readable QR image or paste its raw payload." };
  const result = { raw, type: "text", fields: [], level: "suspicious", title: "Unknown QR content", warning: "Do not open unknown QR destinations until you recognize and verify them." };
  try {
    const url = new URL(raw);
    if (url.protocol === "upi:") {
      const params = url.searchParams;
      result.type = "upi";
      result.title = "UPI payment request";
      result.level = "high";
      result.warning = "This QR asks a UPI app to prepare a payment. It does not credit money to you. Money moves only after you review and approve the payment in your app, usually with your UPI PIN.";
      result.fields = [
        ["Payee UPI ID", params.get("pa") || "Not included"],
        ["Payee name", params.get("pn") || "Not included"],
        ["Amount", params.get("am") ? `₹${params.get("am")}` : "You may be asked to enter it"],
        ["Note", params.get("tn") || params.get("tr") || "Not included"]
      ];
      return result;
    }
    if (["http:", "https:"].includes(url.protocol)) {
      result.type = "url"; result.title = "Website QR"; result.level = url.protocol === "http:" ? "high" : "suspicious";
      result.warning = "This QR opens a website. Inspect the domain carefully; HTTPS does not guarantee legitimacy.";
      result.fields = [["Domain", url.hostname], ["Protocol", url.protocol.replace(":", "").toUpperCase()], ["Path", url.pathname || "/"]];
      return result;
    }
    result.fields = [["Protocol", url.protocol], ["Destination", raw.slice(0, 180)]];
  } catch {
    result.fields = [["Text", raw.slice(0, 260)]];
    result.level = /otp|pin|pay|password|urgent/i.test(raw) ? "high" : "suspicious";
  }
  return result;
}

export function localUrlAnalysis(input) {
  let parsed;
  try { parsed = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`); }
  catch { return { error: "Enter a valid web address." }; }
  const signals = [];
  let score = 0;
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol === "http:") { score += 20; signals.push("The link does not use HTTPS."); }
  if (/\d{1,3}(\.\d{1,3}){3}/.test(host)) { score += 30; signals.push("The link uses a raw IP address."); }
  if (host.includes("xn--")) { score += 22; signals.push("The domain uses Punycode and may imitate another name."); }
  if (host.split(".").length > 4) { score += 12; signals.push("The link has many nested subdomains."); }
  if (parsed.href.length > 180) { score += 10; signals.push("The link is unusually long."); }
  const bait = ["verify","kyc","urgent","reward","refund","block","login","claim"];
  const found = bait.filter((word) => parsed.href.toLowerCase().includes(word));
  if (found.length) { score += Math.min(24,found.length*6); signals.push(`Pressure terms in the link: ${found.join(", ")}.`); }
  score = Math.min(100,score);
  return { normalizedUrl:parsed.href,hostname:host,score,level:score>=70?"high":score>=30?"suspicious":"low",signals,reputation:{configured:false,flagged:false},note:"Server reputation check unavailable; result uses visible link signals only." };
}
