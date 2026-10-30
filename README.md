# VigilPay: a UPI fraud warning website

> Describe a call, message or QR code. VigilPay tells you if it is a scam, why, and what to do. Free, and it never asks for a PIN or OTP.

Built by Grade 9 students for **HCL Jigsaw · Edition 7 · UPI Fraud Awareness Assistant**.

| Layer | Tech | What it does |
|---|---|---|
| Website | HTML, CSS, JavaScript | Hero demo, chat coach, scam guide, quiz, poster maker, sign-in |
| Backend | Python (Flask) on **Render** | Rule engine, API, rate limiting, Gemini calls |
| AI | **Google Gemini** (free tier) | Friendly explanation. The rules decide the verdict, never the AI |
| Database + login | **Supabase** | Google and email sign-in, anonymous stats, quiz results |
| Tools | **Java**, **C++** | UPI ID checker, offline red-flag scanner for test data |
| Code + CI | **GitHub** + Actions | Runs the tests and builds the Java/C++ tools on every push |

## Code split
About 76% HTML (the whole website, with its styles and scripts inside `frontend/index.html`) and 24% other languages: Python (backend, tests), SQL (database), Java and C++ (tools). The JSON files hold scam data, not code.

## Safety rules built in
- The site never asks for a PIN, OTP, password, card or account number. A reminder is always shown in the chat.
- Numbers that look like a PIN/OTP/account number are removed in the browser **before** anything is sent, and are never stored.
- We store only the *outcome* of a check (scenario, verdict, risk %), never what the user typed.
- Gemini only receives the redacted text, and its reply is checked: any reply that tells someone to share a PIN/OTP is thrown away.
- Quiz names are first names or "User 1", never phone numbers.

## Run it on your computer
```bash
pip install -r requirements.txt
python backend/app.py          # open http://localhost:5000
python tests/test_engine.py            # run the tests
```
It works with no keys at all (rules only). Add keys to turn on AI and sign-in.

## Set up the free services (about 20 minutes)

### 1. Supabase (database + Google login)
1. Create a project at supabase.com. Open **SQL Editor**, paste `supabase/schema.sql`, click **Run**.
2. **Project Settings → API**: copy the *Project URL* and the *anon (public) key*.
3. **Authentication → Providers → Email**: keep it enabled.
4. **Google login:** in Google Cloud Console create an *OAuth client ID* (type: Web application). Add the redirect URI shown in Supabase under **Authentication → Providers → Google**. Paste the Client ID and Secret into Supabase and enable Google.
5. **Authentication → URL Configuration**: set *Site URL* to your Render URL and add it (and `http://localhost:5000`) to *Redirect URLs*.

### 2. Gemini (free AI)
Create a key at <https://aistudio.google.com/apikey>. The free tier has limits, which is why AI explanations are for signed-in users only. The default model is `gemini-3.6-flash`, with `gemini-3.5-flash-lite` as backup. Change `GEMINI_MODEL` if Google renames models.

### 3. GitHub
```bash
git init && git add . && git commit -m "VigilPay prototype"
git branch -M main
git remote add origin https://github.com/YOUR-NAME/vigilpay.git
git push -u origin main
```

### 4. Render (hosting)
1. On render.com choose **New → Blueprint** and pick the GitHub repo (it reads `render.yaml`).
2. Add the environment variables: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `GEMINI_API_KEY`.
3. Deploy. Your site is live at `https://vigilpay.onrender.com` (the free plan sleeps after inactivity, so the first load can take about a minute. The browser's built-in engine answers instantly in the meantime).

**Never** put the Gemini key in the code or on GitHub. Only in Render's environment settings. The Supabase anon key is public by design; no secret Supabase key is needed.

## Java and C++ tools
```bash
cd tools/java && javac UpiIdChecker.java && java UpiIdChecker shop@paytm refund-team@xyz
cd tools/cpp  && g++ -O2 -std=c++17 -o redflag_scanner redflag_scanner.cpp && ./redflag_scanner messages.txt
```

## Before you submit
- Ask a teacher, or a parent who works in a bank, to check every scam's advice in `data/scenarios.json` (the rules say to).
- Replace the statistics' sources in the *Why this matters* section if you update them.
- Check the Telugu on the poster with a Telugu speaker.
- Use the quiz in **before** and **after** mode for your 10-day test. The results appear live on the site.

## Project map
```
frontend/   index.html (all pages, styles and scripts in one HTML file)
backend/    app.py (API), engine.py (rules), ai.py (Gemini), db.py (Supabase)
data/       scenarios.json (16 scams), quiz.json
supabase/   schema.sql
tools/      java/UpiIdChecker.java, cpp/redflag_scanner.cpp
tests/      test_engine.py
```

## Toolkit and community features

Everything below is in `frontend/index.html` and runs in the browser unless noted.

- Triage buttons, emergency checklist, case timeline and printable report, money tracker (saved only on the device)
- Pressure detector, link checker, QR payload reader (jsQR / BarcodeDetector), screenshot analyser and fake-document inspector (Tesseract.js, loaded on first use)
- Payment proof verifier and recipient consistency check (compare with your own bank record; VigilPay never claims a payment is confirmed)
- Community reports: `/api/lookup`, `/api/report`, `/api/flag` (Supabase tables `reports`, `report_flags`; only salted hashes and masked values are stored). Moderate by setting `reports.status` in the Supabase table editor.
- Safe-trade agreement, dispute helper, scam drills (`data/drills.json`), alerts (`data/alerts.json`), English / Hindi / Telugu / Tamil for the main screens
- Optional env vars: `SAFE_BROWSING_API_KEY` (Google Safe Browsing link check), `REPORT_SALT` (hash salt for reports)

- Premium UI layer: scroll progress bar, scroll-spy menu, reveal animations, count-up numbers, back-to-top, installable app (manifest.webmanifest, sw.js, icons)
