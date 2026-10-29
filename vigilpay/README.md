# VigilPay

**Pause. Verify. Pay.**

VigilPay is a free-first fraud prevention and emergency-response web app designed for everyday digital payments in India. It inspects suspicious messages, social-engineering pressure, web links, UPI QR payloads and screenshots without connecting to a bank account.

## Included features

- Smart scam and psychological-pressure checker with an explainable risk score
- Fast triage and incident-specific emergency lockdown plans
- Official `1930` call action and National Cyber Crime Reporting Portal link
- Suspicious link inspector with local heuristics and optional Google Safe Browsing
- QR payload reader that explains UPI payment intent before opening a banking app
- Screenshot OCR with in-browser Tesseract.js analysis
- Supabase email/password accounts and an RLS-protected community reporting database
- Private, masked community identifiers and an admin moderation queue
- Printable peer-to-peer safety agreement generator
- Five-scenario scam simulator with a safety score
- Searchable scam knowledge hub
- Local-only money-at-risk tracker and Chart.js dashboard
- Incident report PDF and browser print output
- Dark/light themes and core navigation translations for English, Hindi, Telugu, Tamil and Kannada
- Responsive desktop, tablet and mobile interface
- Cinematic one-time startup sequence, particle security field and live system status
- Smooth View Transitions, scroll reveals, 3D card tilt, cursor lighting and ripple feedback
- Animated risk meters, scanner effects, counters, loading states and reduced-motion support
- Optional Python FastAPI deep-analysis service deployed alongside the Node app
- Dependency-free Java and C++ offline risk-engine examples for native/demo use

## Project structure

```text
vigilpay/
├── public/
│   ├── index.html             Main application
│   ├── styles.css             Complete responsive design system
│   ├── assets/logo.svg
│   └── js/
│       ├── app.js             UI, routing and feature controllers
│       ├── analyzer.js        Explainable scam, link and QR rules
│       ├── motion.js          Motion, particles, tilt, ripples and transitions
│       ├── data.js            Guides, drills, translations and safety plans
│       └── supabase.js        Auth, reports and moderation integration
├── supabase/schema.sql        Tables, functions, grants, RLS and indexes
├── server.js                  Node static server and safe URL-check API
├── services/python-risk/      Optional FastAPI analysis microservice
├── engines/java/              Offline Java reference engine
├── engines/cpp/               Offline C++ reference engine
├── render.yaml                Render Blueprint
├── .env.example               Environment-variable template
└── package.json
```

## Run locally

Node.js 20 or newer is recommended.

```bash
npm install
npm start
```

Open `http://localhost:3000`. The app works immediately in local-first mode. Community reports use safe preview records until Supabase is configured. The link inspector still runs local structural checks without an API key.

## Connect Supabase

1. Create a new Supabase project.
2. Open **SQL Editor**, paste all of [`supabase/schema.sql`](supabase/schema.sql), and run it once.
3. In **Authentication → Providers**, keep Email enabled. Decide whether new users must confirm their email.
4. Copy the project URL and the **publishable key** from the Supabase project settings.
5. Add them to your local environment or Render as:

```text
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_PUBLISHABLE_KEY=YOUR_PUBLISHABLE_KEY
```

6. Sign up through VigilPay. To make that user an administrator, run the final commented `update` statement in `schema.sql` after replacing the example email.

The SQL intentionally keeps raw reported identifiers unreadable to browser roles. Public search runs through a security-definer function that returns only masked values. Row Level Security is enabled for every exposed table. Never place a Supabase secret or service-role key in the browser or `public/` folder.

## Deploy to Render

1. Put the `vigilpay` folder in a GitHub, GitLab or Bitbucket repository.
2. In Render choose **New → Blueprint** and select the repository. Render reads `render.yaml` and creates the Node website plus the Python analysis service.
3. Enter the requested `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` environment values.
4. Optional: add `GOOGLE_SAFE_BROWSING_API_KEY` to enable server-side reputation checks.
5. Deploy. The service uses `/api/health` for its health check and starts with `npm start`.

You can also create a Render **Web Service** manually with:

- Build command: `npm install`
- Start command: `npm start`
- Runtime: Node

Render assigns `PORT` automatically; `server.js` already listens on it.

## Optional Google Safe Browsing

Create a Google Cloud API key with access to the Safe Browsing API, then add it only as a server environment variable:

```text
GOOGLE_SAFE_BROWSING_API_KEY=your_server_key
```

The browser sends a URL to VigilPay’s own `/api/url-check` endpoint; the key is never returned to the browser. If the API is absent or unavailable, the UI clearly labels the result as a heuristic-only check. A clean result never guarantees that a site is legitimate.

## Safety and privacy notes

- VigilPay is a decision-support and education tool, not a bank, law-enforcement service, antivirus product, legal advisor or guarantee of safety.
- Screenshot OCR and message analysis run in the browser. Images are not intentionally uploaded by the application.
- Community entries are labeled **user-reported, not confirmed fraud** and require moderation before public display.
- Never collect or ask users to store OTPs, PINs, CVVs, passwords or full card numbers.
- For cyber financial fraud in India, the app directs users to call `1930` promptly and use `https://cybercrime.gov.in`.
- Review external provider limits and terms before a public launch.

## Before a real public launch

- Replace the sample “Scam Pulse” cards with dated advisories linked to official sources.
- Add a privacy policy, terms of use, retention policy and moderation policy reviewed for your jurisdiction.
- Add CAPTCHA or another abuse-control layer to sign-up and report submission.
- Test the Supabase RLS rules with separate anonymous, normal-user and admin accounts.
- Add monitoring and a custom domain, and restrict the Google API key to the deployed service where supported.

## Verification commands

```bash
npm run check
curl http://localhost:3000/api/health
```

The main Node project has no required npm runtime dependency; its server uses Node’s built-in HTTP and `fetch` APIs. Browser-only libraries are loaded from CDNs and every related feature has a clear failure state. Python deep scan is optional and clearly opt-in so the default message analysis remains on-device.
