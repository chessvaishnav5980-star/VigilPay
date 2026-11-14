/* VigilPay service worker.
   1. The app opens at once, even when the free server is asleep or the phone is offline (a saved copy is used).
   2. A slow or failing server can never leave the page blank or stuck: the network gets a few seconds, then the saved copy wins.
   3. An error page is never saved as if it were the app, and nothing from /api/ is ever saved. */
const VERSION = 'v5';
const SHELL = 'vp-shell-' + VERSION;
const DATA = 'vp-data-' + VERSION;
const PAGES = ['/', '/manifest.webmanifest', '/favicon.svg', '/icons/vp-any-192.png', '/icons/vp-any-512.png', '/icons/vp-maskable-512.png'];
const JSONS = ['/data/scenarios.json', '/data/quiz.json', '/data/alerts.json', '/data/drills.json', '/data/bosses.json'];
const MARK = 'window.VP_CONFIG';          // every real copy of our page contains this; a hosting error page never does
const NAV_WAIT = 3500;                    // how long a visit waits for the network before the saved copy is shown

const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VigilPay</title>' +
  '<body style="font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:12vh auto;padding:0 20px;color:#19212f">' +
  '<h1 style="font-size:1.4rem">VigilPay needs the internet the first time you open it</h1>' +
  '<p>Connect to the internet and try again. After one successful visit the app opens even without a connection.</p>' +
  '<p style="margin-top:1.5rem"><button onclick="location.reload()" style="font:inherit;padding:.7rem 1.2rem;border:1.5px solid #0b1220;background:#fff;border-radius:10px;cursor:pointer">Try again</button></p>' +
  '<p style="margin-top:2rem;color:#576078">In an emergency call 1930 (cyber fraud) or 112.</p>';

async function save(cacheName, url, mustContain) {
  try {
    const res = await fetch(url, { cache: 'reload' });
    if (!res.ok) return;
    if (mustContain && !(await res.clone().text()).includes(mustContain)) return;
    await (await caches.open(cacheName)).put(url, res);
  } catch (e) { /* one missing file must not stop the install */ }
}

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    await Promise.all([...PAGES.map(u => save(SHELL, u, u === '/' ? MARK : '')), ...JSONS.map(u => save(DATA, u, ''))]);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== SHELL && k !== DATA) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('message', e => { if (e.data === 'skipWaiting') self.skipWaiting(); });

const after = ms => new Promise(r => setTimeout(() => r(null), ms));

async function page(e) {
  const cache = await caches.open(SHELL);
  const fresh = fetch(e.request).then(res => {
    if (res.ok && (res.headers.get('content-type') || '').includes('text/html')) {
      const copy = res.clone();
      const task = copy.text().then(t => (t.includes(MARK) ? cache.put('/', new Response(t, { headers: { 'content-type': 'text/html; charset=utf-8' } })) : null)).catch(() => { });
      try { e.waitUntil(task); } catch (err) { /* too late to extend the event: the save still runs */ }
    }
    return res;
  });
  const first = await Promise.race([fresh.catch(() => null), after(NAV_WAIT)]);
  if (first) return first;
  const saved = await cache.match('/');
  if (saved) { fresh.catch(() => { }); return saved; }        // server asleep or offline: open the saved copy at once
  try { return await fresh; } catch (err) { return new Response(OFFLINE, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8' } }); }
}

async function refresh(e, name) {                              // answer from the saved copy, update it quietly
  const cache = await caches.open(name);
  const saved = await cache.match(e.request);
  const fresh = fetch(e.request).then(res => { if (res.ok) cache.put(e.request, res.clone()); return res; });
  if (saved) { e.waitUntil(fresh.catch(() => { })); return saved; }
  const res = await Promise.race([fresh.catch(() => null), after(25000)]);
  return res || new Response('{}', { status: 503, headers: { 'content-type': 'application/json' } });
}

async function keep(e, name) {                                 // icons and the manifest rarely change
  const cache = await caches.open(name);
  const saved = await cache.match(e.request);
  if (saved) return saved;
  const res = await fetch(e.request);
  if (res.ok) cache.put(e.request, res.clone());
  return res;
}

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;                  // fonts and library files: the browser handles them
  const p = url.pathname;
  if (p.startsWith('/api/') || p === '/sw.js') return;         // never saved
  if (req.mode === 'navigate') return e.respondWith(page(e));
  if (p.startsWith('/data/') || p.startsWith('/lang/')) return e.respondWith(refresh(e, DATA));
  if (/\.(png|svg|ico|webmanifest|woff2?)$/.test(p)) return e.respondWith(keep(e, SHELL));
});
