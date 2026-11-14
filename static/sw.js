// Minimal service worker: makes the app installable and shows a friendly page when offline.
// It never caches API calls or account pages, so login and history are always live.
const CACHE = "translator-shell-v1";
const OFFLINE = new Response(
  "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>Offline</title>" +
  "<body style='font:18px Georgia,serif;padding:2rem;text-align:center'><h1>You're offline</h1>" +
  "<p>Translator needs a connection to your server. Check your internet and try again.</p>",
  {headers: {"Content-Type": "text/html; charset=utf-8"}});

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(["/static/icons/icon-192.png", "/static/icons/icon-512.png"])).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  if (req.mode === "navigate") { e.respondWith(fetch(req).catch(() => OFFLINE.clone())); return; }
  if (url.pathname.startsWith("/static/icons/")) e.respondWith(caches.match(req).then(r => r || fetch(req)));
});
