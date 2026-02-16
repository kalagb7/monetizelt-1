/* sw.js - Monetizelt (2026-02-05) */
const CACHE_NAME = "monetizelt-v3";
const APP_SHELL = [
    "/",
    "/index.html",
];

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(APP_SHELL))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

function isStaticAsset(url) {
    return /\.(?:css|js|png|jpg|jpeg|gif|svg|webp|ico|txt|map)$/i.test(url.pathname);
}

self.addEventListener("fetch", (event) => {
    const req = event.request;

    // Only handle GET
    if (req.method !== "GET") return;

    const url = new URL(req.url);

    // IMPORTANT: do not hijack cross-origin requests (fixes weird Response conversion issues)
    if (url.origin !== self.location.origin) return;

    // Do not cache Cloud Functions/API style paths if you ever proxy them
    if (url.pathname.includes("cloudfunctions") || url.pathname.startsWith("/__/")) return;

    // Navigation: network-first, fallback cache, fallback basic response
    if (req.mode === "navigate") {
        event.respondWith((async () => {
            try {
                const fresh = await fetch(req);
                return fresh;
            } catch (e) {
                const cached = await caches.match("/index.html");
                if (cached) return cached;
                return new Response("Offline", { status: 503, headers: { "Content-Type": "text/plain" } });
            }
        })());
        return;
    }

    // Static assets: cache-first
    if (isStaticAsset(url)) {
        event.respondWith((async () => {
            const cached = await caches.match(req);
            if (cached) return cached;
            try {
                const fresh = await fetch(req);
                const cache = await caches.open(CACHE_NAME);
                cache.put(req, fresh.clone());
                return fresh;
            } catch (e) {
                return new Response("", { status: 504 });
            }
        })());
        return;
    }

    // Default: pass-through
});