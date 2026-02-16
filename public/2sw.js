/* 2sw.js - Monetizelt (2026-02-05) */
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
    if (req.method !== "GET") return;

    const url = new URL(req.url);

    // Avoid cross-origin issues (this is what was breaking with "Failed to convert value to Response")
    if (url.origin !== self.location.origin) return;

    if (req.mode === "navigate") {
        event.respondWith((async () => {
            try {
                return await fetch(req);
            } catch {
                const cached = await caches.match("/index.html");
                return cached || new Response("Offline", { status: 503, headers: { "Content-Type": "text/plain" } });
            }
        })());
        return;
    }

    if (isStaticAsset(url)) {
        event.respondWith((async () => {
            const cached = await caches.match(req);
            if (cached) return cached;
            try {
                const fresh = await fetch(req);
                const cache = await caches.open(CACHE_NAME);
                cache.put(req, fresh.clone());
                return fresh;
            } catch {
                return new Response("", { status: 504 });
            }
        })());
    }
});