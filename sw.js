// Bump this on every release so updated assets actually reach installed
// devices — same convention as jaxmoney (CACHE_NAME -> vN).
const CACHE_NAME = "cardvault-shell-v38";
const ASSETS = [
  "./",
  "./index.html",
  "./app.js",
  "./manifest.json",
  "./apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
      ),
      // Navigation Preload: while this SW is still spinning up, let the
      // browser fire the network request for the page in parallel instead
      // of waiting — shortens the cold-start gap on the "open from home
      // screen" path.
      self.registration.navigationPreload ? self.registration.navigationPreload.enable() : Promise.resolve(),
    ]).then(() => self.clients.claim())
  );
});

// Same-origin only — this app has no remote endpoints by design and never
// fetches anything off-device.
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  if (event.request.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const preloaded = await event.preloadResponse;
          if (preloaded) return preloaded;
          return await fetch(event.request);
        } catch (e) {
          const cache = await caches.open(CACHE_NAME);
          return (await cache.match("./index.html")) || Response.error();
        }
      })()
    );
    return;
  }

  // Stale-while-revalidate for everything else: instant response from
  // cache, quietly refreshed in the background for next time.
  event.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {
      const cached = await cache.match(event.request);
      const networkFetch = fetch(event.request)
        .then((res) => { if (res && res.ok) cache.put(event.request, res.clone()); return res; })
        .catch(() => null);
      return cached || (await networkFetch) || Response.error();
    })
  );
});
