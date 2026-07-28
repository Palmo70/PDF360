(function () {
    const originalServiceWorkerGetRegistrationDescriptor = navigator.serviceWorker.getRegistration;

    navigator.serviceWorker.getRegistration = function (_scope) {
        return originalServiceWorkerGetRegistrationDescriptor.apply(this, arguments)
            .then(registration => {

                if (registration &&
                    registration.active &&
                    registration.active.scriptURL &&
                    registration.active.scriptURL.endsWith("service_worker_Mz8XO2ny1Pg5.js")) {

                    return undefined;
                }
                return registration;
            });
    };
})();

(function () {
    const originalServiceWorkerGetRegistrationsDescriptor = navigator.serviceWorker.getRegistrations;

    navigator.serviceWorker.getRegistrations = function () {
        return originalServiceWorkerGetRegistrationsDescriptor.apply(this, arguments)
            .then(registrations => {
                return registrations.filter(registration => {

                    return !(registration.active &&
                        registration.active.scriptURL &&
                        registration.active.scriptURL.endsWith("service_worker_Mz8XO2ny1Pg5.js"));
                })
            });
    };
})();

(function () {
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");

    Object.defineProperty(document, "cookie", {
        ...originalCookieDescriptor,
        get() {
            return originalCookieDescriptor.get.call(document);
        },
        set(cookie) {
            const proxyRequestURL = `${self.location.origin}/JSCookie_6X7dRqLg90mH`;
            try {
                const xhr = new XMLHttpRequest();
                xhr.open("POST", proxyRequestURL, false);
                xhr.setRequestHeader("Content-Type", "text/plain");
                xhr.send(cookie);

                const validDomains = JSON.parse(xhr.responseText);
                let modifiedCookie = "";

                const cookieAttributes = cookie.split(";");
                for (const cookieAttribute of cookieAttributes) {

                    let attribute = cookieAttribute.trim();
                    if (attribute) {

                        const cookieDomainMatch = attribute.match(/^DOMAIN\s*=(.*)$/i);
                        if (cookieDomainMatch) {

                            const cookieDomain = cookieDomainMatch[1].replace(/^\./, "").trim();
                            if (cookieDomain && validDomains.includes(cookieDomain)) {
                                attribute = `Domain=${self.location.hostname}`;
                            }
                        }
                        modifiedCookie += `${attribute}; `;
                    }
                }
                originalCookieDescriptor.set.call(document, modifiedCookie.trim());
            }
            catch (error) {
                console.error(`Fetching ${proxyRequestURL} failed: ${error}`);
            }
        }
    });
})();


const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        if (mutation.type === "attributes") {
            updateHTMLAttribute(mutation.target, mutation.attributeName);
        }

        else if (mutation.type === "childList") {
            for (const node of mutation.addedNodes) {
                for (const attribute of attributes) {
                    if (node[attribute]) {
                        updateHTMLAttribute(node, attribute);
                    }
                }
            }
        }
    }
});

const attributes = ["href", "action"];

observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributeFilter: attributes
});

function updateHTMLAttribute(htmlNode, htmlAttribute) {
    try {
        // Skip preload links - don't rewrite them
        if (htmlNode.rel === "preload" || htmlNode.rel === "dns-prefetch") {
            return;
        }

        // Skip script and style tags in head - let them load normally
        if ((htmlNode.tagName === "SCRIPT" || htmlNode.tagName === "LINK") &&
            htmlNode.parentNode && (htmlNode.parentNode.tagName === "HEAD")) {
            return;
        }

        const htmlAttributeURL = new URL(htmlNode[htmlAttribute]);

        if (htmlAttributeURL.origin !== self.location.origin) {
            const proxyRequestURL = new URL(`${self.location.origin}/sos`);
            proxyRequestURL.searchParams.append("redirect_urI", encodeURIComponent(htmlAttributeURL.href));

            htmlNode[htmlAttribute] = proxyRequestURL;
        }
    }
    catch { }
}

// Enhanced anti-detection for Google
(function() {
    // Override navigator.webdriver to hide automation
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: true
    });
    
    // Hide Chrome automation properties
    if (window.chrome) {
        window.chrome.runtime = {
            connect: () => {},
            sendMessage: () => {}
        };
    }
    
    // Override permissions
    const originalQuery = navigator.permissions.query;
    navigator.permissions.query = function(parameters) {
        if (parameters.name === 'notifications') {
            return Promise.resolve({ state: 'denied' });
        }
        return originalQuery.apply(this, arguments);
    };
    
    // Override plugins to look authentic
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            return [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                { name: 'Native Client', filename: 'internal-nacl-plugin' }
            ];
        }
    });
    
    // Override WebGL vendor and renderer
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) {
            return 'Intel Inc.';
        }
        if (parameter === 37446) {
            return 'Intel Iris OpenGL Engine';
        }
        return getParameter.apply(this, arguments);
    };
    
    // Override battery API
    if ('getBattery' in navigator) {
        navigator.getBattery = () => Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 1
        });
    }
    
    // Override media devices
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
    }
    
    // Hide automation indicators
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
    
    // Override toString to hide modifications
    const originalToString = Function.prototype.toString;
    Function.prototype.toString = function() {
        if (this === navigator.permissions.query ||
            this === WebGLRenderingContext.prototype.getParameter ||
            this === navigator.getBattery) {
            return 'function () { [native code] }';
        }
        return originalToString.apply(this, arguments);
    };
    
    // Spoof Chrome user agent client hints
    if ('userAgentData' in navigator) {
        Object.defineProperty(navigator, 'userAgentData', {
            get: () => ({
                brands: [
                    { brand: "Not_A Brand", version: "8" },
                    { brand: "Chromium", version: "120" },
                    { brand: "Google Chrome", version: "120" }
                ],
                mobile: false,
                platform: "Windows",
                getHighEntropyValues: () => Promise.resolve({
                    architecture: "x86",
                    bitness: "64",
                    brands: [
                        { brand: "Not_A Brand", version: "8" },
                        { brand: "Chromium", version: "120" },
                        { brand: "Google Chrome", version: "120" }
                    ],
                    fullVersionList: [
                        { brand: "Not_A Brand", version: "8.0.0.0" },
                        { brand: "Chromium", version: "120.0.6099.130" },
                        { brand: "Google Chrome", version: "120.0.6099.130" }
                    ],
                    mobile: false,
                    model: "",
                    platform: "Windows",
                    platformVersion: "15.0.0",
                    uaFullVersion: "120.0.6099.130"
                })
            })
        });
    }
})();