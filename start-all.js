#!/usr/bin/env node
/**
 * Start both the main server (port 3000) and proxy server (port 3001)
 */

const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Starting PDF360 with Proxy Integration\n');

// Start main server (port 3000)
console.log('📍 Starting Main Server on port 3000...');
const mainServer = spawn('node', ['server.js'], {
  cwd: __dirname,
  stdio: 'inherit',
  env: { ...process.env, PORT: '3000' }
});

mainServer.on('error', (err) => {
  console.error('❌ Main server error:', err);
});

// Start proxy server (port 3001) after a short delay
setTimeout(() => {
  console.log('\n📍 Starting Proxy Server on port 3001...');
  const proxyServer = spawn('node', ['proxy_server.js'], {
    cwd: path.join(__dirname, 'Proxy'),
    stdio: 'inherit',
    env: { ...process.env, PROXY_PORT: '3001' }
  });

  proxyServer.on('error', (err) => {
    console.error('❌ Proxy server error:', err);
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down servers...');
    mainServer.kill();
    proxyServer.kill();
    process.exit(0);
  });
}, 2000);
