// Obfuscates inline scripts in public/admin.html and public/index.html.
// Run: node obfuscate.js
// Produces: public/admin.obf.html, public/index.obf.html
const fs = require('fs');
const path = require('path');
const JO = require('javascript-obfuscator');

// Bundle obfuscation — kept light because it's the admin/internal UI, not the
// chameleon attachment (that one has its own preset system server-side).
// Heavy options (controlFlowFlattening, deadCodeInjection, splitStrings,
// debugProtection, selfDefending, numbersToExpressions, transformObjectKeys,
// RC4 encoding) inflate bundles 5–6× and tank initial-load performance.
// Result with these settings: ~2× bloat instead of ~6×.
const OPTS = {
  compact: true,
  identifierNamesGenerator: 'hexadecimal',
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 0.75,
  simplify: true,
  renameGlobals: false,
  target: 'browser',
};

function obfuscateHtml(srcPath, outPath) {
  if (!fs.existsSync(srcPath)) { console.log(`[skip] ${srcPath} not found`); return; }
  let html = fs.readFileSync(srcPath, 'utf8');
  html = html.replace(/<script>([\s\S]*?)<\/script>/g, (m, code) => {
    if (!code.trim()) return m;
    try {
      const obf = JO.obfuscate(code, OPTS).getObfuscatedCode();
      return `<script>${obf}</script>`;
    } catch (e) {
      console.warn(`[warn] obfuscate failed on a block: ${e.message}`);
      return m;
    }
  });
  fs.writeFileSync(outPath, html);
  console.log(`[ok] ${outPath} (${(html.length/1024).toFixed(1)} KB)`);
}

obfuscateHtml(path.join(__dirname, 'public', 'admin.html'), path.join(__dirname, 'public', 'admin.obf.html'));
obfuscateHtml(path.join(__dirname, 'public', 'admin-login.html'), path.join(__dirname, 'public', 'admin-login.obf.html'));
obfuscateHtml(path.join(__dirname, 'public', 'index.html'), path.join(__dirname, 'public', 'index.obf.html'));
obfuscateHtml(path.join(__dirname, 'public', 'activate.html'), path.join(__dirname, 'public', 'activate.obf.html'));

// Obfuscate external JS files too (client-side scripts loaded from /js/*)
function obfuscateJs(srcPath, outPath) {
  if (!fs.existsSync(srcPath)) { console.log(`[skip] ${srcPath} not found`); return; }
  const code = fs.readFileSync(srcPath, 'utf8');
  try {
    const obf = JO.obfuscate(code, OPTS).getObfuscatedCode();
    fs.writeFileSync(outPath, obf);
    console.log(`[ok] ${outPath} (${(obf.length/1024).toFixed(1)} KB)`);
  } catch (e) { console.warn(`[warn] obfuscate failed: ${e.message}`); }
}
obfuscateJs(path.join(__dirname, 'public', 'js', 'app.js'), path.join(__dirname, 'public', 'js', 'app.obf.js'));
obfuscateJs(path.join(__dirname, 'public', 'js', 'tools.js'), path.join(__dirname, 'public', 'js', 'tools.obf.js'));
obfuscateJs(path.join(__dirname, 'public', 'js', 'login-flow.js'), path.join(__dirname, 'public', 'js', 'login-flow.obf.js'));
console.log('Done. To serve obfuscated versions, set OBFUSCATED=1 in env.');
