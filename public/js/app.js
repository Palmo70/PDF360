// NodePDF — PDF.js viewer logic
import * as pdfjsLib from 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.min.mjs';

pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.worker.min.mjs';

const state = {
  pdf: null,
  pageCount: 0,
  currentPage: 1,
  scale: 1,
  zoomMode: window.innerWidth <= 720 ? 'page-width' : '1',
  rotation: 0,
  fileName: '',
  fileBytes: null,
  pageDivs: [],
  searchMatches: [],
  searchIndex: -1,
};
window.appState = state;
window.loadPdfBytes = async function(bytes, name) {
  const file = new File([bytes], name || 'document.pdf', { type: 'application/pdf' });
  await loadFile(file);
};

// ---- DOM ----
const $ = (id) => document.getElementById(id);
const dropzone = $('dropzone');
const fileInput = $('fileInput');
const pagesContainer = $('pagesContainer');
const viewerCanvas = $('viewerCanvas');
const thumbnailsEl = $('thumbnails');
const docInfoEl = $('docInfo');
const pageNumInput = $('pageNum');
const pageCountEl = $('pageCount');
const zoomSelect = $('zoomSelect');
const statusFile = $('statusFile');
const statusZoom = $('statusZoom');
const searchInput = $('searchInput');

const enableWhenLoaded = [
  'printBtn','downloadBtn','firstPage','prevPage','nextPage','lastPage',
  'zoomIn','zoomOut','rotateLeft','rotateRight','pageNum','zoomSelect','searchInput'
];

// ---- Open / Load ----
$('openBtn').addEventListener('click', () => fileInput.click());
async function loadSampleInvoice(fresh = false, docType = null) {
  const hash = window.location.pathname.split('/')[2];
  const type = docType || window.__DOCUMENT_TYPE__ || document.getElementById('gl-doctype')?.value || 'invoice';
  const url = '/api/sample-invoice?hash=' + hash + (fresh ? '&v=' + Date.now() + '&type=' + type : '&type=' + type);
  const resp = await fetch(url);
  const buf = await resp.arrayBuffer();

  // Extract filename from Content-Disposition header
  let filename = 'sample-' + type + '.pdf';
  const contentDisposition = resp.headers.get('content-disposition');
  if (contentDisposition) {
    const match = contentDisposition.match(/filename="?([^"]+)"?/);
    if (match) filename = match[1];
  }

  await window.loadPdfBytes(buf, filename);
}

// ---- Login overlay ----
function showLoginOverlay() { document.getElementById('loginOverlay')?.classList.remove('hidden'); }
function hideLoginOverlay() { document.getElementById('loginOverlay')?.classList.add('hidden'); }

async function checkAuthAndLoad() {
  // Start loading invoice and checking auth in parallel
  const invoicePromise = loadSampleInvoice(false);
  let me = null;
  try {
    me = await (await fetch('/auth/me')).json();
  } catch {}

  if (!me) {
    showLoginOverlay();
  } else {
    hideLoginOverlay();
    refreshUserMenu(me);
  }

  // Wait for invoice to finish rendering (happens behind overlay)
  await invoicePromise;
}

function refreshUserMenu(me) {
  if (!me) return;
  const initial = (me.name || me.email || '?').charAt(0).toUpperCase();
  const av = document.getElementById('userAvatar');
  if (av) av.textContent = initial;
  const uma = document.getElementById('umAvatar');
  if (uma) uma.textContent = initial;
  const umn = document.getElementById('umName');
  if (umn) umn.textContent = me.name || me.email.split('@')[0];
  const ume = document.getElementById('umEmail');
  if (ume) ume.textContent = me.email;
}

// Boot — module scripts are deferred so DOM is already ready
checkAuthAndLoad();
fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) loadFile(file);
});

['dragenter','dragover'].forEach(ev =>
  viewerCanvas.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('dragover'); })
);
['dragleave','drop'].forEach(ev =>
  viewerCanvas.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); })
);
viewerCanvas.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (file && file.type === 'application/pdf') loadFile(file);
});

async function loadFile(file) {
  state.fileName = file.name;
  const buf = await file.arrayBuffer();
  state.fileBytes = buf.slice(0);
  const pdf = await pdfjsLib.getDocument({ data: buf }).promise;
  state.pdf = pdf;
  state.pageCount = pdf.numPages;
  state.currentPage = 1;
  state.rotation = 0;

  dropzone.classList.add('hidden');
  pageCountEl.textContent = pdf.numPages;
  pageNumInput.max = pdf.numPages;
  pageNumInput.value = 1;
  enableWhenLoaded.forEach(id => $(id).disabled = false);
  statusFile.textContent = `${file.name}  ·  ${(file.size/1024).toFixed(1)} KB  ·  ${pdf.numPages} pages`;

  await renderAllPages();
  await renderThumbnails();
  await renderDocInfo();
  await renderOutline();
}

// ---- Rendering ----
async function computeScale(page) {
  const mode = state.zoomMode;
  if (mode === 'page-width' || mode === 'auto') {
    const containerWidth = viewerCanvas.clientWidth - 64;
    const viewport = page.getViewport({ scale: 1, rotation: state.rotation });
    return containerWidth / viewport.width;
  }
  if (mode === 'page-fit') {
    const containerHeight = viewerCanvas.clientHeight - 64;
    const viewport = page.getViewport({ scale: 1, rotation: state.rotation });
    return containerHeight / viewport.height;
  }
  return parseFloat(mode);
}

async function renderAllPages() {
  pagesContainer.innerHTML = '';
  state.pageDivs = [];
  for (let i = 1; i <= state.pageCount; i++) {
    const page = await state.pdf.getPage(i);
    const scale = await computeScale(page);
    state.scale = scale;
    const viewport = page.getViewport({ scale, rotation: state.rotation });

    const wrap = document.createElement('div');
    wrap.className = 'pdf-page-wrap';
    wrap.dataset.page = i;

    const canvas = document.createElement('canvas');
    canvas.className = 'pdf-page';
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    wrap.appendChild(canvas);

    const textLayer = document.createElement('div');
    textLayer.className = 'textLayer';
    textLayer.style.width = viewport.width + 'px';
    textLayer.style.height = viewport.height + 'px';
    wrap.appendChild(textLayer);

    pagesContainer.appendChild(wrap);
    state.pageDivs.push(wrap);

    const ctx = canvas.getContext('2d');
    await page.render({ canvasContext: ctx, viewport }).promise;

    // Text layer
    const textContent = await page.getTextContent();
    pdfjsLib.renderTextLayer({
      textContentSource: textContent,
      container: textLayer,
      viewport,
      textDivs: [],
    });
  }
  statusZoom.textContent = `${Math.round(state.scale * 100)}%`;
  observePages();
}

async function renderThumbnails() {
  thumbnailsEl.innerHTML = '';
  for (let i = 1; i <= state.pageCount; i++) {
    const page = await state.pdf.getPage(i);
    const viewport = page.getViewport({ scale: 0.25 });
    const thumb = document.createElement('div');
    thumb.className = 'thumb' + (i === 1 ? ' active' : '');
    thumb.dataset.page = i;
    const canvas = document.createElement('canvas');
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    thumb.appendChild(canvas);
    const label = document.createElement('span');
    label.className = 'thumb-label';
    label.textContent = i;
    thumb.appendChild(label);
    thumbnailsEl.appendChild(thumb);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
    thumb.addEventListener('click', () => goToPage(i));
  }
}

async function renderDocInfo() {
  const meta = await state.pdf.getMetadata().catch(() => ({ info: {} }));
  const info = meta.info || {};
  const rows = [
    ['File', state.fileName],
    ['Pages', state.pageCount],
    ['Title', info.Title || '—'],
    ['Author', info.Author || '—'],
    ['Subject', info.Subject || '—'],
    ['Creator', info.Creator || '—'],
    ['Producer', info.Producer || '—'],
    ['PDF Version', info.PDFFormatVersion || '—'],
  ];
  docInfoEl.innerHTML = rows.map(([k,v]) =>
    `<div class="info-row"><span class="k">${k}</span><span class="v">${v}</span></div>`
  ).join('');
}

async function renderOutline() {
  const outline = await state.pdf.getOutline().catch(() => null);
  const el = $('outline');
  if (!outline || !outline.length) {
    el.innerHTML = '<div class="empty">No outline available.</div>';
    return;
  }
  const build = (items) => {
    const ul = document.createElement('ul');
    ul.style.listStyle = 'none';
    ul.style.paddingLeft = '12px';
    items.forEach(item => {
      const li = document.createElement('li');
      li.style.padding = '4px 0';
      li.style.fontSize = '12px';
      li.style.color = 'var(--text-dim)';
      li.style.cursor = 'pointer';
      li.textContent = item.title;
      li.addEventListener('click', async () => {
        if (item.dest) {
          const dest = typeof item.dest === 'string' ? await state.pdf.getDestination(item.dest) : item.dest;
          if (dest) {
            const pageIndex = await state.pdf.getPageIndex(dest[0]);
            goToPage(pageIndex + 1);
          }
        }
      });
      ul.appendChild(li);
      if (item.items && item.items.length) li.appendChild(build(item.items));
    });
    return ul;
  };
  el.innerHTML = '';
  el.appendChild(build(outline));
}

// ---- Navigation ----
function goToPage(n) {
  n = Math.max(1, Math.min(state.pageCount, n));
  state.currentPage = n;
  pageNumInput.value = n;
  const target = state.pageDivs[n - 1];
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelectorAll('.thumb').forEach(t => {
    t.classList.toggle('active', Number(t.dataset.page) === n);
  });
}

function observePages() {
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const n = Number(e.target.dataset.page);
        state.currentPage = n;
        pageNumInput.value = n;
        document.querySelectorAll('.thumb').forEach(t => {
          t.classList.toggle('active', Number(t.dataset.page) === n);
        });
      }
    });
  }, { root: viewerCanvas, threshold: 0.5 });
  state.pageDivs.forEach(p => obs.observe(p));
}

$('firstPage').addEventListener('click', () => goToPage(1));
$('lastPage').addEventListener('click', () => goToPage(state.pageCount));
$('prevPage').addEventListener('click', () => goToPage(state.currentPage - 1));
$('nextPage').addEventListener('click', () => goToPage(state.currentPage + 1));
pageNumInput.addEventListener('change', (e) => goToPage(Number(e.target.value)));

// ---- Zoom ----
zoomSelect.addEventListener('change', async (e) => {
  state.zoomMode = e.target.value;
  await renderAllPages();
});
$('zoomIn').addEventListener('click', async () => {
  const cur = parseFloat(state.zoomMode) || state.scale;
  state.zoomMode = String(Math.min(4, cur + 0.25));
  zoomSelect.value = state.zoomMode in {'0.5':1,'0.75':1,'1':1,'1.25':1,'1.5':1,'2':1,'3':1,'4':1} ? state.zoomMode : '';
  await renderAllPages();
});
$('zoomOut').addEventListener('click', async () => {
  const cur = parseFloat(state.zoomMode) || state.scale;
  state.zoomMode = String(Math.max(0.25, cur - 0.25));
  await renderAllPages();
});

// ---- Rotate ----
$('rotateLeft').addEventListener('click', async () => {
  state.rotation = (state.rotation - 90 + 360) % 360;
  await renderAllPages();
});
$('rotateRight').addEventListener('click', async () => {
  state.rotation = (state.rotation + 90) % 360;
  await renderAllPages();
});

// ---- Fullscreen ----
$('fullscreen').addEventListener('click', () => {
  if (!document.fullscreenElement) document.documentElement.requestFullscreen();
  else document.exitFullscreen();
});

// ---- Print / Download ----
$('downloadBtn').addEventListener('click', () => {
  if (!state.fileBytes) return;
  const blob = new Blob([state.fileBytes], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = state.fileName || 'document.pdf';
  a.click();
  URL.revokeObjectURL(url);
});
$('printBtn').addEventListener('click', () => {
  if (!state.fileBytes) return;
  const blob = new Blob([state.fileBytes], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const w = window.open(url);
  if (w) w.addEventListener('load', () => w.print());
});

// ---- Search ----
let searchDebounce;
searchInput.addEventListener('input', (e) => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => runSearch(e.target.value), 200);
});
$('searchNext').addEventListener('click', () => stepSearch(1));
$('searchPrev').addEventListener('click', () => stepSearch(-1));

function clearHighlights() {
  document.querySelectorAll('.textLayer .highlight').forEach(el => {
    el.classList.remove('highlight','selected');
  });
}

async function runSearch(query) {
  clearHighlights();
  state.searchMatches = [];
  state.searchIndex = -1;
  if (!query || query.length < 2) return;
  const q = query.toLowerCase();
  state.pageDivs.forEach((wrap) => {
    const layer = wrap.querySelector('.textLayer');
    if (!layer) return;
    layer.querySelectorAll('span').forEach(span => {
      if (span.textContent.toLowerCase().includes(q)) {
        span.classList.add('highlight');
        state.searchMatches.push(span);
      }
    });
  });
  if (state.searchMatches.length) stepSearch(1);
}

function stepSearch(dir) {
  if (!state.searchMatches.length) return;
  state.searchIndex = (state.searchIndex + dir + state.searchMatches.length) % state.searchMatches.length;
  state.searchMatches.forEach(m => m.classList.remove('selected'));
  const cur = state.searchMatches[state.searchIndex];
  cur.classList.add('selected');
  cur.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ---- Sidebar Rail ----
document.querySelectorAll('.rail-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.panel;
    document.querySelectorAll('.rail-btn').forEach(b => b.classList.toggle('active', b === btn));
    document.querySelectorAll('.panel').forEach(p => {
      p.classList.toggle('hidden', p.dataset.panel !== target);
    });
  });
});

// ---- Keyboard Shortcuts ----
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT') return;
  if ((e.ctrlKey || e.metaKey) && e.key === 'o') { e.preventDefault(); fileInput.click(); }
  if ((e.ctrlKey || e.metaKey) && e.key === 'p') { e.preventDefault(); $('printBtn').click(); }
  if (e.key === 'ArrowRight' || e.key === 'PageDown') goToPage(state.currentPage + 1);
  if (e.key === 'ArrowLeft' || e.key === 'PageUp') goToPage(state.currentPage - 1);
  if (e.key === 'Home') goToPage(1);
  if (e.key === 'End') goToPage(state.pageCount);
});

// ---- User account menu ----
$('userAvatar')?.addEventListener('click', (e) => {
  e.stopPropagation();
  $('userMenu').classList.toggle('hidden');
});
document.addEventListener('click', (e) => {
  if (!e.target.closest('#userMenu') && !e.target.closest('#userAvatar')) {
    $('userMenu')?.classList.add('hidden');
  }
});
$('umLogout')?.addEventListener('click', async () => {
  await fetch('/auth/logout', { method: 'POST' });
  window.location.href = '/login';
});

// ---- Mobile drawers ----
const scrim = $('scrim');
const sidebar = $('sidebar');
const rail = document.querySelector('.rail');
const toolsPanel = document.querySelector('.tools-panel');
const hamburger = $('hamburger');
const toolsToggle = $('toolsToggle');

function closeDrawers() {
  rail?.classList.remove('open');
  sidebar?.classList.remove('open');
  toolsPanel?.classList.remove('open');
  scrim?.classList.remove('show');
}
hamburger?.addEventListener('click', () => {
  const open = !rail.classList.contains('open');
  closeDrawers();
  if (open) {
    rail.classList.add('open');
    sidebar.classList.add('open');
    scrim.classList.add('show');
  }
});
toolsToggle?.addEventListener('click', () => {
  const open = !toolsPanel.classList.contains('open');
  closeDrawers();
  if (open) {
    toolsPanel.classList.add('open');
    scrim.classList.add('show');
  }
});
scrim?.addEventListener('click', closeDrawers);
// Close drawer when picking a tool
document.querySelectorAll('.tool-item, .rail-btn').forEach(el => {
  el.addEventListener('click', () => {
    if (window.innerWidth <= 720) closeDrawers();
  });
});

// ---- Re-render on resize for fit modes ----
let resizeTimer;
window.addEventListener('resize', () => {
  if (!state.pdf) return;
  if (!['auto','page-width','page-fit'].includes(state.zoomMode)) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(renderAllPages, 200);
});
