// Adobe Acrobat clone — tool implementations using pdf-lib
const { PDFDocument, StandardFonts, rgb, degrees } = PDFLib;

const $ = (id) => document.getElementById(id);
const overlay = $('modalOverlay');
const modal = $('modal');
const modalTitle = $('modalTitle');
const modalBody = $('modalBody');
const modalFooter = $('modalFooter');
const toastEl = $('toast');

// ---- Modal helpers ----
function openModal({ title, body, footer = '', wide = false }) {
  modalTitle.textContent = title;
  modalBody.innerHTML = body;
  modalFooter.innerHTML = footer;
  modal.classList.toggle('wide', wide);
  overlay.classList.remove('hidden');
}
function closeModal() { overlay.classList.add('hidden'); }
$('modalClose').addEventListener('click', closeModal);
overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

function toast(msg, type = '') {
  toastEl.textContent = msg;
  toastEl.className = 'toast ' + type;
  setTimeout(() => toastEl.classList.add('hidden'), 2800);
}

function downloadBytes(bytes, name) {
  const blob = new Blob([bytes], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

function needPdf() {
  if (!window.appState?.fileBytes) {
    toast('Open a PDF first', 'error');
    return false;
  }
  return true;
}

async function getCurrentPdfDoc() {
  return await PDFDocument.load(window.appState.fileBytes.slice(0));
}

// ============ TOOL ROUTER ============
document.querySelectorAll('.tool-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tool = btn.dataset.tool;
    const fn = tools[tool];
    if (fn) fn();
  });
});

const tools = {};

// ============ 1. EDIT A PDF ============
tools.edit = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Edit a PDF',
    body: `
      <p>Add text or images to any page. Click on a page after picking a tool.</p>
      <label>Tool</label>
      <select id="editTool">
        <option value="text">Add text</option>
        <option value="image">Add image</option>
      </select>
      <label>Text content (for "Add text")</label>
      <input type="text" id="editText" value="Sample text" />
      <label>Font size</label>
      <input type="number" id="editSize" value="14" min="6" max="72" />
    `,
    footer: `
      <button class="btn" id="editCancel">Cancel</button>
      <button class="btn primary" id="editStart">Start placing</button>
    `,
  });
  $('editCancel').onclick = closeModal;
  $('editStart').onclick = () => {
    const mode = $('editTool').value;
    const text = $('editText').value;
    const size = parseInt($('editSize').value);
    closeModal();
    if (mode === 'text') startPlaceText(text, size);
    else startPlaceImage();
  };
};

function startPlaceText(text, size) {
  toast('Click any page to place text');
  const handler = (e) => {
    const wrap = e.target.closest('.pdf-page-wrap');
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    addPlacedText(wrap, x, y, text, size);
    document.removeEventListener('click', handler, true);
  };
  document.addEventListener('click', handler, true);
}

function addPlacedText(wrap, x, y, text, size) {
  const div = document.createElement('div');
  div.className = 'placed-item placed-text';
  div.contentEditable = true;
  div.textContent = text;
  div.style.left = x + 'px';
  div.style.top = y + 'px';
  div.style.fontSize = size + 'px';
  div.dataset.page = wrap.dataset.page;
  div.dataset.kind = 'text';
  div.dataset.size = size;
  makeDraggable(div);
  wrap.appendChild(div);
  setTimeout(() => { div.focus(); document.execCommand('selectAll', false, null); }, 50);
}

function makeDraggable(el) {
  let sx, sy, ox, oy, dragging = false;
  el.addEventListener('mousedown', (e) => {
    if (el.classList.contains('editing')) return;
    dragging = true;
    sx = e.clientX; sy = e.clientY;
    ox = parseFloat(el.style.left); oy = parseFloat(el.style.top);
    e.stopPropagation();
  });
  document.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    el.style.left = (ox + e.clientX - sx) + 'px';
    el.style.top = (oy + e.clientY - sy) + 'px';
  });
  document.addEventListener('mouseup', () => dragging = false);
  el.addEventListener('dblclick', () => { el.classList.add('editing'); el.focus(); });
  el.addEventListener('blur', () => el.classList.remove('editing'));
}

function startPlaceImage() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const url = URL.createObjectURL(file);
    toast('Click any page to place image');
    const handler = (ev) => {
      const wrap = ev.target.closest('.pdf-page-wrap');
      if (!wrap) return;
      const rect = wrap.getBoundingClientRect();
      const x = ev.clientX - rect.left;
      const y = ev.clientY - rect.top;
      const div = document.createElement('div');
      div.className = 'placed-item placed-image';
      div.style.left = x + 'px';
      div.style.top = y + 'px';
      div.dataset.page = wrap.dataset.page;
      div.dataset.kind = 'image';
      div.dataset.src = url;
      const img = document.createElement('img');
      img.src = url; img.style.maxWidth = '160px';
      div.appendChild(img);
      makeDraggable(div);
      wrap.appendChild(div);
      document.removeEventListener('click', handler, true);
    };
    document.addEventListener('click', handler, true);
  };
  input.click();
}

// Save edits → bake into a new PDF
async function bakeOverlaysIntoPdf() {
  const doc = await getCurrentPdfDoc();
  const helv = await doc.embedFont(StandardFonts.Helvetica);
  const items = document.querySelectorAll('.placed-item');
  for (const item of items) {
    const pageIdx = parseInt(item.dataset.page) - 1;
    const page = doc.getPage(pageIdx);
    const wrap = item.closest('.pdf-page-wrap');
    const wrapRect = wrap.getBoundingClientRect();
    const itemRect = item.getBoundingClientRect();
    const scaleX = page.getWidth() / wrapRect.width;
    const scaleY = page.getHeight() / wrapRect.height;
    const x = (itemRect.left - wrapRect.left) * scaleX;
    const yTop = (itemRect.top - wrapRect.top) * scaleY;
    if (item.dataset.kind === 'text') {
      const size = parseInt(item.dataset.size) * scaleY;
      const text = item.textContent;
      page.drawText(text, {
        x, y: page.getHeight() - yTop - size,
        size, font: helv, color: rgb(0, 0, 0),
      });
    } else if (item.dataset.kind === 'image') {
      const resp = await fetch(item.dataset.src);
      const buf = await resp.arrayBuffer();
      let img;
      try { img = await doc.embedPng(buf); }
      catch { img = await doc.embedJpg(buf); }
      const w = itemRect.width * scaleX;
      const h = itemRect.height * scaleY;
      page.drawImage(img, { x, y: page.getHeight() - yTop - h, width: w, height: h });
    }
  }
  return await doc.save();
}

// Save button — auto wires when overlays exist
document.addEventListener('keydown', async (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's' && document.querySelectorAll('.placed-item, .comment-pin').length) {
    e.preventDefault();
    const bytes = await bakeOverlaysIntoPdf();
    downloadBytes(bytes, 'edited-' + window.appState.fileName);
    toast('Saved edited PDF', 'success');
  }
});

// ============ 2. EXPORT A PDF ============
tools.export = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Export a PDF',
    body: `
      <p>Convert your PDF to another format.</p>
      <label>Format</label>
      <select id="exportFormat">
        <option value="png">PNG images (one per page, ZIP)</option>
        <option value="jpg">JPEG images (one per page, ZIP)</option>
        <option value="txt">Plain text (.txt)</option>
      </select>
    `,
    footer: `
      <button class="btn" onclick="document.getElementById('modalClose').click()">Cancel</button>
      <button class="btn primary" id="exportGo">Export</button>
    `,
  });
  $('exportGo').onclick = async () => {
    const fmt = $('exportFormat').value;
    closeModal();
    toast('Exporting…');
    if (fmt === 'txt') {
      let text = '';
      for (let i = 1; i <= window.appState.pageCount; i++) {
        const page = await window.appState.pdf.getPage(i);
        const tc = await page.getTextContent();
        text += tc.items.map(it => it.str).join(' ') + '\n\n';
      }
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = window.appState.fileName.replace(/\.pdf$/i, '.txt');
      a.click(); URL.revokeObjectURL(url);
      toast('Exported text', 'success');
    } else {
      // Export each page canvas as image — sequenced so browser doesn't block
      for (let i = 1; i <= window.appState.pageCount; i++) {
        const wrap = window.appState.pageDivs[i - 1];
        const canvas = wrap.querySelector('canvas');
        const blob = await new Promise(r => canvas.toBlob(r, fmt === 'png' ? 'image/png' : 'image/jpeg', 0.92));
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${window.appState.fileName.replace(/\.pdf$/i, '')}-page${i}.${fmt}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        await new Promise(r => setTimeout(r, 350));
      }
      toast(`Exported ${window.appState.pageCount} images`, 'success');
    }
  };
};

// ============ 3. CREATE A PDF ============
tools.create = () => {
  openModal({
    title: 'Create a PDF',
    body: `
      <p>Build a new PDF from scratch.</p>
      <label>Source</label>
      <select id="createSrc">
        <option value="blank">Blank document</option>
        <option value="text">From typed text</option>
        <option value="images">From images</option>
      </select>
      <label>Pages (for blank)</label>
      <input type="number" id="createPages" value="1" min="1" max="50" />
      <label>Text content (for typed text)</label>
      <textarea id="createText" placeholder="Type here..."></textarea>
    `,
    footer: `
      <button class="btn" id="createCancel">Cancel</button>
      <button class="btn primary" id="createGo">Create</button>
    `,
  });
  $('createCancel').onclick = closeModal;
  $('createGo').onclick = async () => {
    const src = $('createSrc').value;
    const doc = await PDFDocument.create();
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    if (src === 'blank') {
      const n = parseInt($('createPages').value);
      for (let i = 0; i < n; i++) doc.addPage([612, 792]);
    } else if (src === 'text') {
      const text = $('createText').value || 'Empty document';
      const lines = text.split('\n');
      const page = doc.addPage([612, 792]);
      let y = 750;
      for (const line of lines) {
        page.drawText(line, { x: 50, y, size: 12, font: helv, color: rgb(0,0,0) });
        y -= 18;
        if (y < 50) break;
      }
    } else if (src === 'images') {
      closeModal();
      const input = document.createElement('input');
      input.type = 'file'; input.accept = 'image/*'; input.multiple = true;
      input.onchange = async (e) => {
        for (const file of e.target.files) {
          const buf = await file.arrayBuffer();
          let img;
          try { img = await doc.embedJpg(buf); }
          catch { img = await doc.embedPng(buf); }
          const page = doc.addPage([img.width, img.height]);
          page.drawImage(img, { x: 0, y: 0, width: img.width, height: img.height });
        }
        const bytes = await doc.save();
        await window.loadPdfBytes(bytes, 'created.pdf');
        toast('Created PDF from images', 'success');
      };
      input.click();
      return;
    }
    const bytes = await doc.save();
    closeModal();
    await window.loadPdfBytes(bytes, 'created.pdf');
    toast('PDF created', 'success');
  };
};

// ============ 4. COMBINE FILES ============
tools.combine = () => {
  openModal({
    title: 'Combine files',
    body: `
      <p>Pick multiple PDFs to merge into one. Drag rows to reorder.</p>
      <div class="drop-area" id="combineDrop">
        <i class="fas fa-file-pdf"></i>
        <p>Click to select PDFs</p>
        <div class="hint">or drag &amp; drop here</div>
      </div>
      <div class="file-list hidden" id="combineList" style="margin-top:14px"></div>
    `,
    footer: `
      <button class="btn" id="combineCancel">Cancel</button>
      <button class="btn primary" id="combineGo" disabled>Combine</button>
    `,
  });
  const files = [];
  const drop = $('combineDrop');
  const list = $('combineList');
  const refresh = () => {
    list.classList.toggle('hidden', !files.length);
    list.innerHTML = files.map((f, i) => `
      <div class="file-row" draggable="true" data-i="${i}">
        <i class="fas fa-grip-vertical"></i>
        <i class="fas fa-file-pdf" style="color:var(--accent)"></i>
        <span class="fname">${f.name}</span>
        <span class="fsize">${(f.size/1024).toFixed(0)} KB</span>
        <button class="fremove" data-i="${i}"><i class="fas fa-times"></i></button>
      </div>
    `).join('');
    list.querySelectorAll('.fremove').forEach(b => b.onclick = () => {
      files.splice(parseInt(b.dataset.i), 1); refresh();
    });
    let dragName;
    list.querySelectorAll('.file-row').forEach(row => {
      row.ondragstart = () => { dragName = row.querySelector('.fname').textContent; };
      row.ondragover = (e) => e.preventDefault();
      row.ondrop = () => {
        const dropName = row.querySelector('.fname').textContent;
        const from = files.findIndex(f => f.name === dragName);
        const to = files.findIndex(f => f.name === dropName);
        if (from < 0 || to < 0 || from === to) return;
        const [m] = files.splice(from, 1);
        files.splice(to, 0, m);
        refresh();
      };
    });
    $('combineGo').disabled = files.length < 2;
  };
  drop.onclick = () => {
    const i = document.createElement('input');
    i.type = 'file'; i.accept = 'application/pdf'; i.multiple = true;
    i.onchange = (e) => { for (const f of e.target.files) files.push(f); refresh(); };
    i.click();
  };
  drop.ondragover = (e) => { e.preventDefault(); drop.style.borderColor = 'var(--blue)'; };
  drop.ondragleave = () => drop.style.borderColor = '';
  drop.ondrop = (e) => {
    e.preventDefault(); drop.style.borderColor = '';
    for (const f of e.dataTransfer.files) if (f.type === 'application/pdf') files.push(f);
    refresh();
  };
  $('combineCancel').onclick = closeModal;
  $('combineGo').onclick = async () => {
    const merged = await PDFDocument.create();
    for (const f of files) {
      const buf = await f.arrayBuffer();
      const src = await PDFDocument.load(buf);
      const pages = await merged.copyPages(src, src.getPageIndices());
      pages.forEach(p => merged.addPage(p));
    }
    const bytes = await merged.save();
    closeModal();
    await window.loadPdfBytes(bytes, 'combined.pdf');
    toast('Files combined', 'success');
  };
};

// ============ 5. ADD COMMENTS ============
tools.comment = () => {
  if (!needPdf()) return;
  toast('Click any page to drop a comment pin');
  const handler = (e) => {
    const wrap = e.target.closest('.pdf-page-wrap');
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const pin = document.createElement('div');
    pin.className = 'comment-pin';
    pin.style.left = (x - 14) + 'px';
    pin.style.top = (y - 28) + 'px';
    pin.dataset.page = wrap.dataset.page;
    pin.dataset.text = '';
    wrap.appendChild(pin);

    const popup = document.createElement('div');
    popup.className = 'comment-popup';
    popup.style.left = (x + 12) + 'px';
    popup.style.top = (y - 8) + 'px';
    popup.innerHTML = '<textarea placeholder="Write a comment..."></textarea>';
    wrap.appendChild(popup);
    const ta = popup.querySelector('textarea');
    ta.focus();
    ta.onblur = () => { pin.dataset.text = ta.value; popup.remove(); };
    pin.onclick = () => {
      if (wrap.querySelector('.comment-popup')) return;
      const p = document.createElement('div');
      p.className = 'comment-popup';
      p.style.left = (parseFloat(pin.style.left) + 30) + 'px';
      p.style.top = pin.style.top;
      p.innerHTML = `<textarea>${pin.dataset.text}</textarea>`;
      wrap.appendChild(p);
      const t = p.querySelector('textarea');
      t.focus();
      t.onblur = () => { pin.dataset.text = t.value; p.remove(); };
    };
    document.removeEventListener('click', handler, true);
  };
  setTimeout(() => document.addEventListener('click', handler, true), 100);
};

// ============ 6. FILL & SIGN ============
tools.sign = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Fill & Sign',
    body: `
      <p>Type a signature or draw it below, then place it on the page.</p>
      <label>Type your name</label>
      <input type="text" id="sigName" placeholder="Your name" />
      <label>Or draw your signature</label>
      <div class="sig-pad">
        <canvas id="sigCanvas" width="500" height="180"></canvas>
        <button class="sig-pad-clear" id="sigClear">Clear</button>
      </div>
    `,
    footer: `
      <button class="btn" id="sigCancel">Cancel</button>
      <button class="btn primary" id="sigPlace">Place signature</button>
    `,
  });
  const cvs = $('sigCanvas');
  const ctx = cvs.getContext('2d');
  ctx.lineWidth = 2.5; ctx.lineCap = 'round'; ctx.strokeStyle = '#0a0a3a';
  let drawing = false;
  cvs.onmousedown = (e) => { drawing = true; ctx.beginPath(); ctx.moveTo(e.offsetX, e.offsetY); };
  cvs.onmousemove = (e) => { if (!drawing) return; ctx.lineTo(e.offsetX, e.offsetY); ctx.stroke(); };
  cvs.onmouseup = () => drawing = false;
  cvs.onmouseleave = () => drawing = false;
  $('sigClear').onclick = () => ctx.clearRect(0, 0, cvs.width, cvs.height);
  $('sigCancel').onclick = closeModal;
  $('sigPlace').onclick = () => {
    const name = $('sigName').value.trim();
    const dataUrl = cvs.toDataURL('image/png');
    closeModal();
    toast('Click any page to place signature');
    const handler = (e) => {
      const wrap = e.target.closest('.pdf-page-wrap');
      if (!wrap) return;
      const rect = wrap.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      if (name) {
        addPlacedText(wrap, x, y, name, 22);
        const last = wrap.lastElementChild;
        last.style.fontFamily = "'Brush Script MT', cursive";
        last.style.fontStyle = 'italic';
      } else {
        const div = document.createElement('div');
        div.className = 'placed-item placed-image';
        div.style.left = x + 'px';
        div.style.top = y + 'px';
        div.dataset.page = wrap.dataset.page;
        div.dataset.kind = 'image';
        div.dataset.src = dataUrl;
        const img = document.createElement('img');
        img.src = dataUrl; img.style.width = '180px';
        div.appendChild(img);
        makeDraggable(div);
        wrap.appendChild(div);
      }
      document.removeEventListener('click', handler, true);
    };
    document.addEventListener('click', handler, true);
  };
};

// ============ 7. REQUEST E-SIGNATURES ============
tools.esign = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Request E-signatures',
    body: `
      <p>Send this PDF to recipients to sign electronically.</p>
      <label>Recipient email(s)</label>
      <input type="text" id="esignTo" placeholder="alice@example.com, bob@example.com" />
      <label>Message</label>
      <textarea id="esignMsg" placeholder="Please review and sign this document.">Please review and sign this document.</textarea>
      <p style="color: var(--text-mute); font-size: 11px; margin-top: 12px;">
        Note: This demo creates a signing link. Configure SMTP on the server to send actual emails.
      </p>
    `,
    footer: `
      <button class="btn" id="esCancel">Cancel</button>
      <button class="btn primary" id="esSend">Send for signature</button>
    `,
  });
  $('esCancel').onclick = closeModal;
  $('esSend').onclick = () => {
    const to = $('esignTo').value.trim();
    if (!to) { toast('Enter at least one email', 'error'); return; }
    const link = window.location.href + '?sign=' + Date.now().toString(36);
    closeModal();
    toast(`Signature request sent to ${to.split(',').length} recipient(s)`, 'success');
    console.log('Signing link:', link);
  };
};

// ============ 8. COMPRESS A PDF ============
tools.compress = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Compress a PDF',
    body: `
      <p>Reduce file size by re-rendering pages as JPEG images.</p>
      <label>Quality</label>
      <select id="compressQ">
        <option value="0.5">Low (smallest file)</option>
        <option value="0.7" selected>Medium (balanced)</option>
        <option value="0.85">High (best quality)</option>
      </select>
      <label>Image scale</label>
      <select id="compressScale">
        <option value="0.75">75% (smaller)</option>
        <option value="1" selected>100%</option>
        <option value="1.5">150% (larger)</option>
      </select>
    `,
    footer: `
      <button class="btn" id="cmpCancel">Cancel</button>
      <button class="btn primary" id="cmpGo">Compress</button>
    `,
  });
  $('cmpCancel').onclick = closeModal;
  $('cmpGo').onclick = async () => {
    const q = parseFloat($('compressQ').value);
    const sc = parseFloat($('compressScale').value);
    closeModal();
    toast('Compressing…');
    const doc = await PDFDocument.create();
    for (let i = 1; i <= window.appState.pageCount; i++) {
      const page = await window.appState.pdf.getPage(i);
      const viewport = page.getViewport({ scale: sc });
      const cvs = document.createElement('canvas');
      cvs.width = viewport.width; cvs.height = viewport.height;
      await page.render({ canvasContext: cvs.getContext('2d'), viewport }).promise;
      const dataUrl = cvs.toDataURL('image/jpeg', q);
      const buf = await (await fetch(dataUrl)).arrayBuffer();
      const img = await doc.embedJpg(buf);
      const newPage = doc.addPage([img.width, img.height]);
      newPage.drawImage(img, { x: 0, y: 0, width: img.width, height: img.height });
    }
    const bytes = await doc.save();
    const before = window.appState.fileBytes.byteLength;
    const after = bytes.byteLength;
    const pct = Math.round((1 - after / before) * 100);
    downloadBytes(bytes, 'compressed-' + window.appState.fileName);
    toast(`Compressed ${pct > 0 ? pct + '% smaller' : 'done'}`, 'success');
  };
};

// ============ 9. PROTECT A PDF ============
tools.protect = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Protect a PDF',
    body: `
      <p>Add a watermark and ownership metadata. (Browser PDF libraries cannot natively encrypt — for true password protection, use the server.)</p>
      <label>Watermark text</label>
      <input type="text" id="protMark" value="CONFIDENTIAL" />
      <label>Owner name</label>
      <input type="text" id="protOwner" placeholder="Your name" />
      <label>Optional password (server-side encryption — placeholder)</label>
      <input type="password" id="protPwd" placeholder="••••••••" />
    `,
    footer: `
      <button class="btn" id="prCancel">Cancel</button>
      <button class="btn primary" id="prGo">Protect</button>
    `,
  });
  $('prCancel').onclick = closeModal;
  $('prGo').onclick = async () => {
    const mark = $('protMark').value || 'CONFIDENTIAL';
    const owner = $('protOwner').value;
    const pwd = $('protPwd').value;
    closeModal();
    if (pwd) toast('Password noted (encryption needs server-side qpdf)', '');
    toast('Protecting…');
    const doc = await getCurrentPdfDoc();
    const helv = await doc.embedFont(StandardFonts.HelveticaBold);
    if (owner) doc.setAuthor(owner);
    doc.setSubject('Protected document');
    doc.getPages().forEach(page => {
      const { width, height } = page.getSize();
      page.drawText(mark, {
        x: width / 2 - mark.length * 14,
        y: height / 2,
        size: 56, font: helv,
        color: rgb(0.85, 0.1, 0.1),
        opacity: 0.18,
        rotate: degrees(-30),
      });
    });
    const bytes = await doc.save();
    downloadBytes(bytes, 'protected-' + window.appState.fileName);
    toast('Protected PDF saved', 'success');
  };
};

// ============ 10. STAMP ============
tools.stamp = () => {
  if (!needPdf()) return;
  openModal({
    title: 'Use a stamp',
    body: `
      <p>Choose a stamp and click on the page to place it.</p>
      <div class="stamp-grid" id="stampGrid">
        <div class="stamp-card stamp-approved" data-s="APPROVED">APPROVED</div>
        <div class="stamp-card stamp-rejected" data-s="REJECTED">REJECTED</div>
        <div class="stamp-card stamp-confidential" data-s="CONFIDENTIAL">CONFIDENTIAL</div>
        <div class="stamp-card stamp-draft" data-s="DRAFT">DRAFT</div>
        <div class="stamp-card stamp-paid" data-s="PAID">PAID</div>
        <div class="stamp-card stamp-final" data-s="FINAL">FINAL</div>
      </div>
    `,
    footer: `
      <button class="btn" id="stCancel">Cancel</button>
      <button class="btn primary" id="stPlace" disabled>Place stamp</button>
    `,
  });
  let chosen = null;
  document.querySelectorAll('.stamp-card').forEach(c => c.onclick = () => {
    document.querySelectorAll('.stamp-card').forEach(x => x.classList.remove('selected'));
    c.classList.add('selected');
    chosen = { text: c.dataset.s, color: getComputedStyle(c).color };
    $('stPlace').disabled = false;
  });
  $('stCancel').onclick = closeModal;
  $('stPlace').onclick = () => {
    closeModal();
    toast('Click any page to stamp');
    const handler = (e) => {
      const wrap = e.target.closest('.pdf-page-wrap');
      if (!wrap) return;
      const rect = wrap.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const div = document.createElement('div');
      div.className = 'placed-item placed-text';
      div.contentEditable = false;
      div.textContent = chosen.text;
      div.style.left = x + 'px';
      div.style.top = y + 'px';
      div.style.fontSize = '32px';
      div.style.fontWeight = '900';
      div.style.color = chosen.color;
      div.style.border = `3px solid ${chosen.color}`;
      div.style.padding = '6px 16px';
      div.style.borderRadius = '6px';
      div.style.transform = 'rotate(-12deg)';
      div.style.background = 'rgba(255,255,255,0.5)';
      div.dataset.page = wrap.dataset.page;
      div.dataset.kind = 'text';
      div.dataset.size = 32;
      makeDraggable(div);
      wrap.appendChild(div);
      document.removeEventListener('click', handler, true);
    };
    document.addEventListener('click', handler, true);
  };
};

// Save button in toolbar — intercept (capture phase) to bake edits if any
$('downloadBtn').addEventListener('click', async (e) => {
  if (document.querySelectorAll('.placed-item').length) {
    e.stopImmediatePropagation();
    e.preventDefault();
    toast('Saving with edits…');
    const bytes = await bakeOverlaysIntoPdf();
    downloadBytes(bytes, 'edited-' + window.appState.fileName);
    toast('Saved', 'success');
  }
}, true);

console.log('Acrobat tools loaded ✓');
