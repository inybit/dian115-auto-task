// dian115-auto-task — canonical behavior verifier (run: node test/verify.app.js)
// Mocks fetch/indexedDB/DOM/localStorage, uses real WebCrypto to verify the
// BrowserProof ECDSA signature chain. No test framework; exit 0 = green.
'use strict';
const fs = require('fs');
const path = require('path');
const SRC = fs.readFileSync(path.join(__dirname, '..', 'dian115-auto.user.js'), 'utf8');

// ---------- mocks ----------
const idbRecords = {};
const makeReq = result => ({ result, onsuccess: null, onerror: null, oncomplete: null });
const indexedDB = { open() {
  const db = { objectStoreNames: { contains: () => true }, createObjectStore() { return {}; },
    transaction(s, m) { return { objectStore() { return { get(k) { const r = makeReq(idbRecords[k] || null); queueMicrotask(() => r.onsuccess && r.onsuccess()); return r; },
      put(rec) { idbRecords[rec.id] = rec; const r = makeReq(rec); queueMicrotask(() => { r.oncomplete && r.oncomplete(); r.onsuccess && r.onsuccess(); }); return r; } }; } }; } };
  const req = { result: db, onupgradeneeded: null, onsuccess: null, onerror: null };
  queueMicrotask(() => { req.onupgradeneeded && req.onupgradeneeded(); req.onsuccess && req.onsuccess(); });
  return req;
} };
const store = {};
const ls = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => delete store[k] };
const makeEl = () => ({ style: {}, cssText: '', hidden: false, textContent: '', dataset: {}, children: [], _h: '', set innerHTML(v) { this._h = v; }, get innerHTML() { return this._h; }, appendChild() {}, setAttribute() {}, querySelector() { return makeEl(); }, addEventListener() {} });

const calls = [];
const logLines = [];
let failBp = false;
const makeRes = (status, payload) => ({ status, ok: status >= 200 && status < 300, clone() { return makeRes(status, payload); }, async json() { return JSON.parse(JSON.stringify(payload)); } });
const canned = {
  '/api/portal/auth/browser-challenge': { enabled: true, proof: 'PROOF_ABC', ttl: 600 },
  '/api/portal/auth/browser-session': { enabled: true, ttl: 1800, server_time_ms: Date.now() },
  '/api/portal/games/status': { items: { daily_wheel: { used_today: 0, max_plays: 1, cost: 5, award_today: 0, daily_cap: 0 }, monopoly: { used_today: 0, max_plays: 1 }, community_lottery: { used_today: 0, max_plays: 5 } } },
  '/api/portal/signin': { award: 8, new_balance: 114 },
  '/api/portal/lottery/wheel': { prize: { sector: 0, label: '+3', points: 3 } },         // prize is an OBJECT, no new_balance (mirrors real site)
  '/api/portal/games/monopoly/play': { award_points: 6, steps: [{ label: '+1', points: 1 }], new_balance: 115 },
};
async function mockFetch(url, o = {}) {
  const h = o.headers || {}, body = o.body ? JSON.parse(o.body) : null;
  calls.push({ url, method: o.method, headers: h, body });
  const key = url.split('?')[0];
  if (!canned[key]) return makeRes(404, { code: 'not_found' });
  if (failBp && /games\/status/.test(key) && calls.filter(c => c.url === key).length === 1) return makeRes(403, { code: 'browser_proof_required', msg: 'browser proof required' });
  return makeRes(200, canned[key]);
}
function install() {
  const realSet = global.setTimeout;
  global.setTimeout = fn => realSet(fn, 0);                       // collapse sleep()/backoff
  global.fetch = mockFetch;
  global.indexedDB = indexedDB;
  global.localStorage = ls;
  global.window = { setTimeout: cb => cb() };
  global.document = { body: makeEl(), createElement: () => makeEl() };
  global.location = { pathname: '/me/signin', origin: 'https://m.dian115.com', href: 'https://m.dian115.com/me/signin' };
  const ci = global.console.info, ce = global.console.error;
  global.console.info = (...a) => { logLines.push(a.join(' ')); ci(...a); };
  global.console.error = (...a) => { logLines.push(a.join(' ')); ce(...a); };
}

// ---------- harness ----------
let pass = 0, fail = 0;
const assert = (c, m) => { c ? (pass++, console.log('  PASS ' + m)) : (fail++, console.log('  FAIL ' + m)); };
const drain = async (n = 30) => { for (let i = 0; i < n; i++) await new Promise(r => global.setTimeout(r)); };
async function verifySig(call) {
  const rec = idbRecords['request-signing-p256'];
  assert(rec && rec.publicJWK && rec.privateKey, 'site ECDSA key persisted to IDB (private + publicJWK)');
  if (!rec) return;
  const ts = call.headers['X-Portal-Browser-TS'], ns = call.headers['X-Portal-Browser-Nonce'], sg = call.headers['X-Portal-Browser-Sig'];
  const p = call.url.split(/[?#]/)[0], m = call.method || 'GET';
  const msg = `portal-browser-request/v1\n${m}\n${p}\n${ts}\n${ns}`;
  const key = await crypto.subtle.importKey('jwk', rec.publicJWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const sig = Uint8Array.from(atob(sg.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  assert(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(msg)), `signature for ${m} ${p} verifies (real crypto)`);
}

(async () => {
  install();
  console.log('--- fresh day: order + proof headers + signature + disabled community ---');
  assert(/@version\s+1\.1\.[0-9]/.test(SRC), 'script on disk is v1.1.x');
  assert(SRC.includes('portal-browser-request/v1'), 'BrowserProof client present in source');
  eval(SRC); await drain();
  const biz = calls.filter(c => !c.url.includes('/auth/')).map(c => c.method + ' ' + c.url);
  assert(JSON.stringify(biz) === JSON.stringify(['GET /api/portal/games/status', 'POST /api/portal/signin', 'POST /api/portal/lottery/wheel', 'POST /api/portal/games/monopoly/play']), 'business order = status → signin → wheel → monopoly');
  assert(calls.some(c => c.url === '/api/portal/signin' && JSON.stringify(c.body) === '{"mode":"normal"}'), 'signin {mode:normal}');
  assert(calls.filter(c => c.url === '/api/portal/lottery/wheel').length === 1, 'wheel once (max_plays)');
  const wheelLine = logLines.find(l => l.includes('幸运转盘第'));
  assert(wheelLine && wheelLine.includes('+3'), 'wheel log renders prize OBJECT-readable (label "+3"), not [object Object]');
  assert(wheelLine && !wheelLine.includes('undefined'), 'wheel log omits balance when response lacks new_balance (no "undefined")');
  assert(!logLines.join('\n').includes('[object Object]'), 'no "[object Object]" anywhere in logs');
  assert(calls.filter(c => c.url === '/api/portal/games/monopoly/play').length === 1, 'monopoly once');
  assert(calls.filter(c => c.url.includes('community-lottery/buy')).length === 0, 'community buy NOT auto-called (default off)');
  const si = calls.find(c => c.url === '/api/portal/signin');
  assert(si.headers['X-Portal-Browser-Proof'] === 'PROOF_ABC' && si.headers['X-Portal-Browser-TS'] && si.headers['X-Portal-Browser-Nonce'] && si.headers['X-Portal-Browser-Sig'], 'all 4 X-Portal-Browser-* headers on signin');
  assert(si.headers['X-Portal-Visitor-ID'] && si.headers['X-Portal-Current-Path'] === '/me/signin' && si.headers['X-Requested-With'] === 'XMLHttpRequest', 'visitor/path/xhr headers');
  const ses = calls.find(c => c.url === '/api/portal/auth/browser-session');
  assert(ses && ses.headers['X-Portal-Browser-Proof'] === 'PROOF_ABC' && ses.body?.public_jwk?.kty === 'EC', 'browser-session registers EC JWK w/ proof');
  await verifySig(si);

  console.log('--- same-day reload dedup ---');
  calls.length = 0; eval(SRC); await drain();
  assert(calls.length === 0, 'no API calls on same-day reload');

  console.log('--- proof failure -> reset -> retry ---');
  calls.length = 0; failBp = true;
  store['dian115_auto_lastrun'] = JSON.stringify({ date: 'nope', state: 'x' });
  eval(SRC); await new Promise(r => global.setTimeout(r, 50)); await drain();
  assert(calls.filter(c => c.url === '/api/portal/games/status').length >= 2, 'games/status retried on browser_proof_required');
  assert(calls.some(c => c.url === '/api/portal/signin' && c.headers['X-Portal-Browser-Proof']), 'post-retry request carries proof headers');

  console.log('\nRESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();