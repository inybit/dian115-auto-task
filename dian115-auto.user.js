// ==UserScript==
// @name         癫影 m.dian115.com 每日自动任务
// @namespace    https://github.com/inybit/dian115-auto-task
// @description  自动完成 m.dian115.com 每日例行：签到、幸运转盘、幸运大富翁、社区三色球。内置站点 BrowserProof 签名防爬客户端（复用站点 ECDSA 私钥），复用当前登录会话。
// @version      1.3.0
// @author       librarian
// @match        https://m.dian115.com/*
// @grant        none
// @run-at       document-idle
// @noframes
// @license      MIT
// ==/UserScript==

/**
 * ===== 逆向依据（v1.2.x） =====
 * 站点 API 有自研 BrowserProof 防爬签名（axios 请求拦截器），裸 fetch 会被挡，
 * 服务端返回 {code:"browser_proof_required"}（即报错里的 "browser proof required"）。
 * 前置步骤（拦截器顺序）：
 *   1. 每请求带  X-Portal-Visitor-ID（localStorage.portal_visitor_id）+ X-Portal-Current-Path
 *   2. GET /auth/browser-challenge  ->  {enabled, proof, ttl, expires_at}（proof 缓存 ~30s）
 *   3. 有 proof 则带 X-Portal-Browser-Proof
 *   4. POST /auth/browser-session {public_jwk} + proof 头 -> 注册 ECDSA 公钥，返回
 *      {enabled, expires_at, ttl, server_time_ms}（用于同步服务器时钟 skew）
 *   5. 用私钥对 "portal-browser-request/v1\n<METHOD>\n<path>\n<ts>\n<nonce>" 做 ECDSA-SHA256 签名 → base64url
 *      挂 X-Portal-Browser-TS / -Nonce / -Sig
 *   6. 遇 code ∈ {browser_proof_required, browser_proof_invalid} 时重取 proof+重注册 重试一次
 * 私钥：非可导出，存站点 indexedDB "portal-browser-security-v1"/keys/"request-signing-p256"。
 *       —— 脚本必须【复用这把站点私钥】签名，绝不自建新钥（自建会与服务端当前绑定公钥冲突、弄坏站内请求）。
 *
 * 功能 API（base /api/portal，方法上表已逆向）：
 *   POST /signin {mode:"normal"|"lucky"}          单次（默认 lucky）
 *   POST /lottery/wheel                            按 daily_wheel.max_plays
 *   POST /games/monopoly/play                      按 monopoly.max_plays
 *   GET  /games/status                             取各项额度 {used_today,max_plays,award_today,daily_cap,cost}
 *   GET  /games/community-lottery/status           本期三色球状态（含可投上限/余额）
 *   POST /games/community-lottery/buy {numbers[3],units}   默认随机 3 号 + 2 注/期，可填号码定点
 */

(function () {
  'use strict';

  // ============================ 配置区 ============================
  const CONFIG = {
    AUTO_RUN: true,
    SHOW_PANEL: true,
    SIGNIN_MODE: 'lucky',          // 默认运气签到（可能大奖/空签/倒霉），改 'normal' 走稳健
    SIGNIN_ENABLED: true,
    WHEEL_ENABLED: true,
    MONOPOLY_ENABLED: true,
    // 大富翁有服务端冷却（无时间戳可读）。遇"用完或冷却"时，等待 MONOPOLY_COOLDOWN_MS 重试，
    // 最多 MONOPOLY_MAX_ATTEMPTS 次；总等待预算 = COOLDOWN_MS × MAX_ATTEMPTS。设 0 即遇冷却直接停。
    MONOPOLY_COOLDOWN_MS: 6000,
    MONOPOLY_MAX_ATTEMPTS: 10,
    COMMUNITY_ENABLED: true,
    // 社区三色球：号码范围 1..settings.number_max（默认 15，即 01-15）。
    // 显式填恰好 3 个合法数字则定点下注；留空/非法则每期随机选 3 个不重复号。
    COMMUNITY_NUMBERS: [],
    COMMUNITY_UNITS: 2,            // 每期投注注数（默认随机投 2 注）
    // 本期已投注（status.my_bet 存在）时的行为：默认跳过（防手动重跑重复烧分/随机换号被拒）；
    // 设 true 则改为追加 COMMUNITY_UNITS 注到【同一组已选号码】。
    COMMUNITY_APPEND_ENABLED: false,
    BALANCE_FLOOR: 10,
  };
  const API_BASE = '/api/portal';

  // ============================ BrowserProof 客户端 ============================
  // 镜像站点 axios 拦截器（常量名/算法/消息格式逐字对齐逆向结果）
  const BP = {
    IDB_NAME: 'portal-browser-security-v1',
    IDB_STORE: 'keys',
    IDB_KEY: 'request-signing-p256',
    VISITOR_KEY: 'portal_visitor_id',
    H_PROOF: 'X-Portal-Browser-Proof',
    H_TS: 'X-Portal-Browser-TS',
    H_NONCE: 'X-Portal-Browser-Nonce',
    H_SIG: 'X-Portal-Browser-Sig',
    H_VISITOR: 'X-Portal-Visitor-ID',
    H_PATH: 'X-Portal-Current-Path',

    // 模块态
    _key: null,        // {privateKey, publicJWK}
    _proof: null,      // {value, expiresAt}
    _session: null,    // true/false/null
    _sessionExp: 0,    // be
    _skew: 0,          // Fe

    _openIdb() {
      return new Promise((res, rej) => {
        const req = indexedDB.open(BP.IDB_NAME, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(BP.IDB_STORE)) {
            req.result.createObjectStore(BP.IDB_STORE, { keyPath: 'id' });
          }
        };
        req.onsuccess = () => res(req.result);
        req.onerror = () => rej(req.error || new Error('browser db unavailable'));
      });
    },

    // 读回站点私钥；缺则生成一把并写回同一 store（应用与脚本共享同一把钥）
    async ensureKey() {
      if (BP._key) return BP._key;
      let rec = null;
      try {
        const db = await BP._openIdb();
        rec = await new Promise((res, rej) => {
          const tx = db.transaction(BP.IDB_STORE, 'readonly').objectStore(BP.IDB_STORE).get(BP.IDB_KEY);
          tx.onsuccess = () => res(tx.result || null);
          tx.onerror = () => rej(tx.error || new Error('key read failed'));
        });
      } catch (_) { /* 无 IDB 则走生成 */ }
      if (!rec || rec.privateKey?.type !== 'private' || rec.publicJWK?.kty !== 'EC') {
        const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
        const publicJWK = await crypto.subtle.exportKey('jwk', kp.publicKey);
        rec = { id: BP.IDB_KEY, privateKey: kp.privateKey, publicJWK };
        try {
          const db = await BP._openIdb();
          await new Promise((res, rej) => {
            const tx = db.transaction(BP.IDB_STORE, 'readwrite').objectStore(BP.IDB_STORE).put(rec);
            tx.oncomplete = () => res();
            tx.onerror = () => rej(tx.error || new Error('key write failed'));
          });
        } catch (_) { /* 写入失败不致命 */ }
      }
      BP._key = rec;
      return rec;
    },

    visitorID() {
      try {
        const e = localStorage.getItem(BP.VISITOR_KEY);
        if (e && /^[A-Za-z0-9_.-]{8,80}$/.test(e)) return e;
      } catch (_) {}
      const id = (crypto?.randomUUID?.()) || ('v_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2));
      try { localStorage.setItem(BP.VISITOR_KEY, id); } catch (_) {}
      return id;
    },

    b64u(bytes) {
      let bin = '';
      const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      for (let i = 0; i < arr.length; i += 32768) bin += String.fromCharCode(...arr.subarray(i, i + 32768));
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    },
    nonce() { const u = new Uint8Array(24); crypto.getRandomValues(u); return BP.b64u(u); },

    // GET /auth/browser-challenge（proof 缓存 30s）
    async challenge(force) {
      if (!force && BP._proof && BP._proof.expiresAt > Date.now()) return BP._proof.value;
      const r = await fetch(API_BASE + '/auth/browser-challenge', { method: 'GET', credentials: 'include' });
      if (!r.ok) return null;
      const j = await r.json();
      if (j.enabled === false || !j.proof) { BP._proof = null; return null; }
      const ttl = (Number(j.ttl) || 600) * 1000;
      BP._proof = { value: String(j.proof), expiresAt: Date.now() + Math.max(ttl, 60000) };
      return BP._proof.value;
    },

    // POST /auth/browser-session 注册公钥 + 同步时钟
    async session(proof) {
      if (BP._session === true && BP._sessionExp > Date.now()) return true;
      const { privateKey: _ign, publicJWK } = await BP.ensureKey();
      const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
      if (proof) headers[BP.H_PROOF] = proof;
      const r = await fetch(API_BASE + '/auth/browser-session', {
        method: 'POST', credentials: 'include', headers,
        body: JSON.stringify({ public_jwk: { kty: publicJWK.kty, crv: publicJWK.crv, x: publicJWK.x, y: publicJWK.y } }),
      });
      if (!r.ok) return false;
      const v = await r.json();
      if (v.enabled === false) { BP._session = false; return false; }
      const now = Date.now();
      const srv = Number(v.server_time_ms);
      BP._skew = Number.isFinite(srv) ? srv - now : 0;
      const ttlN = Number(v.ttl);
      BP._sessionExp = Number.isFinite(ttlN) ? now + Math.max(ttlN, 300) * 1000
        : (typeof v.expires_at === 'string' ? Date.parse(v.expires_at) - BP._skew : now + 1800 * 1000);
      BP._session = true;
      return true;
    },

    pathFor(urlPath) {
      let t = urlPath.split(/[?#]/)[0];
      if (!t.startsWith('/api/portal/')) t = '/api/portal/' + t.replace(/^\/+/, '');
      return t.startsWith('/') ? t : '/' + t;
    },

    // ECDSA-SHA256 签 "portal-browser-request/v1\nMETHOD\npath\nts\nnonce"
    async sign(method, urlPath) {
      const { privateKey } = await BP.ensureKey();
      const path = BP.pathFor(urlPath);
      const ts = String(Math.round(Date.now() + BP._skew));
      const ns = BP.nonce();
      const msg = `portal-browser-request/v1\n${String(method).trim().toUpperCase()}\n${path}\n${ts}\n${ns}`;
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(msg));
      return { timestamp: ts, nonce: ns, signature: BP.b64u(new Uint8Array(sig)), path, msg };
    },

    // 供诊断：可校验签名是否与公钥匹配
    async verifySig(msg, sigB64, publicJWK) {
      const key = await crypto.subtle.importKey('jwk', publicJWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const sig = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(msg));
    },

    async resetProof() {
      BP._proof = null;
      BP._session = null;
      BP._sessionExp = 0;
    },
  };

  const LOG = [];
  function log(msg, level = 'info') {
    const line = `${new Date().toLocaleTimeString('zh-CN', { hour12: false })} [${level}] ${msg}`;
    LOG.push(line);
    if (CONFIG.SHOW_PANEL) renderPanel();
    (console[level === 'error' ? 'error' : 'info'])('[dian115-auto] ' + msg);
  }

  // 带 BrowserProof 的受保护请求（镜像站点拦截器），遇 proof 错误重试一次
  async function api(path, method = 'GET', body) {
    const doFetch = async () => {
      const headers = {};
      const proof = await BP.challenge(false);
      if (proof) {
        headers[BP.H_PROOF] = proof;
        const okSession = await BP.session(proof);
        if (okSession) {
          const s = await BP.sign(method, path);
          headers[BP.H_TS] = s.timestamp;
          headers[BP.H_NONCE] = s.nonce;
          headers[BP.H_SIG] = s.signature;
        }
      }
      headers[BP.H_VISITOR] = BP.visitorID();
      headers[BP.H_PATH] = (location.pathname || '/').slice(0, 160);
      headers['Content-Type'] = 'application/json';
      headers['X-Requested-With'] = 'XMLHttpRequest';
      return fetch(API_BASE + path, {
        method, credentials: 'include', headers,
        body: body ? JSON.stringify(body) : undefined,
      });
    };

    let res;
    try { res = await doFetch(); } catch (err) { throw err; }
    let code = null, msg = null;
    try {
      const j = await res.clone().json().catch(() => ({}));
      code = j.code || null; msg = j.msg || null;
    } catch (_) {}

    if (res.status === 401) throw Object.assign(new Error('未登录或会话失效（401）'), { code: 'AUTH' });
    if ((code === 'browser_proof_required' || code === 'browser_proof_invalid' ) && res.status !== 200) {
      await BP.resetProof();
      log('proof 失效，重取后重试一次 …', 'warn');
      await new Promise(r => setTimeout(r, 300));
      res = await doFetch(); // 重试
      try { const j = await res.clone().json().catch(() => ({})); code = j.code || null; msg = j.msg || null; } catch (_) {}
    }
    if (!res.ok) {
      if (res.status === 401) throw Object.assign(new Error('未登录或会话失效（401）'), { code: 'AUTH' });
      const err = new Error(msg || `HTTP ${res.status}`);
      err.code = code;
      throw err;
    }
    return res.json();
  }

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function fmtPrize(p) {
    if (p == null) return '未知';
    if (typeof p === 'string') return p || '未知';
    const parts = [];
    const label = p.label != null ? String(p.label) : '';
    if (label) parts.push(label);
    const pts = Number(p.points);
    if (pts > 0 && label !== '+' + pts && !label.endsWith('+' + pts)) parts.push('+' + pts);
    if (Number(p.vip_days) > 0) parts.push(`VIP ${p.vip_days}天`);
    return parts.join(' ') || JSON.stringify(p);
  }
  const bal = v => (typeof v === 'number') ? `（余额 ${v}）` : '';
  function today() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  const DEDUP_KEY = 'dian115_auto_lastrun';
  function readState() { try { return JSON.parse(localStorage.getItem(DEDUP_KEY) || 'null') || {}; } catch (_) { return {}; } }
  function saveState(s) { try { localStorage.setItem(DEDUP_KEY, JSON.stringify(s)); } catch (_) {} }

  // ============================ 各功能 ============================
  async function doSignin() {
    if (!CONFIG.SIGNIN_ENABLED) return;
    try {
      const r = await api('/signin', 'POST', { mode: CONFIG.SIGNIN_MODE });
      if (r.award > 0) log(`签到成功：+${r.award} 积分（余额 ${r.new_balance}）`);
      else if (r.award === 0) log(`签到完成（空签，余额 ${r.new_balance}）`, 'warn');
      else log(`签到完成（倒霉签 ${r.award}，余额 ${r.new_balance}）`, 'warn');
    } catch (e) {
      if (e.code === 'AUTH') throw e;
      if (/已签到/.test(e.message)) log('今日已签到，跳过', 'info');
      else log(`签到失败：${e.message}`, 'error');
    }
  }

  async function doWheel(status) {
    if (!CONFIG.WHEEL_ENABLED || !status?.daily_wheel) return;
    const g = status.daily_wheel;
    while (g.used_today < g.max_plays) {
      if (g.daily_cap > 0 && g.award_today >= g.daily_cap) { log('幸运转盘已达今日积分上限，停止', 'warn'); break; }
      try {
        const r = await api('/lottery/wheel', 'POST');
        g.used_today++;
        log(`幸运转盘第 ${g.used_today}/${g.max_plays} 次 -> ${fmtPrize(r.prize)}${bal(r.new_balance ?? r.balance)}`);
        if (typeof r.new_balance === 'number') g.balance = r.new_balance;
      } catch (e) {
        if (e.code === 'AUTH') throw e;
        log(`幸运转盘失败：${e.message}`, 'error'); break;
      }
      await sleep(1800);
    }
  }

  async function doMonopoly(status) {
    if (!CONFIG.MONOPOLY_ENABLED || !status?.monopoly) return;
    const g = status.monopoly;
    let attempts = 0;
    while (g.used_today < g.max_plays) {
      try {
        const r = await api('/games/monopoly/play', 'POST');
        g.used_today++; attempts = 0;
        const step = (r.steps && r.steps[r.steps.length - 1]);
        log(`幸运大富翁第 ${g.used_today}/${g.max_plays} 次 -> 本局奖励 +${r.award_points ?? 0} 分（${step?.label ?? ''}）${bal(r.new_balance)}`);
        if (typeof r.new_balance === 'number') g.balance = r.new_balance;
        await sleep(1800);
      } catch (e) {
        if (e.code === 'AUTH') throw e;
        const remaining = g.max_plays - g.used_today;
        attempts++;
        if (CONFIG.MONOPOLY_COOLDOWN_MS > 0 && attempts <= CONFIG.MONOPOLY_MAX_ATTEMPTS) {
          log(`大富翁冷却中（已 ${g.used_today}/${g.max_plays}，剩 ${remaining} 次），${Math.round(CONFIG.MONOPOLY_COOLDOWN_MS / 1000)}s 后重试 ${attempts}/${CONFIG.MONOPOLY_MAX_ATTEMPTS} …`, 'warn');
          await sleep(CONFIG.MONOPOLY_COOLDOWN_MS);
          continue;
        }
        log(`幸运大富翁暂停：${e.message}（今日完成 ${g.used_today}/${g.max_plays}，剩 ${remaining} 次未跑）`, 'warn');
        break;
      }
    }
  }

  function randomPick3(max) {
    const set = new Set();
    while (set.size < 3) set.add(1 + Math.floor(Math.random() * max));
    return [...set];
  }
  async function doCommunity() {
    if (!CONFIG.COMMUNITY_ENABLED) return;
    try {
      const st = await api('/games/community-lottery/status');
      const numberMax = Number(st.settings?.number_max) || 15;   // 01-15
      const floor = (typeof st.balance === 'number') ? st.balance : undefined;
      if (typeof floor === 'number' && floor < CONFIG.BALANCE_FLOOR) {
        log(`社区三色球跳过：余额 ${floor} 低于安全阈值`, 'warn');
        return;
      }
      const existing = (st.my_bet && Array.isArray(st.my_bet.numbers) && st.my_bet.numbers.length === 3)
        ? st.my_bet.numbers.map(Number) : null;
      const maxBuy = st.max_buy ?? st.remaining ?? st.ticket_count ?? 1;
      if (existing) {
        const existShow = existing.map(n => String(n).padStart(2, '0')).join(',');
        if (CONFIG.COMMUNITY_APPEND_ENABLED) {
          const units = Math.max(1, Math.min(CONFIG.COMMUNITY_UNITS, maxBuy));
          const r = await api('/games/community-lottery/buy', 'POST', { numbers: existing, units });
          log(`社区三色球追加：${existShow} +${units} 注${bal(r.new_balance ?? floor)}`);
        } else {
          log(`社区三色球本期已投注（${existShow}），跳过重复投注（COMMUNITY_APPEND_ENABLED=false）`, 'info');
        }
        return;
      }
      const cfg = (Array.isArray(CONFIG.COMMUNITY_NUMBERS) ? CONFIG.COMMUNITY_NUMBERS.map(Number) : [])
        .filter(n => Number.isInteger(n) && n >= 1 && n <= numberMax);
      const useFixed = cfg.length === 3 && new Set(cfg).size === 3;
      const numbers = useFixed ? cfg : randomPick3(numberMax);
      const tag = useFixed ? '指定号' : '随机';
      const units = Math.max(1, Math.min(CONFIG.COMMUNITY_UNITS, maxBuy));
      const r = await api('/games/community-lottery/buy', 'POST', { numbers, units });
      const show = numbers.map(n => String(n).padStart(2, '0')).join(',');
      log(`社区三色球已购入：${tag} ${show} × ${units} 注${bal(r.new_balance ?? floor)}`);
    } catch (e) {
      if (e.code === 'AUTH') throw e;
      log(`社区三色球失败：${e.message}`, 'error');
    }
  }

  async function runAll() {
    if (!CONFIG.AUTO_RUN) { log('自动执行已关闭（AUTO_RUN=false），仅显示面板'); return; }
    log(`开始今日任务（${today()}）`);
    try {
      const status = await api('/games/status');
      if (status?.items) {
        log('· 额度：' + Object.keys(status.items).map(k => `${k}=${status.items[k].used_today}/${status.items[k].max_plays}`).join('  '));
      }
      await doSignin();
      await doWheel(status?.items);
      await doMonopoly(status?.items);
      await doCommunity();
      log('今日任务执行完毕 ✔');
    } catch (e) {
      if (e.code === 'AUTH') log('未登录：请先在 m.dian115.com 登录一次，脚本会复用你的登录态。', 'error');
      else log(`执行中止：${e.message}`, 'error');
    }
  }

  function maybeRun() {
    const s = readState(); const t = today();
    if (s.date !== t) {
      saveState({ date: t, state: 'running' });
      runAll().finally(() => { const cur = readState(); saveState({ ...cur, date: t, state: 'done' }); });
    } else {
      log(`今日（${t}）已在之前执行过（${s.state}），跳过自动触发`, 'warn');
    }
  }

  // ============================ 状态面板 ============================
  let panel, logBox;
  function renderPanel() {
    if (!panel) return;
    logBox.textContent = CONFIG.SHOW_PANEL ? LOG.slice(-18).join('\n') : '';
    const runDate = readState();
    const badge = runDate.date === today() ? `今日 ✓ (${runDate.state})` : '今日未执行';
    panel.dataset.badge = badge;
    const badgeEl = panel.querySelector('.d115-badge');
    if (badgeEl) badgeEl.textContent = badge;
  }
  function buildPanel() {
    panel = document.createElement('div');
    panel.id = 'dian115-auto-panel';
    panel.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:99999;width:300px;max-height:360px;display:flex;flex-direction:column;font:12px/1.5 Menlo,Consolas,monospace;background:#10131a;color:#d6dbe5;border:1px solid #2a3040;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.45);overflow:hidden;';
    panel.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:#1a202c;border-bottom:1px solid #2a3040;">
        <span style="font-weight:600;">癫影每日任务</span>
        <span class="d115-badge" style="margin-left:auto;font-size:11px;color:#8ab4f8;"></span>
      </div>
      <pre class="d115-log" style="flex:1;overflow:auto;padding:8px 10px;margin:0;white-space:pre-wrap;word-break:break-all;min-height:90px;"></pre>
      <div style="display:flex;gap:8px;padding:8px;border-top:1px solid #2a3040;">
        <button class="d115-run" style="flex:1;padding:6px;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer;">立即执行</button>
        <button class="d115-toggle" style="flex:0 0 auto;padding:6px;border:0;border-radius:6px;background:#374151;color:#cbd5e1;cursor:pointer;">面板收起</button>
      </div>`;
    document.body.appendChild(panel);
    logBox = panel.querySelector('.d115-log');
    // 收起后的小挂件（展开入口），常态隐藏。面板本身有内联 display:flex，会覆盖 hidden 属性的
    // display:none——所以收起/展开必须用 panel.style.display 切换，不能用 panel.hidden。
    const pill = document.createElement('div');
    pill.id = 'dian115-auto-pill';
    pill.title = '展开癫影任务面板';
    pill.textContent = '癫影·任务面板';
    pill.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:99999;padding:6px 14px;font:12px Menlo,Consolas,monospace;background:#10131a;color:#8ab4f8;border:1px solid #2a3040;border-radius:16px;box-shadow:0 4px 16px rgba(0,0,0,.4);cursor:pointer;display:none;';
    pill.addEventListener('click', () => setCollapsed(false));
    document.body.appendChild(pill);
    const toggleBtn = panel.querySelector('.d115-toggle');
    let collapsed = false;
    function setCollapsed(hide) {
      collapsed = hide;
      panel.style.display = hide ? 'none' : 'flex';
      pill.style.display = hide ? 'block' : 'none';
      toggleBtn.textContent = hide ? '面板展开' : '面板收起';
      if (!hide) renderPanel();
    }
    panel.querySelector('.d115-run').addEventListener('click', () => {
      const s = readState();
      saveState({ ...s, date: '-', state: 'manual' });
      log('手动触发执行……');
      runAll().finally(() => { const cur = readState(); saveState({ ...cur, date: today(), state: 'done' }); });
    });
    toggleBtn.addEventListener('click', () => setCollapsed(!collapsed));
    renderPanel();
  }

  window.setTimeout(() => {
    if (CONFIG.SHOW_PANEL) buildPanel();
    if (CONFIG.AUTO_RUN) maybeRun();
  }, 800);
})();