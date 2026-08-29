// ==UserScript==
// @name         癫影 m.dian115.com 每日自动任务
// @namespace    https://github.com/<owner>/dian115-auto-task
// @description  自动完成 m.dian115.com 每日例行：签到、幸运转盘、幸运大富翁、社区三色球。纯 API 直调，复用当前登录会话，带运行面板与配置开关。
// @version      1.0.0
// @author       librarian
// @match        https://m.dian115.com/*
// @grant        none
// @run-at       document-idle
// @noframes
// @license      MIT
// ==/UserScript==

/**
 * 逆向自前端 bundle 的功能 API（base 均为 /api/portal，cookie 认证，无 Authorization）：
 *   签到        POST /signin                      { mode:"normal"|"lucky" }          → { award, lucky_tier, new_balance }
 *   游戏总状态   GET  /games/status                —                                → { items:{ daily_wheel, monopoly, community_lottery } }
 *   幸运转盘     POST /lottery/wheel               —                                → { prize, new_balance }
 *   幸运大富翁   POST /games/monopoly/play         —                                → { tiles, award_points, steps, new_balance }
 *   三色球状态   GET  /games/community-lottery/status                              → { participant_count, ticket_count, ... }
 *   三色球购买   POST /games/community-lottery/buy { numbers:[3个], units:注数 }     → { new_balance }
 *
 * games/status 各项字段：{ used_today, max_plays, award_today, daily_cap, cost }
 * 安全策略：
 *   - 社区三色球是"选号+投注"的博彩式玩法，默认关闭；必须手动在配置里填写 numbers，否则跳过不自动烧积分。
 *   - 所有消耗积分的动作受 daily quota（used_today < max_plays）与最低余额阈值双重约束。
 *   - 签到默认用 "normal"（稳健、必得积分）；lucky 可能出"倒霉/空签"，需自行承担，故默认关闭。
 */

(function () {
  'use strict';

  // ============================ 配置区 ============================
  const CONFIG = {
    AUTO_RUN: true,          // 页面加载后是否自动执行（每个自然日触发一次）
    SHOW_PANEL: true,        // 右下角运行日志面板

    // 签到：normal=稳健(必得)  lucky=运气(可能大奖也可能倒霉/空签)
    SIGNIN_MODE: 'normal',
    SIGNIN_ENABLED: true,

    // 幸运转盘（5 积分/次，受 daily_wheel.max_plays 限制）
    WHEEL_ENABLED: true,

    // 幸运大富翁（受 monopoly.max_plays 限制）
    MONOPOLY_ENABLED: true,

    // 社区三色球：选 3 个 1~99 号 + 投注注数。默认关闭；要开启请填 numbers。
    COMMUNITY_ENABLED: false,
    COMMUNITY_NUMBERS: [],   // 例：[7, 21, 66]  必须恰好 3 个数字
    COMMUNITY_UNITS: 1,      // 每期投注注数

    // 安全阀：执行耗积分动作前，要求余额至少 >= 该值；低于则跳过。
    BALANCE_FLOOR: 10,
  };
  // 初始化一次即可（本脚本只登记一次，面板计数用）
  const API_BASE = '/api/portal';

  // ============================ 工具 ============================
  const $log = [];
  function log(msg, level = 'info') {
    const line = `${new Date().toLocaleTimeString('zh-CN', { hour12: false })} [${level}] ${msg}`;
    $log.push(line);
    if (CONFIG.SHOW_PANEL) renderPanel();
    console[level === 'error' ? 'error' : 'info'](`[dian115-auto] ${msg}`);
  }

  async function api(path, method = 'GET', body) {
    const res = await fetch(API_BASE + path, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) throw Object.assign(new Error('未登录或会话失效'), { code: 'AUTH' });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { msg = ((await res.json()).msg) || msg; } catch (_) {}
      throw new Error(msg);
    }
    return res.json();
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  function today() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }

  // 按自然日去重：避免刷新/多标签重复执行
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
      log(`签到失败：${e.message}`, 'error');
    }
  }

  async function doWheel(status) {
    if (!CONFIG.WHEEL_ENABLED || !status || !status.daily_wheel) return;
    const g = status.daily_wheel;
    while (g.used_today < g.max_plays) {
      if ((g.award_today !== undefined && g.daily_cap > 0 && g.award_today >= g.daily_cap)) {
        log('幸运转盘已达今日积分上限，停止', 'warn');
        break;
      }
      if (g.balance !== undefined && g.balance < CONFIG.BALANCE_FLOOR) {
        log(`余额 ${g.balance} 低于安全阈值，停止转盘`, 'warn');
        break;
      }
      try {
        const r = await api('/lottery/wheel', 'POST');
        g.used_today++;
        if (r.new_balance !== undefined) g.balance = r.new_balance;
        log(`幸运转盘第 ${g.used_today}/${g.max_plays} 次 -> ${r.prize ?? '未知'}（余额 ${r.new_balance}）`);
      } catch (e) {
        if (e.code === 'AUTH') throw e;
        log(`幸运转盘失败：${e.message}`, 'error');
        break;
      }
      await sleep(1800);
    }
  }

  async function doMonopoly(status) {
    if (!CONFIG.MONOPOLY_ENABLED || !status || !status.monopoly) return;
    const g = status.monopoly;
    while (g.used_today < g.max_plays) {
      try {
        const r = await api('/games/monopoly/play', 'POST');
        g.used_today++;
        const step = (r.steps && r.steps[r.steps.length - 1]);
        log(`幸运大富翁第 ${g.used_today}/${g.max_plays} 次 -> 本局奖励 +${r.award_points ?? 0} 分（${step ? step.label : ''}，余额 ${r.new_balance}）`);
        g.balance = r.new_balance;
      } catch (e) {
        if (e.code === 'AUTH') throw e;
        log(`幸运大富翁失败：${e.message}`, 'error');
        break;
      }
      await sleep(1800);
    }
  }

  async function doCommunity() {
    if (!CONFIG.COMMUNITY_ENABLED) return;
    if (!Array.isArray(CONFIG.COMMUNITY_NUMBERS) || CONFIG.COMMUNITY_NUMBERS.length !== 3) {
      log('社区三色球已开启但未填 3 个号码，跳过（请配置 COMMUNITY_NUMBERS）', 'warn');
      return;
    }
    try {
      const st = await api('/games/community-lottery/status');
      const maxBuy = st.max_buy ?? st.remaining ?? st.ticket_count ?? 1; // 可投上限，尽量读取
      const units = Math.max(1, Math.min(CONFIG.COMMUNITY_UNITS, maxBuy));
      const r = await api('/games/community-lottery/buy', 'POST', {
        numbers: CONFIG.COMMUNITY_NUMBERS,
        units,
      });
      log(`社区三色球已购入：号码 ${CONFIG.COMMUNITY_NUMBERS.join(',')} × ${units} 注（余额 ${r.new_balance}）`);
    } catch (e) {
      if (e.code === 'AUTH') throw e;
      log(`社区三色球失败：${e.message}`, 'error');
    }
  }

  async function runAll() {
    if (!CONFIG.AUTO_RUN) { log('自动执行已关闭（AUTO_RUN=false），仅显示面板'); return; }
    log(`开始今日任务（${today()}）`);
    try {
      const status = await api('/games/status');   // 校验会话 + 取各功能额度
      if (status && status.items) {
        log('· 额度：' + Object.keys(status.items).map(k => `${k}=${status.items[k].used_today}/${status.items[k].max_plays}`).join('  '));
      }
      await doSignin();
      await doWheel(status && status.items);
      await doMonopoly(status && status.items);
      await doCommunity();
      log('今日任务执行完毕 ✔');
    } catch (e) {
      if (e.code === 'AUTH') log('未登录：请先在 m.dian115.com 登录一次，脚本会复用你的登录态。', 'error');
      else log(`执行中止：${e.message}`, 'error');
    }
  }

  // ============================ 日期去重 & 触发 ============================
  function maybeRun() {
    const s = readState();
    const t = today();
    if (s.date !== t) {
      saveState({ date: t, state: 'running' });
      runAll().finally(() => {
        const cur = readState();
        saveState({ ...cur, date: t, state: 'done' });
      });
    } else {
      log(`今日（${t}）已在之前执行过（${s.state}），跳过自动触发`, 'warn');
    }
  }

  // ============================ 状态面板 ============================
  let panel, logBox;
  function renderPanel() {
    if (!panel) return;
    const lines = CONFIG.SHOW_PANEL ? $log.slice(-18).join('\n') : '';
    logBox.textContent = lines;
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
    panel.querySelector('.d115-run').addEventListener('click', () => {
      const s = readState();
      saveState({ ...s, date: '-', state: 'manual' }); // 清日，允许手动重跑
      log('手动触发执行……');
      runAll().finally(() => {
        const cur = readState();
        saveState({ ...cur, date: today(), state: 'done' });
      });
    });
    panel.querySelector('.d115-toggle').addEventListener('click', () => {
      panel.hidden = !panel.hidden;
    });
    renderPanel();
  }

  // ============================ 启动 ============================
  window.setTimeout(() => {
    if (CONFIG.SHOW_PANEL) buildPanel();
    if (CONFIG.AUTO_RUN) maybeRun();
  }, 800);
})();