// 最小 DOM 桩：验证面板 JS 在真实形状的数据下不报错、能产出节点。
// 跑法：node tools/panel_check.js
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');

function mkEl(tag) {
  const e = {
    tagName: (tag || 'div').toUpperCase(),
    children: [], _text: '', className: '', style: {}, dataset: {},
    onclick: null, onkeydown: null, disabled: false, title: '',
    value: '', type: '', placeholder: '', colSpan: 1, id: '',
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { this.children = this.children.filter(x => x !== c); },
    setAttribute(k, v) { if (k === 'data-tab') this.dataset.tab = v; },
    removeAttribute() {},
    addEventListener() {},
    get classList() {
      const self = this;
      const list = () => self.className.split(/\s+/).filter(Boolean);
      const save = a => { self.className = a.join(' '); };
      return {
        add(c) { const a = list(); if (!a.includes(c)) { a.push(c); save(a); } },
        remove(c) { save(list().filter(x => x !== c)); },
        contains(c) { return list().includes(c); },
        toggle(c, f) {
          const has = list().includes(c);
          const on = (f === undefined) ? !has : !!f;
          if (on && !has) { const a = list(); a.push(c); save(a); }
          else if (!on) save(list().filter(x => x !== c));
        },
      };
    },
    get textContent() { return this._text; },
    set textContent(v) { this._text = String(v); },
    get innerHTML() { return this._html || ''; },
    set innerHTML(v) { this._html = String(v); if (v === '') this.children = []; },
    querySelector() { return mkEl('div'); },
    querySelectorAll() { return []; },
    get firstChild() { return this.children[0] || null; },
  };
  return e;
}

const registry = new Map();
global.document = {
  getElementById(id) {
    if (!registry.has(id)) { const e = mkEl('div'); e.id = id; registry.set(id, e); }
    return registry.get(id);
  },
  createElement(tag) { return mkEl(tag); },
  createElementNS(ns, tag) { return mkEl(tag); },
  createTextNode(t) { return { nodeValue: t, textContent: t }; },
  querySelector() { return mkEl('div'); },
  querySelectorAll(sel) {
    const m = /\[data-tab(?:="([^"]*)")?\]/.exec(sel || '');
    if (!m) return [];
    const want = m[1];
    return [...registry.values()].filter(e => e.dataset && e.dataset.tab !== undefined
      && (want === undefined || e.dataset.tab === want));
  },
  addEventListener() {},
  body: mkEl('body'),
  documentElement: mkEl('html'),
};
global.window = {
  addEventListener() {}, scrollTo() {},
  location: { href: '', hash: '' },
};
global.location = global.window.location;
global.history = { replaceState() {}, pushState() {} };
global.fetch = () => new Promise(() => {});
global.confirm = () => false;
global.setInterval = () => 0;
global.clearInterval = () => {};
global.setTimeout = () => 0;
global.__toasts = [];

const html = fs.readFileSync(path.join(ROOT, 'homewatch/web/page.html'), 'utf8');
const code = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const patched = code.replace(
  'function toast(msg,isErr){',
  'function toast(msg,isErr){ global.__toasts.push([msg,!!isErr]); return;'
);

try {
  eval(patched);
} catch (e) {
  console.error('✗ 脚本执行失败:', e.message);
  process.exit(1);
}
console.log('✓ 脚本加载完成');

function dummyState() {
  return {
    level: 'green', msg: '一切正常', generated_at_str: '21:00',
    kpi: { total_today: 0, blocked_today: 0, passed_today: 0, blocked_10m: 0, ssh_today: 0, ssh_10m: 0, auto_bans_today: 0 },
    net_items: [], timeline: [], ips: [], paths: [], geo_top: [], geo_known: 0,
    total_24h: 0, anomaly: [], ssh: {}, ssh_top: [], leak: [],
  };
}

const state = {
  generated_at: 1762700000,
  ports: [{ port: 22, label: 'SSH', desc: '远程管理', closed: false, listening: true, readonly: false,
            ctrl: { in: 'lan', out: 'allow', proto: 'tcp' } },
          { port: 8088, label: '监控面板', desc: '本页自身', closed: false, listening: true, readonly: true,
            ctrl: { in: 'lan', out: 'allow', proto: 'tcp' } }],
  ssh: { socket_active: true, port: 22, password_age: 20 },
  auth: { path: '/etc/nginx/.htpasswd.homewatch', exists: true, user: 'admin',
          users: ['admin'], age_days: 3, mtime: 1762700000, backup: true,
          mode: '0640', warnings: [] },
  blocked_nft: [{ ip: '203.0.113.45', until: 0, reason: '自动封禁：单 IP 高频请求', auto: true, geo: '中国台湾·臺北', cc: 'TW' }],
  blocked_nginx: ['203.0.113.45'],
  cf: {
    updated: 1762600000, v4: 15, v6: 7,
    api: { enabled: true, configured: true, auto_sync: true, zone: 'example.com', zone_id: '',
           token: 'TTTT…TTTT', has_token: true, note: 'HomeWatch', timeout: 8 },
    last: { at: 1762700000, ok: true, msg: 'Cloudflare 边缘规则：新增 1', added: ['45.1.2.3'], failed: [] },
    synced_at: 1762700000,
  },
  policy: {
    enabled: true, auto_ban: true, dry_run: false,
    ban_mode: 'silent', ban_mode_label: '444 静默断开', silent_log: true,
    wiring: { mode: 'silent', mode_label: '444 静默断开', want_code: 444,
              wired: false, log_wired: false, files: [],
              warnings: ['站点配置里没找到 $blocked_scanner 引用，封禁规则目前不会生效'] },
    max_bans_per_run: 3, max_hours: 720, repeat_window_hours: 72,
    whitelist: ['198.51.100.7'],
    limits: { uri_len: 1024, req_bytes: 65536, ua_len: 400 },
    allowed_methods: ['GET', 'HEAD'],
    trusted_bots: ['googlebot', 'bingbot'],
    warnings: [], log_fields: { request_length: false, user_agent: true },
    rules: [
      { id: 'honeypot', name: '蜜罐路径', source: 'honeypot', window: 3600, threshold: 1, hours: 72, layer: 'both', enabled: true },
      { id: 'ip_rate', name: '单 IP 高频请求', source: 'http_total', window: 120, threshold: 120, hours: 12, layer: 'both', enabled: true },
    ],
    last: { at: 1762700000, msg: '已自动封禁 1 个 IP', banned: [{ ip: '203.0.113.45', hours: 24, geo: '中国台湾·臺北', reason: '自动封禁：单 IP 高频请求' }] },
    bans: [{ ts: 1762700000, ip: '203.0.113.45', hours: 24, layer: 'both', rule: 'ip_rate', reason: '自动封禁：单 IP 高频请求', mode: 'auto', hits: 120, geo: '中国台湾·臺北', cc: 'TW' }],
  },
  limits: { red_threshold_10m: 50, yellow_threshold_10m: 1, retention_days: 30 },
  units: {
    guard: { on: true, file: '/etc/systemd/system/homewatch-admin.service.d/10-homewatch-guard.conf',
             restart: 'always' },
    last_collect: 1762700000, lag: 40, checked_at: 1762700000, warnings: [],
    units: [
      { name: 'homewatch.timer', label: '采集定时器', desc: '每分钟唤一次采集', kind: 'timer',
        readonly: false, active: 'active', sub: 'waiting', enabled: true, unit_state: 'enabled',
        pid: 0, restarts: 0, result: 'success', memory: '', since: 1762600000, next: 1762700030 },
      { name: 'homewatch-admin.service', label: '管理接口', desc: '面板背后的接口', kind: 'daemon',
        readonly: false, active: 'active', sub: 'running', enabled: true, unit_state: 'enabled',
        pid: 812, restarts: 2, result: 'success', memory: '24.1 MB', since: 1762680000, next: 0 },
      { name: 'nginx.service', label: 'Nginx', desc: '站点入口', kind: 'daemon',
        readonly: true, active: 'active', sub: 'running', enabled: true, unit_state: 'enabled',
        pid: 604, restarts: 0, result: 'success', memory: '38.6 MB', since: 1762600000, next: 0 },
    ],
  },
  geo: { enabled: true, provider: 'auto' },
  own_ips: ['203.0.113.9'],
  fw: {
    rules: [
      { id: 'r10', name: 'SSH 仅内网', note: '', dir: 'in', dir_label: '入站',
        proto: 'tcp', proto_label: 'TCP', port: '22', src: ['192.168.1.0/24'],
        src_label: '192.168.1.0/24', action: 'accept', action_label: '放行',
        enabled: true, priority: 10, hits: 1280, bytes: 203456 },
      { id: 'r20', name: '面板白名单', note: '管理口只给家里',
        dir: 'in', dir_label: '入站', proto: 'tcp', proto_label: 'TCP', port: '8088',
        src: ['192.168.1.0/24', '10.0.0.0/8'], src_label: '内网',
        action: 'accept', action_label: '放行', enabled: true, priority: 20,
        hits: 42, bytes: 8192 },
      { id: 'r30', name: '拒绝扫描器', note: '', dir: 'in', dir_label: '入站',
        proto: 'all', proto_label: '全部', port: '', src: ['203.0.113.77'],
        src_label: '203.0.113.77', action: 'drop', action_label: '拒绝',
        enabled: false, priority: 30, hits: 0, bytes: 0 },
    ],
    policy: { in: 'drop', out: 'accept' },
    container: true,
    seq: 30,
  },
  fw_ctx: {
    lan: ['192.168.1.0/24', '10.0.0.0/8'], cf: ['173.245.48.0/20'],
    own: ['203.0.113.9'], admin_port: 8088, ssh_port: 22,
  },
  listen: [
    { port: 22, procs: ['sshd'], pids: [812], addr: '*', container: null },
    { port: 9000, procs: ['docker-proxy'], pids: [1904], addr: '0.0.0.0',
      container: { name: 'minio', image: 'minio/minio' } },
  ],
  geo_lock: {
    in: { enabled: true, scope: 'web', scope_label: '只挡 Web 端口', ports: [80, 443, 8088] },
    out: { enabled: false },
    container: true,
    allow: ['198.18.0.0/15'],
    cn: { v4: 4339, v6: 1688, updated: 1762600000, source: 'clang.cn', age_days: 3 },
    exempt: { lan: ['192.168.1.0/24'], own: ['203.0.113.9/32'], cf: 22,
              dns: ['192.168.1.1'], allow: ['198.18.0.0/15'] },
    hits: { in: { packets: 1820, bytes: 240000 }, out: { packets: 0, bytes: 0 } },
    loaded: true,
    counters: true, on: true,
  },
  banned: {
    '203.0.113.45': { ip: '203.0.113.45', nft: true, nginx: true, cf: false,
                       until: 0, reason: '自动封禁：单 IP 高频请求', auto: true,
                       layers: ['nft', 'nginx'], label: 'nft、nginx' },
  },
  audit: [{ at: '2026-11-09 21:50', action: 'ip.block', args: { ip: '203.0.113.45' }, ok: true, msg: '已封禁' }],
};

try { render(dummyState()); } catch (e) { console.error('✗ render 失败:', e.message); process.exit(1); }
console.log('✓ 态势页渲染完成');

try { renderAdmin(state); } catch (e) {
  console.error('✗ renderAdmin 失败:', e.stack.split('\n').slice(0, 3).join(' | '));
  process.exit(1);
}
console.log('✓ 管理页渲染完成');

const cfBox = document.getElementById('cfState');
console.log('  Cloudflare 状态节点:', cfBox.children.length);
if (!cfBox.children.length) { console.error('✗ Cloudflare 卡片是空的'); process.exit(1); }
console.log('  边缘规则表行数:', document.getElementById('cfList').children.length);
console.log('  封禁表行数:', document.getElementById('adm-blocked').children.length);
console.log('  模式下拉值:', document.getElementById('banMode').value);
console.log('  模式提示:', document.getElementById('banModeHint').textContent.slice(0, 50));

const txt = n => (n._text || '') + (n.children || []).map(txt).join(' ');
const authBox = document.getElementById('adm-auth');
const authRows = authBox.children.length;
console.log('  面板登录卡片节点:', authRows);
if (!authRows) { console.error('✗ 面板登录卡片是空的'); process.exit(1); }
if (!txt(authBox).includes('admin')) { console.error('✗ 面板登录卡片没显示用户名'); process.exit(1); }
console.log('  面板登录卡片内容:', txt(authBox).replace(/\s+/g, ' ').slice(0, 90));
if (!document.getElementById('pwaBtn')) { console.error('✗ 缺少面板密码按钮'); process.exit(1); }
console.log('  面板密码按钮: 存在');

/* ---- 端口出入站 + 进程守护（v0.6 新增） ---- */
const portsTbl = document.getElementById('adm-ports');
const portsTxt = txt(portsTbl);
console.log('  端口表行数:', portsTbl.children.length, '（含表头）');
if (portsTbl.children.length !== state.ports.length + 1) {
  console.error('✗ 端口表行数和 ports 数量对不上'); process.exit(1);
}
['入站', '出站', '内网', '放行'].forEach(w => {
  if (!portsTxt.includes(w)) { console.error('✗ 端口表缺文案:', w); process.exit(1); }
});
const segCount = (function walk(n) {
  let k = (n.className || '').split(/\s+/).includes('seg') ? 1 : 0;
  return k + (n.children || []).reduce((a, c) => a + walk(c), 0);
})(portsTbl);
console.log('  分段控件个数:', segCount, '（每个端口 2 个：入站 + 出站）');
if (segCount !== state.ports.length * 2) {
  console.error('✗ 分段控件数量不对，出入站没渲染出来'); process.exit(1);
}

const unitsBox = document.getElementById('adm-units');
const unitsTxt = txt(unitsBox);
console.log('  服务行数:', unitsBox.children.length);
if (unitsBox.children.length !== state.units.units.length) {
  console.error('✗ 服务行数和 units 数量对不上'); process.exit(1);
}
if (!unitsTxt.includes('只读')) { console.error('✗ 只读单元没标出来'); process.exit(1); }
if (!unitsTxt.includes('重启 2 次')) { console.error('✗ 服务行没显示重启次数'); process.exit(1); }
const guardBox = document.getElementById('adm-guard');
const guardTxt = txt(guardBox);
console.log('  守护卡片:', guardTxt.replace(/\s+/g, ' ').slice(0, 70));
if (!guardTxt.trim()) { console.error('✗ 守护卡片是空的'); process.exit(1); }

/* ---- 防火墙规则表（v0.7 新增） ---- */
const walkAll = (n, pred, out) => {
  out = out || [];
  if (pred(n)) out.push(n);
  (n.children || []).forEach(c => walkAll(c, pred, out));
  return out;
};
const fwTbl = document.getElementById('fwTable');
const fwTxt = txt(fwTbl);
console.log('  防火墙规则行数:', fwTbl.children.length, '（含表头）');
if (fwTbl.children.length !== state.fw.rules.length + 1) {
  console.error('✗ 规则表行数和 fw.rules 数量对不上'); process.exit(1);
}
['匹配条件', '放行', '拒绝', '命中', '启用'].forEach(w => {
  if (!fwTxt.includes(w)) { console.error('✗ 规则表缺文案:', w); process.exit(1); }
});
if (!fwTxt.includes('192.168.1.0/24')) {
  console.error('✗ 规则表没显示来源地址'); process.exit(1);
}
const ordBtns = walkAll(fwTbl, n => (n.className || '').includes('fw-ord'));
console.log('  排序按钮组:', ordBtns.length);
if (ordBtns.length !== state.fw.rules.length) {
  console.error('✗ 每条规则都该有上下移按钮'); process.exit(1);
}
const fwNote = document.getElementById('fwNote');
console.log('  规则概览:', fwNote.textContent);
if (!/\d+ 条启用/.test(fwNote.textContent)) {
  console.error('✗ 规则概览没写启用条数'); process.exit(1);
}

/* 默认策略：入站拒绝 + 已有 8088 白名单 → 不该告警 */
const polBox = document.getElementById('fwPolicy');
const polTxt = txt(polBox);
if (!polTxt.includes('入站') || !polTxt.includes('容器转发')) {
  console.error('✗ 默认策略卡片缺内容'); process.exit(1);
}
if (polTxt.includes('还没有放行面板端口')) {
  console.error('✗ 面板端口已被规则覆盖，不该提示缺白名单'); process.exit(1);
}
const segPol = walkAll(polBox, n => (n.className || '').split(/\s+/).includes('seg'));
console.log('  策略分段控件:', segPol.length, '（入站 + 出站）');
if (segPol.length !== 2) { console.error('✗ 入站/出站策略开关没渲染'); process.exit(1); }

/* 把覆盖 8088 的规则拿掉 → 必须告警 */
const noCover = JSON.parse(JSON.stringify(state));
noCover.fw.rules = [noCover.fw.rules[0]];
try { renderFwPolicy(noCover); } catch (e) {
  console.error('✗ renderFwPolicy(noCover) 失败:', e.message); process.exit(1);
}
if (!txt(document.getElementById('fwPolicy')).includes('还没有放行面板端口')) {
  console.error('✗ 入站默认拒绝且无白名单时没告警'); process.exit(1);
}
try { renderFwPolicy(state); } catch (e) {
  console.error('✗ renderFwPolicy 还原失败:', e.message); process.exit(1);
}
console.log('  ✓ 默认拒绝的锁死防呆提示正常');

const baseTxt = txt(document.getElementById('fwBase'));
if (!baseTxt.includes('入 内网') || !baseTxt.includes('22')) {
  console.error('✗ 端口页基线没反映 ports 的出入站类型'); process.exit(1);
}
const listenBox = document.getElementById('fwListen');
const listenTxt = txt(listenBox);
const scroller = walkAll(listenBox, n => (n.className || '').includes('listen-scroll'))[0];
console.log('  监听端口行数:', scroller ? scroller.children.length : 0, '（列表自带滚动）');
if (!scroller || scroller.children.length !== state.listen.length) {
  console.error('✗ 监听端口行数不对'); process.exit(1);
}
if (listenBox.children.length !== 2) {
  console.error('✗ 监听卡片应是「滚动列表 + 底部提示」两块'); process.exit(1);
}
if (!listenTxt.includes('容器 minio') || !listenTxt.includes('Docker')) {
  console.error('✗ 监听端口没标出容器或转发提示'); process.exit(1);
}

/* 概览六格 + 守护格里的开关 */
const strip = document.getElementById('admStrip');
console.log('  概览格数:', strip.children.length);
if (strip.children.length !== 6) {
  console.error('✗ 概览应有 6 格（服务/端口/防火墙/封禁/守护/Cloudflare）'); process.exit(1);
}
const swEl = walkAll(strip, n => (n.className || '').includes('t-sw'));
if (!swEl.length) { console.error('✗ 概览里找不到守护开关'); process.exit(1); }
console.log('  ✓ 概览格内嵌守护开关:', swEl.length, '个');

/* 异常来源 IP 铺在类型下 */
try {
  applyRisk({
    anomaly: [{ kind: 'honeypot', label: '蜜罐路径', n: 37, ips: 12, vmax: 1,
      top: [{ ip: '203.0.113.77', n: 20 }, { ip: '203.0.113.45', n: 9 },
            { ip: '61.4.2.9', n: 3 }] }],
    ssh: { total: 0, top: [] }, leak: [],
  });
} catch (e) {
  console.error('✗ applyRisk 失败:', e.stack.split('\n').slice(0, 3).join(' | '));
  process.exit(1);
}
const anBox = document.getElementById('anomaly');
const anTxt = txt(anBox);
const anIps = walkAll(anBox, n => n.dataset && n.dataset.ip);
console.log('  异常来源 IP 节点:', anIps.length, '｜文案片段:',
  anTxt.replace(/\s+/g, ' ').slice(0, 60));
if (anIps.length !== 3) { console.error('✗ 异常行没把来源 IP 铺出来'); process.exit(1); }
if (!anTxt.includes('全部 12 个来源')) {
  console.error('✗ 异常行没给「全部 N 个来源」入口'); process.exit(1);
}
const anLinks = walkAll(anBox, n => (n.className || '').split(/\s+/).includes('link'));
if (anLinks.length !== 1) { console.error('✗ 异常行不可点开抽屉'); process.exit(1); }

/* IP 可点：delegation 依赖 data-ip，这里只验证 span 带上了标记 */
const probeIp = ipSpan('1.2.3.4');
if (probeIp.dataset.ip !== '1.2.3.4' || !/\bip\b/.test(probeIp.className)) {
  console.error('✗ ipSpan 没带 data-ip/.ip 类，点击弹窗会失效'); process.exit(1);
}

/* ---- 地域封锁（v0.8 新增） ---- */
const geoBox = document.getElementById('geoSwitch');
const geoTxt = txt(geoBox);
const geoRows = walkAll(geoBox, n => (n.className || '').split(/\s+/).includes('swrow'));
console.log('  地域开关行数:', geoRows.length, '｜概览:', document.getElementById('geoNote').textContent);
if (geoRows.length !== 2) {
  console.error('✗ 地域开关应有「外来 / 对外」两行'); process.exit(1);
}
['外来', '对外', '境外'].forEach(w => {
  if (!geoTxt.includes(w)) { console.error('✗ 地域卡片缺文案:', w); process.exit(1); }
});
const geoTgl = walkAll(geoBox, n => (n.className || '').includes('tgl'));
if (geoTgl.length !== 2) { console.error('✗ 两个方向各要一个开关'); process.exit(1); }
if (!geoTgl[0].className.includes('on') || geoTgl[1].className.includes('on')) {
  console.error('✗ 开关状态和 geo_lock.enabled 不一致'); process.exit(1);
}
const geoScopeSeg = walkAll(geoBox, n => (n.className || '').split(/\s+/).includes('seg'));
if (!geoScopeSeg.length) { console.error('✗ 外来封锁缺少作用范围选择'); process.exit(1); }

const cnTxt = txt(document.getElementById('geoCn'));
console.log('  国内网段卡:', cnTxt.replace(/\s+/g, ' ').slice(0, 60));
if (!cnTxt.includes('4339') || !cnTxt.includes('clang.cn')) {
  console.error('✗ 国内网段卡没显示段数或来源'); process.exit(1);
}
const exTxt = txt(document.getElementById('geoExempt'));
if (!exTxt.includes('198.18.0.0/15') || !exTxt.includes('192.168.1.1')) {
  console.error('✗ 豁免卡没列出自定义放行 / DNS'); process.exit(1);
}
const hitTxt = txt(document.getElementById('geoHits'));
console.log('  命中卡:', hitTxt.replace(/\s+/g, ' ').slice(0, 60));
if (!hitTxt.includes('1820')) { console.error('✗ 命中卡没显示丢包数'); process.exit(1); }

/* ---- 已封禁标记 + 一键封禁（v0.8 新增） ---- */
const bannedWrap = ipSpan('203.0.113.45');
const hasBanTag = (bannedWrap.children || []).some(c => (c.className || '').includes('ban-tag'));
if (!hasBanTag) { console.error('✗ 已封禁的 IP 没带「已封禁」标'); process.exit(1); }
if (!/banned/.test(bannedWrap.children[0].className)) {
  console.error('✗ 已封禁的 IP 没加 .banned 样式'); process.exit(1);
}
const btnBanned = banToggle('203.0.113.45');
const btnFree = banToggle('1.2.3.4');
console.log('  一键封禁按钮:', btnBanned.textContent, '/', btnFree.textContent);
if (btnBanned.textContent !== '解封') { console.error('✗ 已封禁的 IP 应显示「解封」'); process.exit(1); }
if (btnFree.textContent !== '封禁') { console.error('✗ 未封禁的 IP 应显示「封禁」'); process.exit(1); }

/* 来源表要有操作列，且已封禁那行的按钮是「解封」 */
try {
  applySources({
    label: '近 1 小时',
    ips: [{ ip: '203.0.113.45', n: 4120, blocked: 3800, last: 1762700000,
            geo: { cc: 'TW', label: '中国台湾·臺北' }, label: '中国台湾·臺北' },
          { ip: '203.0.113.77', n: 980, blocked: 920, last: 1762700000,
            geo: { cc: 'NL', label: '荷兰·阿姆斯特丹' }, label: '荷兰·阿姆斯特丹' }],
    geo: [], status: [], paths: [],
  });
} catch (e) {
  console.error('✗ applySources 失败:', e.stack.split('\n').slice(0, 3).join(' | '));
  process.exit(1);
}
const ipsTbl = document.getElementById('ips');
const ipsBtns = walkAll(ipsTbl, n => n.tagName === 'BUTTON' && /^(封禁|解封)$/.test(n.textContent || ''));
console.log('  来源表操作按钮:', ipsBtns.map(b => b.textContent).join(' / '));
if (ipsBtns.length !== 2) { console.error('✗ 来源表每行都该有一键封禁按钮'); process.exit(1); }
if (ipsBtns[0].textContent !== '解封') {
  console.error('✗ 已封禁来源应显示「解封」'); process.exit(1);
}
if (!txt(ipsTbl).includes('已封禁')) {
  console.error('✗ 来源表没标出已封禁'); process.exit(1);
}

try { renderPolicy(state); } catch (e) { console.error('✗ renderPolicy 失败:', e.message); process.exit(1); }
console.log('✓ 策略页渲染完成');
console.log('  toast 调用:', JSON.stringify(global.__toasts));

/* ---- 导航骨架 ---- */
const tpl = fs.readFileSync(path.join(ROOT, 'homewatch/web/page.html'), 'utf8');
const need = ['class="side"', 'class="bottomnav"', 'data-tab="mon"',
              'data-tab="adm"', 'data-tab="pol"', 'id="pageTitle"', 'id="liveChip"'];
const miss = need.filter(x => !tpl.includes(x));
if (miss.length) { console.error('✗ 导航骨架缺元素:', miss.join(', ')); process.exit(1); }
console.log('✓ 导航骨架完整:', need.length, '项');
console.log('  初始页面标题:', document.getElementById('pageTitle').textContent);
if (document.getElementById('pageTitle').textContent !== '态势') {
  console.error('✗ 初始标题不对'); process.exit(1);
}
if (!document.getElementById('sideState').textContent) {
  console.error('✗ 侧栏状态文字为空'); process.exit(1);
}
console.log('  侧栏状态:', document.getElementById('sideState').textContent);
