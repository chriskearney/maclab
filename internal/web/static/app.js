// maclab — browser UI. No build step, no dependencies: labd serves this file as-is.
'use strict';

// ——— basics ———————————————————————————————————————————————————————————
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const root = document.documentElement;

// Nerd Font Material Design glyphs (JetBrainsMono Nerd Font, the Omarchy default).
const I = {
  laptop: '\u{F0322}', desktop: '\u{F01C4}', apple: '\u{F0035}', chip: '\u{F061A}', heart: '\u{F05F6}', alert: '\u{F0026}',
  play: '\u{F040A}', restart: '\u{F0709}', console: '\u{F018D}', lan: '\u{F0318}', palette: '\u{F03D8}', lock: '\u{F033E}',
  check: '\u{F012C}', close: '\u{F0156}', clock: '\u{F0150}', flash: '\u{F0241}', power: '\u{F0425}', usb: '\u{F0553}',
  upload: '\u{F0552}', file: '\u{F09EE}', image: '\u{F02E9}', robot: '\u{F06A9}', shield: '\u{F0565}', dots: '\u{F01D8}',
  chev: '\u{F0142}', serial: '\u{F065C}', plus: '\u{F0415}', stop: '\u{F04DB}', sand: '\u{F051F}', bolt: '\u{F140B}',
  cpu: '\u{F0EE0}', dash: '\u{F0A07}', monitor: '\u{F0379}', hammer: '\u{F08EA}', camera: '\u{F0100}', pause: '\u{F03E4}', eraser: '\u{F01FE}', list: '\u{F0279}', rocket: '\u{F14DE}', history: '\u{F02DA}', pulse: '\u{F0430}',
  bug: '\u{F00E4}', bell: '\u{F009E}', cloud: '\u{F0167}', keyboard: '\u{F030C}', cog: '\u{F0493}', pkg: '\u{F03D3}',
  hand: '\u{F0A4F}', pcycle: '\u{F0901}', copy: '\u{F018F}', eye: '\u{F0208}', filter: '\u{F0232}', down: '\u{F0140}',
};
const ic = (n, cls = '') => `<span class="i ${cls}">${I[n] || ''}</span>`;

const OMARCHY = ''; // the Omarchy logo glyph in omarchy.ttf

const S = {
  token: store('token') || '',
  theme: store('theme') || 'follow',
  view: 'macs', params: {},
  devices: [], jobs: [], themes: [],
  jobCache: {},         // id -> job
  online: true, locked: false,
  liveDev: null, oob: {},
  logFile: null, logText: null, logFilter: '', detailTab: 'overview',
  shots: {},            // job/file -> object URL
  upload: null,         // {name, pct, sha, err}
  enrolled: null,
  follow: true,         // console auto-scroll
};

function store(k, v) {
  try {
    if (v === undefined) return localStorage.getItem('maclab.' + k);
    if (v === null) localStorage.removeItem('maclab.' + k); else localStorage.setItem('maclab.' + k, v);
  } catch { return null; }
}

// ——— time ———————————————————————————————————————————————————————————————
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const pad = n => String(n).padStart(2, '0');
const hhmm = d => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const hms = d => `${hhmm(d)}:${pad(d.getSeconds())}`;
const zero = t => !t || t.startsWith('0001-');
function ago(t) {
  if (zero(t)) return 'never';
  const s = Math.max(0, (Date.now() - new Date(t)) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
function dur(s) {
  if (s < 1) return '<1s';
  s = Math.max(0, Math.round(s));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${pad(s % 60)}s`;
  const h = Math.floor(s / 3600);
  return h < 48 ? `${h}h ${pad(Math.floor(s % 3600 / 60))}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}
const since = t => (Date.now() - new Date(t)) / 1000;

// ——— API ———————————————————————————————————————————————————————————————
// On a trusted network labd needs no token; otherwise the saved one is sent.
// A tailnet viewer may look without one, and unlocks changes with one.
const lockable = () => !S.open || S.viewer;
const authH = () => S.token ? { Authorization: 'Bearer ' + S.token } : {};
async function api(path, opt = {}) {
  const r = await fetch(path, { ...opt, headers: { ...(opt.headers || {}), ...authH() } });
  if (r.status === 401) { lock('That token was not accepted.'); throw new Error('unauthorized'); }
  const text = await r.text();
  if (!r.ok) throw new Error(text.trim() || r.statusText);
  return (r.headers.get('content-type') || '').includes('json') ? JSON.parse(text) : text;
}
const post = (path, body) => api(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body), headers: { 'Content-Type': 'application/json' } });

// ——— themes: Omarchy colors.toml tokens ————————————————————————————————————
const TOKENS = ['background', 'dark_background', 'darker_background', 'lighter_background', 'foreground', 'dark_foreground',
  'light_foreground', 'bright_foreground', 'accent', 'selection', 'muted', 'red', 'yellow', 'orange', 'green', 'cyan',
  'blue', 'magenta', 'brown', 'bright_red', 'bright_yellow', 'bright_green', 'bright_cyan', 'bright_blue', 'bright_magenta'];

async function loadThemes() {
  try {
    const r = await fetch('/api/themes');
    S.themes = await r.json();
  } catch { S.themes = []; }
  applyTheme();
}

// WCAG contrast ratio between two #rrggbb colors.
function contrast(a, b) {
  const lum = h => {
    const v = parseInt(String(h || '#000').slice(1, 7), 16);
    const ch = [v >> 16, (v >> 8) & 255, v & 255].map(x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; });
    return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
  };
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

function activeTheme() {
  return (S.theme !== 'follow' && S.themes.find(t => t.name === S.theme)) || S.themes.find(t => t.current) || S.themes.find(t => t.name === 'tokyo-night') || S.themes[0];
}

function applyTheme() {
  const t = activeTheme();
  if (!t) return;
  const c = { ...t.colors };
  // Not every theme defines every token; fall back the way a palette reads.
  c.bright_foreground ||= c.foreground;
  c.accent ||= c.blue || c.foreground;
  c.yellow ||= c.orange || c.accent;
  c.orange ||= c.yellow;
  c.green ||= c.cyan || c.accent;
  c.red ||= c.bright_red || c.orange;
  c.magenta ||= c.accent;
  c.selection ||= c.lighter_background || c.background;
  // Some themes set the accent to their background (System 7: white on white).
  // An accent nobody can see is no accent: use the foreground instead.
  if (contrast(c.accent, c.background) < 1.6) c.accent = c.foreground;
  for (const k of TOKENS) c[k] ? root.style.setProperty('--' + k, c[k]) : root.style.removeProperty('--' + k);
  root.dataset.mode = t.mode || 'dark';
  const bg = t.has_background ? `url("/api/themes/${S.theme === 'follow' ? 'current' : encodeURIComponent(t.name)}/background")` : 'none';
  $('#wall').style.backgroundImage = bg;
  root.style.setProperty('--lockbg', bg);
  const meta = $('meta[name=theme-color]') || document.head.appendChild(Object.assign(document.createElement('meta'), { name: 'theme-color' }));
  meta.content = c.background;
  if (S.sh?.term) S.sh.term.options.theme = xtTheme();
}

// ——— vocabulary ————————————————————————————————————————————————————————————
const STATE = {
  ready: ['c-ok', 'Ready'], busy: ['c-info live', 'Testing'], recovering: ['c-warn live', 'Recovering'],
  needs_hands: ['c-bad live', 'Needs hands'], offline: ['c-dim', 'Offline'], new: ['c-odd', 'Needs baseline'],
};
const OUTCOME = {
  pass: ['c-ok', 'check', 'Passed'], tests_failed: ['c-warn', 'close', 'Tests failed'],
  booted_unhealthy: ['c-warn', 'alert', 'Booted, unhealthy'], panicked: ['c-bad', 'flash', 'Panicked'],
  hung: ['c-bad', 'sand', 'Hung'], crashed_or_hung: ['c-bad', 'bolt', 'Crashed or hung'], boot_failed: ['c-bad', 'power', 'Boot failed'], stage_failed: ['c-warn', 'pkg', 'Staging failed'],
  infra_error: ['c-warn', 'cog', 'Lab error'], build_failed: ['c-bad', 'hammer', 'Build failed'], canceled: ['c-dim', 'stop', 'Canceled'],
};
const pill = (cls, label) => `<span class="pill ${cls}">${esc(label)}</span>`;
const statePill = d => pill(...(STATE[d.state] || ['c-dim', d.state]));
function outcomePill(j) {
  if (j.state !== 'done') return pill('c-info live', j.state === 'queued' ? 'Queued' : j.state);
  const [c, , l] = OUTCOME[j.outcome] || ['c-dim', '', j.outcome];
  return pill(c, l);
}
const outcomeColor = j => j.state !== 'done' ? 'var(--info)' : ({ 'c-ok': 'var(--ok)', 'c-bad': 'var(--bad)', 'c-warn': 'var(--warn)' }[(OUTCOME[j.outcome] || [])[0]] || 'var(--faint)');

function jobKind(j) {
  const s = j.spec || {};
  if (s.baseline) return 'Baseline';
  if (s.crash) return 'Crash test';
  if (s.source && !j.result?.boot_kernel) {
    for (const e of j.events || []) { const m = /^(?:staged|reusing|kernel) (\S+?)[: ]/.exec(e.msg); if (m && !/^(owner|build)/.test(m[1])) return m[1]; }
    return repoName({ input: s.source });
  }
  if (!s.kernel) return 'Reboot test';
  if (j.result?.boot_kernel) return j.result.boot_kernel;
  for (const e of j.events || []) { const m = /^staged (\S+) as/.exec(e.msg); if (m) return m[1]; }
  return 'kernel ' + s.kernel.slice(0, 10);
}

const TIER_NAMES = ['panic reboot', 'watchdog', 'out-of-band'];

// Same rules labd runs on serial and kmsg (internal/detect).
const KINDS = [
  ['panic', /Kernel panic - not syncing/], ['oops', /Internal error: Oops|Unable to handle kernel (NULL pointer|paging request)/],
  ['bug', /BUG: soft lockup|hard LOCKUP|rcu: INFO: rcu_\w+ (self-)?detected stall|INFO: task .+ blocked for more than|kernel BUG at|BUG: /],
  ['warn', /WARNING: CPU: \d+ PID: \d+|\bwarn(ing)?\b|\berror\b|\bfail(ed|ure)?\b/i],
  ['mark', /Booting Linux on physical CPU|Run \/\S*init as init process|m1n1|U-Boot|GNU GRUB| login: |\[oobd\]/],
];
const lineKind = l => (KINDS.find(([, re]) => re.test(l)) || [''])[0];

// ——— routing ———————————————————————————————————————————————————————————————
const VIEWS = [['macs', 'macs'], ['jobs', 'jobs'], ['builds', 'builds'], ['run', 'run'], ['live', 'live']];
function parseHash() {
  const [path, q] = location.hash.replace(/^#\/?/, '').split('?');
  const parts = path.split('/').filter(Boolean);
  if (parts[0] === 'console') parts[0] = 'live'; // old links
  const view = VIEWS.some(v => v[0] === parts[0]) ? parts[0] : 'macs';
  return { view, arg: parts[1] ? decodeURIComponent(parts[1]) : null, q: Object.fromEntries(new URLSearchParams(q || '')) };
}
function go(h) { if (location.hash !== h) location.hash = h; else route(); }
window.addEventListener('hashchange', route);

function route() {
  const r = parseHash();
  const changed = r.view !== S.laid;
  S.view = r.view; S.params = r;
  if (r.view === 'jobs') {
    const id = r.arg || S.jobs[0]?.id || null;
    if (id !== S.jobId) { S.jobId = id; S.logFile = null; S.logText = null; S.detailTab = 'overview'; }
  }
  if (r.view === 'builds') {
    const id = r.arg || S.buildId || S.builds[0]?.id || null;
    if (id !== S.buildId) S.buildId = id;
  }
  if (r.view === 'live') {
    const d = r.arg || S.liveDev || store('live') || S.devices[0]?.name || null;
    if (d !== S.liveDev) { S.liveDev = d; S.laid = null; if (d) store('live', d); }
  }
  if (changed) layout();
  paint();
  tick();
}

// ——— painting ——————————————————————————————————————————————————————————————
const painted = new Map();
function put(id, html) {
  const el = document.getElementById(id);
  if (!el || painted.get(el) === html) return el;
  painted.set(el, html);
  el.innerHTML = html;
  return el;
}

function win(id, title, { sub = '', tools = '', area = id, cls = '', flush = false } = {}) {
  return `<section class="win ${cls}" style="grid-area:${area}" id="win-${id}">
    <header class="titlebar"><span class="dot"></span><span class="t">${esc(title)}</span><span class="sub" id="sub-${id}">${sub}</span><span class="grow"></span><span class="tools" id="tools-${id}">${tools}</span></header>
    <div class="body ${flush ? 'flush' : ''}" id="${id}"></div></section>`;
}

function shell() {
  $('#app').innerHTML = `
    <header class="bar">
      <div class="left">
        <button class="brand og" id="brand" title="maclab menu">${OMARCHY}</button>
        <div class="ws" id="ws"></div>
      </div>
      <div class="clock" id="clock"></div>
      <div class="right" id="status"></div>
    </header>
    <main class="desk" id="desk"></main>
    <nav class="tabbar" id="tabbar"></nav>`;
  $('#brand').onclick = e => mainMenu(e.currentTarget);
  clock();
}

function layout() {
  closeShell();
  painted.clear();
  S.laid = S.view;
  const desk = $('#desk');
  desk.className = 'desk v-' + S.view;
  if (S.view === 'macs') {
    desk.innerHTML = `<div id="alert-slot" style="display:contents"></div>` +
      win('macs', 'Macs', { tools: `<button class="btn sm ghost" onclick="go('#/run')">${ic('plus')} Enroll</button>` }) +
      win('now', 'Now running') + win('pulse', 'Lab pulse') +
      win('recent', 'Recent jobs', { flush: true, tools: `<button class="btn sm ghost" onclick="go('#/jobs')">${ic('history')} All jobs</button>` });
  } else if (S.view === 'jobs') {
    desk.innerHTML = win('list', 'Jobs', { area: 'list', flush: true }) + win('detail', 'Job', { area: 'detail' });
  } else if (S.view === 'run') {
    desk.innerHTML = win('run', 'Boot a kernel', { sub: 'stage · boot once · test · restore' }) +
      win('enroll', 'Enroll a Mac') + win('guide', 'Artifacts & agents');
    runForm(); enrollForm(); guide();
  } else if (S.view === 'builds') {
    desk.innerHTML = win('blist', 'Builds', { area: 'blist', flush: true }) + win('bdetail', 'Build', { area: 'bdetail' });
    buildsLayout();
  } else if (S.view === 'live') {
    desk.innerHTML = win('screen', 'Screen', { area: 'screen' }) +
      win('serial', 'Serial console', { area: 'serial', flush: true }) +
      win('logs', 'Logs', { area: 'logs', flush: true });
    liveLayout();
  }
}

function paint() {
  bar();
  if (S.locked) return;
  const f = { macs: paintMacs, jobs: paintJobs, builds: paintBuilds, run: paintRun, live: paintLive }[S.view];
  f && f();
}

function bar() {
  const ws = $('#ws');
  if (!ws) return;
  put('ws', VIEWS.map(([v], i) => `<button class="${v === S.view ? 'on' : ''}" onclick="go('#/${v}')" title="${v} (${i + 1})"><span class="n">${i + 1}</span><span class="sq"></span></button>`).join('') +
    `<span class="label">${esc(S.view)}</span>`);
  const hands = S.devices.filter(d => d.state === 'needs_hands');
  const ready = S.devices.filter(d => d.state === 'ready').length;
  const running = S.jobs.filter(j => j.state !== 'done').length;
  const building = (S.builds || []).filter(b => b.state === 'running' || b.state === 'queued').length;
  const TAB = { macs: ['laptop', 'Macs', hands.length ? 'bad' : ''], jobs: ['history', 'Jobs', running || ''], builds: ['hammer', 'Builds', building || ''], run: ['rocket', 'Run', ''], live: ['monitor', 'Live', ''] };
  put('tabbar', VIEWS.map(([v]) => {
    const [icon, label, badge] = TAB[v];
    return `<button class="${v === S.view ? 'on' : ''}" onclick="go('#/${v}')"><span class="ti">${I[icon]}${badge === 'bad' ? '<b class="dot"></b>' : badge ? `<b>${badge}</b>` : ''}</span><span>${label}</span></button>`;
  }).join(''));
  const t = activeTheme();
  put('status', [
    hands.length ? `<button class="stat alert" onclick="go('#/macs')" title="${hands.length} Mac(s) need a power cycle">${ic('hand')} <b>${hands.length}</b></button>` : '',
    `<button class="stat" onclick="go('#/macs')" title="Macs ready / enrolled">${ic('laptop')}<b>${ready}/${S.devices.length}</b></button>`,
    `<button class="stat" onclick="go('#/jobs')" title="jobs running or queued">${ic('pulse')}<b>${running}</b></button>`,
    `<button class="stat hide-sm" id="theme-btn" title="theme: ${esc(t?.title || '')}">${ic('palette')}</button>`,
    `<button class="stat" title="${!S.online ? 'labd unreachable' : S.stream === 'up' ? 'connected · live stream' : 'connected · polling'}"><span class="live ${S.online ? '' : 'down'}"></span></button>`,
    lockable() ? `<button class="stat" onclick="lock()" title="${S.viewer && !S.token ? 'view only: unlock with an admin token' : 'lock'}">${ic('lock')}</button>` : '',
  ].join(''));
  const tb = $('#theme-btn');
  if (tb) tb.onclick = e => themeMenu(e.currentTarget);
}

function clock() {
  const d = new Date();
  const c = $('#clock');
  if (c) c.textContent = matchMedia('(max-width: 760px)').matches ? hhmm(d) : `${DAYS[d.getDay()]} ${hhmm(d)}`;
  const lt = $('#lock-time');
  if (lt) { lt.textContent = hhmm(d); $('#lock-date').textContent = d.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' }); }
}
setInterval(clock, 1000);

// ——— view: macs ————————————————————————————————————————————————————————————
function paintMacs() {
  const hands = S.devices.filter(d => d.state === 'needs_hands' && d.action);
  const desk = $('#desk');
  desk.classList.toggle('calm', !hands.length);
  const slot = $('#alert-slot');
  if (slot) {
    const html = hands.map(alertWin).join('');
    if (painted.get(slot) !== html) { painted.set(slot, html); slot.innerHTML = html; }
  }
  put('sub-macs', `${S.devices.length} enrolled`);
  hydrateScreens(put('macs', S.devices.length ? `<div class="macs">${S.devices.map(macCard).join('')}</div>` :
    `<div class="empty"><div class="big">${ic('laptop')}</div><div>No Macs yet.</div><button class="btn primary" onclick="go('#/run')">${ic('plus')} Enroll your first Mac</button></div>`));

  const live = S.jobs.filter(j => j.state !== 'done');
  put('sub-now', live.length ? `${live.length} job${live.length > 1 ? 's' : ''}` : 'idle');
  put('now', live.length ? live.map(j => nowCard(S.jobCache[j.id] || j)).join('') : idle());
  put('pulse', pulse());
  put('recent', jobRows(S.jobs.slice(0, 12)));
}

function idle() {
  const last = S.jobs[0];
  return `<div class="idle"><div class="mark">${logoCache || ''}</div>
    <div class="line">every mac is idle</div>
    ${last ? `<div class="muted">last: ${esc(jobKind(last))} on ${esc(last.spec.device)} · ${esc((OUTCOME[last.outcome] || [])[2] || last.state)} · ${ago(last.updated)}</div>` : ''}
    <div class="row" style="justify-content:center"><button class="btn primary" onclick="go('#/run')">${ic('rocket')} Boot a kernel</button></div></div>`;
}

// Lab pulse: what the last jobs say about the lab, drawn from job history.
function pulse() {
  const done = S.jobs.filter(j => j.state === 'done');
  if (!done.length) return `<div class="empty"><div class="big">${ic('pulse')}</div><div>Charts appear after the first jobs.</div></div>`;
  const day = done.filter(j => since(j.created) < 86400);
  const passed = done.filter(j => j.outcome === 'pass').length;
  const crashes = done.filter(j => ['panicked', 'hung', 'crashed_or_hung'].includes(j.outcome) || j.spec.crash).length;
  const res = j => (S.jobCache[j.id] || j).result || {};
  const boots = done.map(j => res(j).boot_seconds).filter(Boolean);
  const med = boots.length ? [...boots].sort((a, b) => a - b)[Math.floor(boots.length / 2)] : 0;
  const hands = done.filter(j => (res(j).recovery || []).some(r => /human/.test(r))).length;
  const series = done.slice(0, 32).reverse();
  const W = 100 / Math.max(series.length, 12);
  const max = Math.max(60, ...series.map(j => res(j).boot_seconds || 0));
  const bars = series.map((j, i) => {
    const b = res(j).boot_seconds || 0;
    const h = b ? Math.max(4, b / max * 100) : 4;
    return `<a href="#/jobs/${esc(j.id)}" class="barc" title="${esc(jobKind(j))} · ${esc(j.outcome)}${b ? ' · booted in ' + dur(b) : ''}" style="left:${i * W}%;width:calc(${W}% - 3px);height:${h}%;--c:${outcomeColor(j)}"></a>`;
  }).join('');
  return `<div class="stats">
      <div class="stat"><div class="n">${day.length}</div><div class="k">jobs · 24h</div></div>
      <div class="stat"><div class="n ${passed === done.length ? 'ok' : ''}">${Math.round(passed / done.length * 100)}<small>%</small></div><div class="k">pass rate</div></div>
      <div class="stat"><div class="n">${med ? Math.round(med) + '<small>s</small>' : '—'}</div><div class="k">median boot</div></div>
      <div class="stat"><div class="n ${hands ? 'bad' : ''}">${crashes}<small>/${hands}</small></div><div class="k">crashes / needed hands</div></div>
    </div>
    <div class="chart"><div class="lbl">boot time by job · colored by outcome</div><div class="plot">${bars}<span class="axis">${Math.round(max)}s</span></div></div>`;
}

function alertWin(d) {
  const a = d.action;
  return `<section class="win danger alert-win" style="grid-area:alert">
    <header class="titlebar"><span class="dot"></span><span class="t">${esc(a.title)}</span><span class="sub">the lab could not recover it on its own</span></header>
    <div class="alert">
      <div class="glyph">${I.pcycle}</div>
      <div>
        <h2>${esc(d.name)} needs a power cycle</h2>
        <div class="why">${esc(a.why)}.</div>
        <ol>${a.steps.filter(s => !/^That's it/.test(s)).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ol>
        ${a.steps.some(s => /^That's it/.test(s)) ? `<div class="done">${ic('check', 'ok')} ${esc(a.steps.find(s => /^That's it/.test(s)))}</div>` : ''}
        ${a.last_log ? `<div class="last">${esc(a.last_log)}</div>` : ''}
      </div>
      <div class="since">waiting<b>${dur(since(a.since))}</b></div>
    </div></section>`;
}

function macCard(d) {
  const model = d.facts?.dt_model || 'Apple Silicon Mac';
  const fresh = !zero(d.last_seen) && since(d.last_seen) < 20;
  const tier = d.tier ?? 0;
  const kgMatch = d.known_good && d.known_good === d.kernel;
  const job = d.active_job && (S.jobCache[d.active_job] || S.jobs.find(j => j.id === d.active_job));
  const problems = d.facts?.problems || [];
  const warnings = d.facts?.warnings || [];
  const tierColor = tier === 2 ? 'var(--ok)' : tier === 1 ? 'var(--accent)' : 'var(--warn)';
  const thumb = !zero(d.screen_at) ? `<a class="thumb" href="#/live/${esc(d.name)}" title="latest screen capture"><img data-screen="${esc(d.name)}" data-at="${esc(d.screen_at)}" alt=""><span class="age">${ago(d.screen_at)}</span></a>` : '';
  return `<article class="mac ${esc(d.state)} ${thumb ? 'has-thumb' : ''}" style="--c:${d.state === 'needs_hands' ? 'var(--bad)' : d.state === 'recovering' ? 'var(--warn)' : 'var(--info)'}">
    <div class="head">
      <div class="icon">${I[d.model === 'desktop' ? 'desktop' : 'laptop']}</div>
      <div style="min-width:0"><div class="name">${esc(d.name)}</div><div class="model">${esc(model)}${d.label && !model.includes(d.label) && d.label !== model ? ' · ' + esc(d.label) : ''}</div></div>
      ${statePill(d)}
    </div>
    ${thumb}
    <div class="facts">
      <div class="fact"><div class="k">kernel</div><div class="v" title="${esc(d.kernel)}">${esc(d.kernel || '—')}</div></div>
      <div class="fact"><div class="k">known-good</div><div class="v">${d.known_good ? (kgMatch ? `<span class="good">${ic('check')} running it</span>` : esc(d.known_good)) : '<span class="muted">no baseline yet</span>'}</div></div>
      <div class="fact"><div class="k">heartbeat</div><div class="v"><span class="heart ${fresh ? 'beat' : 'stale'}"></span>${ago(d.last_seen)}</div></div>
      <div class="fact"><div class="k">uptime · systemd</div><div class="v">${d.health?.uptime ? dur(d.health.uptime) : '—'} · ${esc(d.health?.system_state || '—')}</div></div>
    </div>
    <div class="tier" style="--c:${tierColor}">
      <span class="segs">${[0, 1, 2].map(i => `<i class="${i <= tier ? 'on' : ''}"></i>`).join('')}</span>
      <span class="what">tier ${tier} · ${TIER_NAMES.slice(0, tier + 1).join(' + ')}${tier < 2 ? ` <span class="muted">· no ${TIER_NAMES[tier + 1]}</span>` : ''}</span>
    </div>
    <div class="ladder">${ladder(d)}</div>
    ${history(d)}
    ${job ? `<div class="job" onclick="go('#/jobs/${esc(job.id)}')">${ic('pulse', 'strong')}<span class="strong">${esc(jobKind(job))}</span><span class="dim">${esc(job.state)}</span><span class="grow"></span><span class="muted">${esc(job.id)}</span>${ic('chev', 'muted')}</div>` : ''}
    ${problems.length ? `<div class="problems">${ic('alert')} ${problems.map(esc).join(' · ')}</div>` : ''}
    ${warnings.length ? `<div class="problems warnings">${ic('alert')} ${warnings.map(esc).join(' · ')}</div>` : ''}
    <div class="actions">
      ${d.known_good ? `<button class="btn primary sm" onclick="go('#/run?device=${esc(d.name)}')">${ic('play')} Boot a kernel</button>`
        : `<button class="btn primary sm" onclick="confirmJob('${esc(d.name)}','baseline')">${ic('shield')} Run baseline</button>`}
      ${d.known_good ? `<button class="btn sm" onclick="confirmJob('${esc(d.name)}','crash')">${ic('flash')} Crash test</button>` : ''}
      <button class="btn sm" onclick="go('#/live/${esc(d.name)}')">${ic('monitor')} Live</button>
      <button class="btn sm ghost danger" onclick="confirmReset('${esc(d.name)}')">${ic('restart')} Reset</button>
    </div>
  </article>`;
}

function ladder(d) {
  const rungs = [
    ['panic reboot', (d.facts?.panic_timeout || 0) > 0, 'kernel.panic set'],
    ['watchdog', !!d.facts?.watchdog_armed, 'apple_wdt via systemd'],
    ['hard reset', !!d.oob, d.oob ? 'out-of-band controller' : 'attach a controller Mac'],
    ['human', true, 'one clear instruction'],
  ];
  return rungs.map(([n, on, why], i) => `<span class="rung ${on ? 'on' : ''}" title="${esc(why)}"><span class="ix">${i + 1}</span>${esc(n)}</span>${i < 3 ? `<span class="arrow">${I.chev}</span>` : ''}`).join('');
}

function history(d) {
  const js = S.jobs.filter(j => j.spec.device === d.name).slice(0, 28).reverse();
  if (!js.length) return '';
  return `<div class="hist"><span class="k">runs</span>${js.map(j => `<a href="#/jobs/${esc(j.id)}" class="${j.state !== 'done' ? 'live' : ''}" style="--c:${outcomeColor(j)}" title="${esc(jobKind(j))} · ${esc(j.state === 'done' ? j.outcome : j.state)} · ${ago(j.created)}"></a>`).join('')}</div>`;
}

// ——— pipeline —————————————————————————————————————————————————————————————
function pipeline(j) {
  const crash = !!j.spec?.crash;
  const built = !!(j.spec?.source || buildIdOf(j));
  const off = built ? 1 : 0;
  const names = (built ? ['Build'] : []).concat(crash ? ['Stage', 'Boot', 'Panic & recover', 'Restore'] : ['Stage', 'Boot', 'Test', 'Collect', 'Restore']);
  let at = { queued: -1, staging: 0, booting: 1, testing: 2, collecting: 3, restoring: 4, done: 5 }[j.state] ?? -1;
  if (crash && at >= 3) at = at === 5 ? 4 : 3;
  if (at >= 0) at += off;
  if (j.state === 'building') at = 0;
  const ev = j.events || [];
  const find = re => { const e = ev.find(e => re.test(e.msg)); return e ? new Date(e.time) : null; };
  const findLast = re => { const e = [...ev].reverse().find(e => re.test(e.msg)); return e ? new Date(e.time) : null; };
  const marks = (built ? [find(/^resolving|^building |^reusing/)] : []).concat(crash
    ? [find(/^staging/), find(/^one-shot armed/), find(/^triggering/), find(/^done:/), find(/^done:/)]
    : [find(/^staging/), find(/^one-shot armed/), find(/^booted |^came back on/), findLast(/^test \S+: (pass|fail|error|timed)/), find(/^rebooting back|^restore/), find(/^done:/)]);
  let fail = -1;
  if (j.state === 'done' && j.outcome !== 'pass') {
    const booted = j.result?.booted;
    fail = { stage_failed: 0, tests_failed: 2, booted_unhealthy: 3, panicked: booted ? 2 : 1, hung: booted ? 2 : 1, crashed_or_hung: 2, boot_failed: 1 }[j.outcome] ?? (booted ? names.length - 1 - off : 1);
    fail += off;
    if (j.outcome === 'build_failed') fail = 0;
    if (j.outcome === 'canceled') fail = -1;
  }
  return `<div class="pipe" style="grid-template-columns:repeat(${names.length},1fr)">${names.map((n, i) => {
    let cls = '', s = 'waiting';
    const start = marks[i], end = marks.slice(i + 1).find(Boolean);
    if (i === fail) { cls = 'fail'; s = (OUTCOME[j.outcome] || [])[2] || 'failed'; }
    else if (j.state === 'done' ? (fail < 0 ? j.outcome !== 'canceled' || start : i < fail) : i < at) { cls = 'done'; s = start && end && end > start ? dur((end - start) / 1000) : `${I.check} done`; }
    else if (i === at) {
      cls = 'now'; s = start ? dur(since(start)) : 'running';
      const b = built && i === 0 && S.buildCache[buildIdOf(j)];
      if (b) s = `${esc(b.stage || b.state)}${b.stage === 'build' && b.progress ? ' · ' + Math.round(b.progress * 100) + '%' : ''}`;
    }
    else if (j.state === 'done') { s = '—'; }
    return `<div class="stage ${cls}"><div class="n">${n}</div><div class="s">${s}</div></div>`;
  }).join('')}</div>`;
}

function eventsHtml(ev, n) {
  const list = n ? ev.slice(-n) : ev;
  return `<div class="events">${list.map(e => {
    const cls = /^recovery:|^lost the Mac|waiting for/.test(e.msg) ? 'rec' : /^done:/.test(e.msg) ? 'fin' : /fail|panick|hung|error/i.test(e.msg) ? 'bad' : '';
    return `<div class="e ${cls}"><span class="t">${hms(new Date(e.time))}</span><span class="m">${esc(e.msg)}</span></div>`;
  }).join('')}</div>`;
}

function nowCard(j) {
  return `<div class="now-card">
    <div class="now-head"><span class="what">${esc(jobKind(j))}</span><span class="dim">on ${esc(j.spec.device)}</span>${outcomePill(j)}
      <span class="clock">${dur(since(j.created))}</span></div>
    ${pipeline(j)}
    ${j.state === 'building' && S.buildCache[buildIdOf(j)] ? `<div class="row" style="gap:12px">${buildBar(S.buildCache[buildIdOf(j)])}<span class="dim nowrap">${esc(etaText(S.buildCache[buildIdOf(j)]))}</span></div>` : ''}
    ${eventsHtml(j.events || [], 7)}
    <div class="row"><button class="btn sm" onclick="go('#/jobs/${esc(j.id)}')">${ic('eye')} Open</button><button class="btn sm ghost danger" onclick="cancelJob('${esc(j.id)}')">${ic('stop')} Cancel</button></div>
  </div>`;
}

function jobRows(jobs, sel) {
  if (!jobs.length) return `<div class="empty"><div class="big">${ic('history')}</div><div>No jobs yet.</div></div>`;
  return `<div class="jobs">${jobs.map(j => `
    <div class="jrow ${j.id === sel ? 'sel' : ''}" onclick="go('#/jobs/${esc(j.id)}')" style="--c:${outcomeColor(j)}">
      <span class="b ${j.state !== 'done' ? 'live' : ''}"></span>
      <div class="top"><span class="kind">${esc(jobKind(j))}</span><span class="dev">${esc(j.spec.device)}</span></div>
      <span class="when">${ago(j.created)}</span>
      <div class="sum">${esc(j.state === 'done' ? j.summary : (j.events?.at(-1)?.msg || j.state))}</div>
    </div>`).join('')}</div>`;
}

// ——— view: jobs —————————————————————————————————————————————————————————————
function paintJobs() {
  put('sub-list', `${S.jobs.length} recent`);
  put('list', jobRows(S.jobs, S.jobId));
  const j = S.jobId && S.jobCache[S.jobId];
  if (!S.jobId) { put('detail', `<div class="empty"><div class="big">${ic('list')}</div><div>Pick a job.</div></div>`); return; }
  if (!j) { put('detail', `<div class="empty muted">loading ${esc(S.jobId)}…</div>`); return; }
  put('sub-detail', `${esc(j.id)} · ${esc(j.spec.device)} · ${new Date(j.created).toLocaleString()}`);
  $('#desk')?.classList.toggle('sel', !!S.params.arg);
  put('tools-detail', `<button class="btn sm ghost mob-back" onclick="go('#/jobs')">${I.chev} Jobs</button>` + (j.state !== 'done' ? `<button class="btn sm ghost danger" onclick="cancelJob('${esc(j.id)}')">${ic('stop')} Cancel</button>` :
    `<button class="btn sm ghost" onclick="retryJob('${esc(j.id)}')">${ic('restart')} Retry</button>`));
  put('detail', jobDetail(j));
  bindDetail(j);
}

function jobFiles(j) {
  const files = [...(j.result?.logs || [])];
  for (const t of j.result?.tests || []) for (const f of t.files || []) if (!files.includes(f)) files.push(f);
  return files;
}

function jobDetail(j) {
  const r = j.result || {};
  const [cls, icon, label] = j.state === 'done' ? (OUTCOME[j.outcome] || ['c-dim', 'dots', j.outcome]) : ['c-info', 'pulse', 'Running'];
  const files = jobFiles(j);
  const shots = files.filter(f => /\.(png|jpe?g)$/i.test(f));
  const texts = files.filter(f => !/\.(png|jpe?g)$/i.test(f));
  const tabs = [['overview', 'Overview'], ['logs', 'Logs', texts.length], ['shots', 'Screenshots', shots.length]]
    .filter(t => t[2] === undefined || t[2] > 0 || t[0] === 'logs');
  if (!tabs.some(t => t[0] === S.detailTab)) S.detailTab = 'overview';
  let body = '';
  if (S.detailTab === 'overview') body = `<div class="split"><div>${overview(j)}</div><aside><div class="h">Timeline</div>${eventsHtml(j.events || [])}</aside></div>`;
  else if (S.detailTab === 'logs') body = logsPane(j, texts);
  else if (S.detailTab === 'shots') body = `<div class="shots">${shots.map(f => `<figure class="shot" data-shot="${esc(f)}"><img data-src="${esc(f)}" alt=""><figcaption class="cap">${ic('image')} ${esc(f)}</figcaption></figure>`).join('')}</div>`;
  else if (S.detailTab === 'events') body = eventsHtml(j.events || []);
  return `
    <div class="verdict" style="--c:${outcomeColor(j)}">
      <div class="big">${I[icon] || ''}</div>
      <div style="min-width:0"><div class="o">${esc(label)}<span class="kind">${esc(jobKind(j))}</span></div>
        <div class="s">${esc(j.state === 'done' ? j.summary : (j.events?.at(-1)?.msg || ''))}</div></div>
      <div class="muted" style="text-align:right;white-space:nowrap">${j.state === 'done' ? dur((new Date(j.updated) - new Date(j.created)) / 1000) : dur(since(j.created))}<br>${r.booted ? `booted in ${dur(r.boot_seconds)}` : ''}</div>
    </div>
    ${pipeline(j)}
    ${jobBuild(j)}
    <nav class="tabs">${tabs.map(([k, l, n]) => `<button class="${k === S.detailTab ? 'on' : ''}" data-tab="${k}">${l}${n ? `<span class="cnt">${n}</span>` : ''}</button>`).join('')}</nav>
    ${body}`;
}

function jobBuild(j) {
  const bid = buildIdOf(j);
  const b = bid && S.buildCache[bid];
  if (!j.spec?.source && !b) return '';
  if (!b) return j.state === 'building' ? `<div class="bcard" style="margin-top:14px"><div class="muted">resolving ${esc(j.spec.source)}…</div></div>` : '';
  if (j.state === 'building' || j.outcome === 'build_failed') return `<div style="margin-top:14px">${buildCard(b, { log: 14 })}</div>`;
  return `<div class="bline">${ic('hammer')} built <a href="#/builds/${esc(b.id)}">${esc(b.release || b.id)}</a> from ${esc(repoName(b.source))} <code>${esc(shortSha(b.source?.sha))}</code>${b.seconds ? ` in ${dur(b.seconds)}` : ''}${b.reused ? ' · reused' : ''}</div>`;
}

// omarchy-m-test: the hardware checks it ran, what changed from the known-good kernel, and where it's published.
function omtSection(j) {
  const o = j.result?.omt;
  if (!o) return '';
  const item = (c, color, tag) => `<li style="--c:${color}"><span class="k">${tag}</span><b>${esc(c.id)}</b>${c.evidence ? ` · ${esc(c.evidence)}` : ''}</li>`;
  const changed = [...(o.regressions || []).map(c => item(c, 'var(--bad)', 'regressed')), ...(o.fixed || []).map(c => item(c, 'var(--ok)', 'fixed')),
    ...(o.allowed || []).map(c => item(c, 'var(--faint)', 'allowed')),
    ...(o.lab_boot || []).map(c => item({ ...c, evidence: 'fails for any kernel that is not an installed package' }, 'var(--faint)', 'lab boot'))];
  const canPublish = j.state === 'done' && o.known_good && !o.published;
  return `<div class="section"><div class="h">omarchy-m-test <span class="muted" style="font-weight:400">${esc(o.tool)} · ${o.pass} pass · ${o.fail} fail · ${o.skip} skipped</span></div>
    <div class="muted" style="margin:-2px 0 8px">compared with ${esc(o.compared_to || 'nothing')}</div>
    ${changed.length ? `<ul class="lines">${changed.join('')}</ul>` : `<ul class="lines"><li style="--c:var(--ok)">${o.known_good ? 'known-good run: the reference for this Mac' : 'nothing changed from the known-good kernel'}</li></ul>`}
    ${o.fails?.length ? `<details class="test" style="margin-top:8px"><summary><span class="nm">All ${o.fails.length} failing checks</span><span class="tm">on this Mac's setup, not only this kernel</span></summary>
      <ul class="lines" style="margin-top:6px">${o.fails.map(c => item(c, 'var(--warn)', c.outcome || 'fail')).join('')}</ul></details>` : ''}
    <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap">
      ${o.published ? `<a class="btn sm" href="${esc(o.published)}" target="_blank" rel="noopener">${ic('cloud')} Published on omarchy-m-testing.org</a>`
        : o.publish_note ? `<span class="muted">not published: ${esc(o.publish_note)}</span>` : ''}
      ${canPublish ? `<button class="btn sm primary" onclick="publishOMT('${esc(j.id)}')">${ic('upload')} Publish</button>` : ''}
    </div></div>`;
}

async function publishOMT(id) {
  try { const r = await post(`/api/jobs/${enc(id)}/publish`); toast('Published', r.report_url); tick(); }
  catch (e) { toast('Not published', e.message, true); }
}

function overview(j) {
  const r = j.result || {};
  const s = j.spec || {};
  const serious = (r.kernel_events || []).filter(e => e.kind !== 'warning');
  return `
    ${r.tests?.length ? `<div class="section"><div class="h">Tests</div><div class="tests">${r.tests.map(t => `
      <details class="test"><summary><span class="st ${t.passed ? 'ok' : 'bad'}">${I[t.passed ? 'check' : t.timed_out ? 'sand' : 'close']}</span>
        <span class="nm">${esc(t.name)}</span><span class="tm">${t.passed ? `passed · ${dur(t.seconds)}` : t.timed_out ? 'timed out' : t.error ? esc(t.error) : `exit ${t.exit_code}`}</span></summary>
        ${t.tail ? `<pre class="term plain">${t.tail.split('\n').map(l => `<span class="l k-${lineKind(l)}">${esc(l)}</span>`).join('')}</pre>` : ''}
      </details>`).join('')}</div></div>` : ''}
    ${r.recovery?.length ? `<div class="section"><div class="h">Recovery</div><ul class="lines">${r.recovery.map(x => `<li style="--c:var(--warn)">${esc(x)}</li>`).join('')}</ul></div>`
      : j.spec?.crash && j.outcome === 'pass' ? `<div class="section"><div class="h">Recovery</div><ul class="lines"><li style="--c:var(--ok)"><span class="k">self</span>panic=10 rebooted the Mac and the one-shot fell back to its known-good kernel. No reset or human needed.</li></ul></div>` : ''}
    ${serious.length ? `<div class="section"><div class="h">Kernel events</div><ul class="lines">${serious.map(e => `<li style="--c:var(--bad)"><span class="k">${esc(e.kind)} · ${esc(e.source)}</span>${esc(e.line)}</li>`).join('')}</ul></div>` : ''}
    ${omtSection(j)}
    ${r.new_error_lines?.length ? `<div class="section"><div class="h">New kernel warnings vs baseline <span class="muted" style="font-weight:400">${r.new_error_lines.length}</span></div>
      <ul class="lines">${r.new_error_lines.slice(0, 60).map(l => `<li style="--c:var(--warn)">${esc(l)}</li>`).join('')}</ul></div>` : ''}
    ${r.booted ? `<div class="section"><div class="h">Boot</div><dl class="kv"><dt>kernel</dt><dd>${esc(r.boot_kernel)}</dd><dt>up in</dt><dd>${dur(r.boot_seconds)}</dd>${r.logs?.length ? `<dt>logs</dt><dd>${r.logs.length} files</dd>` : ''}</dl></div>` : ''}
    <div class="section"><div class="h">Spec</div><dl class="kv">
      <dt>device</dt><dd>${esc(s.device)}</dd>
      <dt>kernel</dt><dd>${s.source ? `built from <a href="${esc(s.source)}" target="_blank" rel="noopener">${esc(repoName({ input: s.source }))}</a>${s.kernel ? ` · <code>${esc(s.kernel.slice(0, 12))}…</code>` : ''}` : s.kernel ? `<code>${esc(s.kernel.slice(0, 16))}…</code> ${esc(r.boot_kernel || '')}` : 'current (known-good)'}</dd>
      ${s.cmdline ? `<dt>cmdline</dt><dd class="wrap"><code>${esc(s.cmdline)}</code></dd>` : ''}
      <dt>tests</dt><dd>${['boot-health', ...(s.tests || []).map(t => t.name + (t.gui ? ' (gui)' : ''))].filter((v, i, a) => a.indexOf(v) === i).map(esc).join(', ')}</dd>
      ${s.boot_timeout_sec ? `<dt>boot timeout</dt><dd>${s.boot_timeout_sec}s</dd>` : ''}
      ${s.holder ? `<dt>by</dt><dd>${esc(s.holder)}</dd>` : ''}
      ${r.fell_back ? `<dt>fell back</dt><dd class="warn">yes: the Mac came back on its known-good kernel</dd>` : ''}
    </dl></div>`;
}

function logsPane(j, files) {
  if (!files.length) return `<div class="empty"><div class="big">${ic('file')}</div><div>No logs yet.</div></div>`;
  if (!S.logFile || !files.includes(S.logFile)) S.logFile = files.includes('serial.log') ? 'serial.log' : files.find(f => /kernel\.txt$/.test(f)) || files[0];
  const groups = {};
  for (const f of files) { const g = f.includes('/') ? f.split('/')[0] : 'console'; (groups[g] ||= []).push(f); }
  let text = S.logText;
  let view;
  if (text === null) view = `<div class="empty muted">loading…</div>`;
  else {
    let lines = text.replace(/\n$/, '').split('\n');
    const total = lines.length;
    if (S.logFilter) { const q = S.logFilter.toLowerCase(); lines = lines.filter(l => l.toLowerCase().includes(q)); }
    const cap = 5000;
    const cut = lines.length > cap ? lines.length - cap : 0;
    lines = lines.slice(cut);
    view = `<div class="bar2"><span class="dim">${esc(S.logFile)}</span><span class="muted">${S.logFilter ? `${lines.length + cut} of ${total} lines` : `${total} lines`}${cut ? ` · last ${cap}` : ''}</span><span class="grow"></span>
      <input type="text" id="logfilter" placeholder="filter" value="${esc(S.logFilter)}"></div>
      <pre class="term">${lines.map(l => `<span class="l k-${lineKind(l)}">${esc(l) || ' '}</span>`).join('')}</pre>`;
  }
  return `<div class="logs"><div class="files">${Object.entries(groups).map(([g, fs]) => `<div class="grp">${esc(g)}</div>` +
    fs.map(f => `<button class="${f === S.logFile ? 'on' : ''}" data-file="${esc(f)}" title="${esc(f)}">${esc(f.includes('/') ? f.slice(f.indexOf('/') + 1) : f)}</button>`).join('')).join('')}</div>
    <div class="view">${view}</div></div>`;
}

function bindDetail(j) {
  $$('#detail [data-tab]').forEach(b => b.onclick = () => { S.detailTab = b.dataset.tab; paintJobs(); if (S.detailTab === 'logs') loadLog(j); });
  $$('#detail [data-file]').forEach(b => b.onclick = () => { S.logFile = b.dataset.file; S.logText = null; S.logFilter = ''; paintJobs(); loadLog(j); });
  const f = $('#logfilter');
  if (f) f.oninput = () => { S.logFilter = f.value; const pos = f.selectionStart; paintJobs(); const g = $('#logfilter'); g.focus(); g.setSelectionRange(pos, pos); };
  $$('#detail img[data-src]').forEach(async img => { img.src = await shotURL(j.id, img.dataset.src); });
  $$('#detail [data-shot]').forEach(s => s.onclick = async () => viewer(await shotURL(j.id, s.dataset.shot)));
  if (S.detailTab === 'logs' && S.logText === null) loadLog(j);
}

async function loadLog(j) {
  const want = S.logFile;
  if (!want) return;
  try {
    const t = await api(`/api/jobs/${encodeURIComponent(j.id)}/files/${want.split('/').map(encodeURIComponent).join('/')}`);
    if (S.logFile === want) { S.logText = typeof t === 'string' ? t : JSON.stringify(t, null, 2); paintJobs(); }
  } catch (e) { if (S.logFile === want) { S.logText = `[could not load: ${e.message}]`; paintJobs(); } }
}

async function shotURL(id, f) {
  const k = id + '/' + f;
  if (!S.shots[k]) {
    const r = await fetch(`/api/jobs/${encodeURIComponent(id)}/files/${f.split('/').map(encodeURIComponent).join('/')}`, { headers: authH() });
    S.shots[k] = URL.createObjectURL(await r.blob());
  }
  return S.shots[k];
}

// ——— view: run ———————————————————————————————————————————————————————————————
const BUILTINS = [
  ['boot-health', 'systemd state, failed units, kernel errors, boot time', false, true],
  ['gui-smoke', 'Hyprland answers, a monitor is up, screenshot', true, false],
  ['gui-terminal', 'open a terminal, type into it, screenshot', true, false],
  ['suspend-devices', 'suspend and resume the devices (pm_test), network back', false, false],
];

function paintRun() {
  const sel = $('#rf-device');
  if (!sel) return;
  const opts = S.devices.map(d => `<option value="${esc(d.name)}" ${d.state === 'new' ? 'data-new="1"' : ''}>${esc(d.name)} — ${esc(STATE[d.state]?.[1] || d.state)}</option>`).join('');
  if (sel.dataset.opts !== opts) {
    const cur = sel.value || S.params.q?.device || '';
    sel.innerHTML = opts; sel.dataset.opts = opts;
    if (cur && S.devices.some(d => d.name === cur)) sel.value = cur;
  }
  const d = S.devices.find(x => x.name === sel.value);
  put('rf-devinfo', d ? `${statePill(d)} <span class="muted">${esc(d.facts?.dt_model || '')} · tier ${d.tier} · known-good ${esc(d.known_good || 'none')}</span>` : '');
  const up = S.upload;
  put('rf-upinfo', up ? `<div class="row"><span class="strong">${ic('pkg')} ${esc(up.name)}</span><span class="grow"></span><span class="${up.err ? 'bad' : up.sha ? 'ok' : 'dim'}">${up.err ? esc(up.err) : up.sha ? `${I.check} ${up.sha.slice(0, 12)}` : `${up.pct}%`}</span></div><div class="bar-progress"><i style="width:${up.sha ? 100 : up.pct}%"></i></div>` : '');
}

function runForm() {
  put('run', `
    <div class="field"><label for="rf-device">Mac</label><select id="rf-device"></select><div id="rf-devinfo" class="row"></div></div>
    <div class="field"><label>Kernel</label>
      <div class="seg" id="rf-src"><button data-v="upload" class="on">${ic('upload')} Upload artifact</button><button data-v="sha">${ic('pkg')} Artifact sha256</button><button data-v="current">${ic('restart')} Current kernel</button><button data-v="url">${ic('hammer')} Build from GitHub</button></div>
      <div id="rf-src-upload"><label class="drop" id="rf-drop"><input type="file" id="rf-file" hidden>
        <span class="big">${ic('cloud')}</span><span>Drop a kernel tarball, or click to choose</span>
        <span class="muted">usr/lib/modules/&lt;release&gt;/{vmlinuz,…} — <code>lab pack</code> makes one; a linux-*.pkg.tar.zst works as-is</span></label>
        <div id="rf-upinfo" style="margin-top:10px;display:grid;gap:8px"></div></div>
      <div id="rf-src-sha" hidden><input type="text" id="rf-sha" placeholder="sha256 of an uploaded artifact"></div>
      <div id="rf-src-url" hidden><input type="text" id="rf-url" placeholder="https://github.com/owner/repo/tree/branch · /commit/sha · /pull/N" spellcheck="false">
        <div class="hint">The lab builds it on the builder host with this Mac's own running config, then boots it. Identical builds are reused.</div></div>
      <div id="rf-src-current" hidden class="hint">Reboots once into a lab entry on the known-good kernel: useful for testing a cmdline, or the lab itself.</div>
    </div>
    <div class="field"><label for="rf-cmdline">Extra kernel arguments</label><input type="text" id="rf-cmdline" placeholder="e.g. nvme_apple.flush_interval=0 dyndbg=…">
      <div class="hint">Appended to the known-good cmdline. The lab adds <code>loglevel=7 panic=10</code> and removes <code>quiet splash</code>.</div></div>
    <div class="field"><label>Tests</label><div class="checks">${BUILTINS.map(([n, desc, gui, locked]) => `
      <label class="check ${locked ? 'locked' : ''}"><input type="checkbox" name="t" value="${n}" ${locked ? 'checked disabled' : ''} data-gui="${gui ? 1 : ''}"><span class="box">${I.check}</span>
        <span class="name">${n}${gui ? ` <span class="pill c-info" style="margin-left:6px">gui</span>` : ''}${locked ? ` <span class="muted">always</span>` : ''}</span><span class="desc">${desc}</span></label>`).join('')}
      <label class="check"><input type="checkbox" id="rf-scripts-on"><span class="box">${I.check}</span><span class="name">Your own scripts</span>
        <span class="desc">shell scripts; write artifacts to <code>$MACLAB_OUT</code> <input type="file" id="rf-scripts" multiple accept=".sh,text/x-shellscript" style="margin-top:8px;display:block"></span></label>
    </div></div>
    <div class="row">
      <div class="field" style="width:170px;margin:0"><label for="rf-timeout">Boot timeout</label><input type="number" id="rf-timeout" value="240" min="60" max="1800"></div>
      <label class="check" style="flex:1;margin-top:18px"><input type="checkbox" id="rf-scripts-gui"><span class="box">${I.check}</span><span class="name">Run my scripts in the GUI session</span><span class="desc">as the Mac's GUI user, inside Hyprland</span></label>
    </div>
    <hr class="sep">
    <div class="row end"><span class="muted grow" id="rf-msg"></span>
      <button class="btn" id="rf-crash">${ic('flash')} Crash test</button>
      <button class="btn primary" id="rf-go">${ic('rocket')} Boot it</button></div>`);
  let src = 'upload';
  $$('#rf-src button').forEach(b => b.onclick = e => {
    e.preventDefault(); src = b.dataset.v;
    $$('#rf-src button').forEach(x => x.classList.toggle('on', x === b));
    ['upload', 'sha', 'current', 'url'].forEach(v => $('#rf-src-' + v).hidden = v !== src);
  });
  const drop = $('#rf-drop');
  ['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => e.dataTransfer.files[0] && uploadKernel(e.dataTransfer.files[0]));
  $('#rf-file').onchange = e => e.target.files[0] && uploadKernel(e.target.files[0]);
  $('#rf-device').onchange = paintRun;
  $('#rf-crash').onclick = () => confirmJob($('#rf-device').value, 'crash');
  $('#rf-go').onclick = async () => {
    const btn = $('#rf-go'), msg = $('#rf-msg');
    const spec = { device: $('#rf-device').value, cmdline: $('#rf-cmdline').value.trim(), boot_timeout_sec: +$('#rf-timeout').value || 0, holder: 'web', tests: [] };
    if (src === 'upload') {
      if (!S.upload?.sha) { msg.textContent = S.upload ? 'still uploading…' : 'choose a kernel artifact first'; return; }
      spec.kernel = S.upload.sha;
    } else if (src === 'url') {
      spec.source = $('#rf-url').value.trim();
      if (!/^(https?:\/\/|git@)/.test(spec.source)) { msg.textContent = 'paste a GitHub URL (repo, branch, commit or PR)'; return; }
    } else if (src === 'sha') {
      spec.kernel = $('#rf-sha').value.trim();
      if (!/^[0-9a-f]{64}$/.test(spec.kernel)) { msg.textContent = 'that is not a sha256'; return; }
    }
    for (const c of $$('#run input[name=t]:checked:not([disabled])')) spec.tests.push({ name: c.value, builtin: c.value, gui: !!c.dataset.gui });
    btn.disabled = true;
    try {
      if ($('#rf-scripts-on').checked) {
        for (const f of $('#rf-scripts').files) {
          msg.textContent = `uploading ${f.name}…`;
          const sha = await uploadBlob(f);
          spec.tests.push({ name: f.name.replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '-'), script: sha, gui: $('#rf-scripts-gui').checked });
        }
      }
      const j = await post('/api/jobs', spec);
      toast('Job queued', `${jobKind(j)} on ${j.spec.device}`);
      S.upload = null;
      go('#/jobs/' + j.id);
    } catch (e) { msg.textContent = ''; toast('Could not queue the job', e.message, true); }
    finally { btn.disabled = false; }
  };
}

function uploadBlob(file, onpct) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('POST', '/api/artifacts');
    if (S.token) x.setRequestHeader('Authorization', 'Bearer ' + S.token);
    x.upload.onprogress = e => e.lengthComputable && onpct && onpct(Math.floor(e.loaded / e.total * 100));
    x.onload = () => x.status === 200 ? resolve(JSON.parse(x.responseText).sha256) : reject(new Error(x.responseText || x.statusText));
    x.onerror = () => reject(new Error('upload failed'));
    x.send(file);
  });
}

async function uploadKernel(file) {
  S.upload = { name: file.name, pct: 0 };
  paintRun();
  try {
    const sha = await uploadBlob(file, p => { if (S.upload?.name === file.name) { S.upload.pct = p; paintRun(); } });
    if (S.upload?.name === file.name) { S.upload.sha = sha; paintRun(); }
  } catch (e) { if (S.upload) { S.upload.err = e.message; paintRun(); } }
}

function enrollForm() {
  put('enroll', `
    <div class="field"><label for="en-name">Name</label><input type="text" id="en-name" placeholder="m2pro" autocomplete="off"></div>
    <div class="field"><label for="en-label">Where is it?</label><input type="text" id="en-label" placeholder="MacBook Pro 14, shelf by the window"><div class="hint">Goes into the power-cycle instructions, so a person can find it.</div></div>
    <div class="row"><div class="seg" id="en-model"><button data-v="laptop" class="on">${ic('laptop')} Laptop</button><button data-v="desktop">${ic('desktop')} Desktop</button></div>
      <span class="grow"></span><button class="btn primary" id="en-go">${ic('plus')} Create token</button></div>
    <div id="en-out" style="margin-top:16px"></div>`);
  let model = 'laptop';
  $$('#en-model button').forEach(b => b.onclick = () => { model = b.dataset.v; $$('#en-model button').forEach(x => x.classList.toggle('on', x === b)); });
  $('#en-go').onclick = async () => {
    try {
      const name = $('#en-name').value.trim();
      const t = await post('/api/enroll-tokens', { name, label: $('#en-label').value.trim(), model });
      const cmd = `sudo ./lab-agent setup --server ${location.origin} --token ${t.token} --gui-user $USER`;
      $('#en-out').innerHTML = `<div class="lbl" style="margin-bottom:6px">On ${esc(name)}, with lab-agent copied over</div>
        <pre class="term plain" style="white-space:pre-wrap;word-break:break-all;border-radius:6px;border:1px solid var(--line)"><span class="l">${esc(cmd)}</span></pre>
        <div class="row" style="margin-top:8px"><button class="btn sm" id="en-copy">${ic('copy')} Copy</button><span class="muted">one use · expires ${new Date(t.expires).toLocaleString()}</span></div>
        <div class="hint" style="margin-top:10px">Then run its baseline from the Macs view: it proves the one-shot boot before any test kernel runs.</div>`;
      $('#en-copy').onclick = () => copy(cmd);
    } catch (e) { toast('Could not enroll', e.message, true); }
  };
}

function guide() {
  put('guide', `
    <div class="h">Kernel artifacts</div>
    <p class="dim" style="margin-top:0">A tarball with exactly one <code>usr/lib/modules/&lt;release&gt;/</code> holding the modules and <code>vmlinuz</code>. Give every build a unique <code>LOCALVERSION</code>: the lab refuses to overwrite a kernel it didn't install.</p>
    <pre class="term plain" style="border-radius:6px;border:1px solid var(--line)"><span class="l"><span class="ts">$</span> lab pack --build ~/aurora-build/…/build/base</span><span class="l"><span class="ts">$</span> lab run m1air --kernel kernel-7.2.0-lab1.tar.zst --gui-test gui-smoke</span></pre>
    <div class="h" style="margin-top:22px">${ic('robot')} Agents</div>
    <p class="dim" style="margin-top:0">Claude Code and other MCP clients drive the same lab:</p>
    <pre class="term plain" style="border-radius:6px;border:1px solid var(--line)"><span class="l"><span class="ts">$</span> claude mcp add maclab -- lab mcp</span></pre>
    <p class="muted">lab_run · lab_wait · lab_job · lab_log · lab_screenshot · lab_serial · lab_reset …</p>`);
}

// ——— view: builds ——————————————————————————————————————————————————————————
// Kernels built from a GitHub URL on a builder host, with each Mac's own config.
S.builds = [];
S.buildCache = {};   // id -> build
S.blog = {};         // id -> {lines: [], loaded, loading}
S.builders = [];

// Stages per build kind, with each stage's share of the overall bar; "build" is the one measured by objects.
const BSTAGES = {
  kernel: { list: [['fetch', 'Fetch'], ['checkout', 'Checkout'], ['configure', 'Configure'], ['build', 'Compile'], ['package', 'Package'], ['upload', 'Upload']],
    at: { starting: -1, fetch: 0, checkout: 1, configure: 2, build: 3, package: 4, tidy: 4, upload: 5, done: 6 }, w: [4, 3, 6, 72, 10, 5] },
  package: { list: [['recipe', 'Recipe'], ['checksums', 'Sources'], ['build', 'makepkg'], ['package', 'Packages'], ['upload', 'Upload']],
    at: { starting: -1, recipe: 0, checksums: 1, build: 2, package: 3, tidy: 3, upload: 4, done: 5 }, w: [2, 4, 84, 3, 7] },
};
const stagesOf = b => BSTAGES[b.kind === 'package' ? 'package' : 'kernel'];
const baseName = p => (p || '').replace(/\/+$/, '').split('/').pop();
// What a build is, the way people say it: "owner/repo@branch", or "linux-aurora packages".
function buildName(b) {
  if (b.kind !== 'package') return repoName(b.source);
  return `${baseName(b.recipe_dir) || 'recipe'} packages${b.pkgrel ? ` -${b.pkgrel}` : ''}`;
}
function buildSub(b) {
  if (b.kind !== 'package') return shortSha(b.source?.sha);
  return b.source?.sha ? `at ${repoName(b.source)} ${shortSha(b.source.sha)}` : 'recipe as written';
}
const BUILD_STATE = { queued: ['c-dim live', 'Queued'], running: ['c-info live', 'Building'], done: ['c-ok', 'Built'], failed: ['c-bad', 'Failed'], canceled: ['c-dim', 'Canceled'] };
const buildColor = b => ({ done: 'var(--ok)', failed: 'var(--bad)', running: 'var(--info)', queued: 'var(--faint)', canceled: 'var(--faint)' }[b.state] || 'var(--faint)');

// "owner/repo@ref" from a clone URL, the way people say it.
// The build behind a job: from its spec once labd records it, else from the timeline.
function buildIdOf(j) {
  if (j?.spec?.build) return j.spec.build;
  for (const e of j?.events || []) { const m = /\(build (b[\w-]+)\)|build (b\d{4}-\d{6}-\w+)/.exec(e.msg); if (m) return m[1] || m[2]; }
  const m = /build (b\d{4}-\d{6}-\w+)/.exec(j?.summary || '');
  return m ? m[1] : '';
}

function repoName(src) {
  const m = /github\.com[/:]([^/]+\/[^/.]+)/.exec(src?.repo || src?.input || '');
  const repo = m ? m[1] : (src?.repo || src?.input || '').replace(/^https?:\/\//, '').replace(/\.git$/, '');
  const ref = (src?.ref || '').replace(/^refs\/heads\//, '').replace(/^refs\/pull\/(\d+)\/head$/, 'PR #$1');
  if (/^[0-9a-f]{12,40}$/.test(ref)) return repo; // a bare commit: the sha is shown on its own
  return ref ? `${repo}@${ref}` : repo;
}
const shortSha = s => (s || '').slice(0, 10);

function buildTitle(b) { return b.release || repoName(b.source); }

function etaText(b) {
  if (b.state !== 'running') return '';
  if (b.eta_sec > 0) return `about ${dur(b.eta_sec)} left`;
  if (b.stage === 'build' && !b.progress) return 'first build of this config: no estimate yet';
  return '';
}

function buildStepper(b) {
  const st = stagesOf(b);
  const at = b.state === 'done' ? st.list.length : st.at[b.stage] ?? -1;
  return `<div class="pipe bpipe" style="grid-template-columns:repeat(${st.list.length},1fr)">${st.list.map(([k, n], i) => {
    let cls = '', s = 'waiting';
    if (b.state === 'failed' && i === Math.max(at, 0)) { cls = 'fail'; s = 'failed'; }
    else if (b.state === 'canceled' && i === Math.max(at, 0)) { cls = 'fail'; s = 'canceled'; }
    else if (i < at) { cls = 'done'; s = `${I.check} done`; }
    else if (i === at && b.state === 'running') { cls = 'now'; s = k === 'build' && b.progress ? `${Math.round(b.progress * 100)}%` : 'running'; }
    else if (b.state !== 'running' && b.state !== 'queued') s = '—';
    return `<div class="stage ${cls}"><div class="n">${n}</div><div class="s">${s}</div></div>`;
  }).join('')}</div>`;
}

// Overall bar: finished stages count fully, the compile stage by objects built.
function buildBar(b) {
  const st = stagesOf(b);
  const at = st.at[b.stage] ?? -1;
  let pct = b.state === 'done' ? 100 : 0;
  if (b.state === 'running' && at >= 0) {
    const w = st.w;
    const before = w.slice(0, at).reduce((a, x) => a + x, 0);
    const within = at === st.at.build ? (b.progress || 0) : 0.3;
    pct = Math.min(99, before + w[at] * within);
  }
  const indet = b.state === 'running' && b.stage === 'build' && !b.progress;
  return `<div class="bprog ${indet ? 'indet' : ''} ${b.state}"><i style="width:${indet ? 100 : pct.toFixed(1)}%"></i></div>`;
}

function buildCard(b, { log = 12, compact = false } = {}) {
  const [cls, label] = BUILD_STATE[b.state] || ['c-dim', b.state];
  const took = b.state === 'running' ? since(b.started && !zero(b.started) ? b.started : b.created) : b.seconds;
  const lines = S.blog[b.id]?.lines || [];
  return `<div class="bcard" style="--c:${buildColor(b)}">
    <div class="bhead">
      <div class="bicon">${I.hammer}</div>
      <div style="min-width:0"><div class="btitle">${esc(buildName(b))}</div>
        <div class="muted">${esc(buildSub(b))}${b.device ? ` · ${esc(b.device)}'s config` : ''}${b.builder ? ` · on ${esc(b.builder)}` : ''}</div></div>
      <div style="text-align:right">${pill(cls, label)}<div class="muted" style="margin-top:4px">${took ? dur(took) : ''}</div></div>
    </div>
    ${buildStepper(b)}
    ${b.state === 'running' || b.state === 'queued' ? `<div class="row" style="gap:12px">${buildBar(b)}<span class="dim nowrap">${esc(etaText(b) || (b.state === 'queued' ? 'waiting for a builder' : ''))}</span></div>` : ''}
    ${b.state === 'done' ? `<div class="bdone">${I.check} <span class="strong">${esc(b.release)}</span><span class="muted">${b.size ? ` · ${(b.size / 1048576).toFixed(0)} MB` : ''}${b.reused ? ' · reused an identical earlier build' : ''}</span></div>` : ''}
    ${b.error ? `<div class="berr">${esc(b.error)}</div>` : ''}
    ${compact ? '' : `<pre class="term blog" data-build="${esc(b.id)}">${lines.length ? lines.slice(-log).map(l => `<span class="l k-${lineKind(l)}">${esc(l)}</span>`).join('') : `<span class="l muted">${b.state === 'running' || b.state === 'queued' ? 'waiting for build output…' : 'no log output'}</span>`}</pre>`}
    <div class="row">
      ${compact ? '' : `<button class="btn sm" onclick="go('#/builds/${esc(b.id)}')">${ic('file')} Full log${b.log_lines ? ` · ${b.log_lines}` : ''}</button>`}
      ${b.state === 'running' || b.state === 'queued' ? `<button class="btn sm ghost danger" onclick="cancelBuild('${esc(b.id)}')">${ic('stop')} Cancel</button>` : ''}
      ${b.state === 'done' && b.artifact ? bootTargets(b).map(d => `<button class="btn sm primary" onclick="bootBuild('${esc(b.id)}','${esc(d)}')">${ic('rocket')} Boot once on ${esc(d)}</button>`).join('') : ''}
    </div>
  </div>`;
}

function buildRows(list, sel) {
  if (!list.length) return `<div class="empty"><div class="big">${ic('hammer')}</div><div>No builds yet.</div><div class="muted" style="max-width:40ch">Paste a GitHub repo, branch, commit or PR URL above.</div></div>`;
  return `<div class="jobs">${list.map(b => `
    <div class="jrow ${b.id === sel ? 'sel' : ''}" onclick="go('#/builds/${esc(b.id)}')" style="--c:${buildColor(b)}">
      <span class="b ${b.state === 'running' || b.state === 'queued' ? 'live' : ''}"></span>
      <div class="top"><span class="kind">${esc(buildName(b))}</span><span class="dev">${esc(shortSha(b.source?.sha))}</span></div>
      <span class="when">${ago(b.created)}</span>
      <div class="sum">${b.state === 'running' ? `${esc(b.stage)}${b.stage === 'build' && b.progress ? ` · ${Math.round(b.progress * 100)}%` : ''}${b.eta_sec ? ` · ~${dur(b.eta_sec)} left` : ''}`
        : b.state === 'done' ? `${esc(b.release)} · ${dur(b.seconds || 0)}${b.reused ? ' · reused' : ''}` : esc(b.error || b.state)}</div>
    </div>`).join('')}</div>`;
}

function buildsLayout() {
  put('blist', `<form class="bnew" id="bnew">
      <input type="text" id="bn-src" placeholder="https://github.com/owner/repo/tree/branch · commit · pull/N" autocomplete="off" spellcheck="false">
      <div class="row"><select id="bn-dev"></select>
        <label class="tog" title="rebuild even if an identical build exists"><input type="checkbox" id="bn-force"><i></i>force</label>
        <span class="grow"></span><button class="btn primary sm" type="submit">${ic('hammer')} Build</button></div>
    </form><div id="blist-rows"></div>`);
  $('#bnew').onsubmit = async e => {
    e.preventDefault();
    const source = $('#bn-src').value.trim();
    if (!source) { $('#bn-src').focus(); return; }
    try {
      const b = await post('/api/builds', { source, device: $('#bn-dev').value || undefined, force: $('#bn-force').checked });
      S.buildCache[b.id] = b;
      toast(b.state === 'done' ? 'Already built' : 'Build queued', `${repoName(b.source)} ${shortSha(b.source?.sha)}`);
      $('#bn-src').value = '';
      go('#/builds/' + b.id);
    } catch (err) { toast('Could not start the build', err.message, true); }
  };
}

function paintBuilds() {
  const sel = $('#bn-dev');
  if (sel) {
    const opts = `<option value="">no device config</option>` + S.devices.map(d => `<option value="${esc(d.name)}">${esc(d.name)}'s config</option>`).join('');
    if (sel.dataset.opts !== opts) { const cur = sel.value || S.devices[0]?.name || ''; sel.innerHTML = opts; sel.dataset.opts = opts; sel.value = cur; }
  }
  const alive = S.builders.filter(b => b.alive);
  put('sub-blist', alive.length ? `builder ${alive.map(b => esc(b.host)).join(', ')} · online` : S.builders.length ? '<span class="warn">builder offline</span>' : 'no builder connected');
  put('blist-rows', buildRows(S.builds, S.buildId));
  const b = S.buildId && (S.buildCache[S.buildId] || S.builds.find(x => x.id === S.buildId));
  if (!b) { put('bdetail', `<div class="empty"><div class="big">${ic('hammer')}</div><div>${S.buildId ? 'loading…' : 'Pick a build.'}</div></div>`); return; }
  put('sub-bdetail', `${esc(b.id)} · ${new Date(b.created).toLocaleString()}`);
  $('#desk')?.classList.toggle('sel', !!S.params.arg);
  put('tools-bdetail', `<button class="btn sm ghost mob-back" onclick="go('#/builds')">${I.chev} Builds</button>` + (b.state === 'running' || b.state === 'queued' ? `<label class="tog"><input type="checkbox" ${S.bfollow !== false ? 'checked' : ''} onchange="S.bfollow=this.checked"><i></i>follow</label>` : ''));
  const term = $('#bdetail .blog.full');
  const keep = term && { top: term.scrollTop, bottom: term.scrollHeight - term.scrollTop - term.clientHeight < 40, id: term.dataset.build };
  put('bdetail', buildDetail(b));
  const nt = $('#bdetail .blog.full');
  if (nt) nt.scrollTop = !keep || keep.id !== b.id || (keep.bottom && S.bfollow !== false) ? nt.scrollHeight : keep.top;
}

function buildDetail(b) {
  const lines = S.blog[b.id]?.lines || [];
  const jobs = S.jobs.filter(j => buildIdOf(j) === b.id);
  const errs = lines.filter(l => /\berror\b/i.test(l)).length, warns = lines.filter(l => /\bwarning\b/i.test(l)).length;
  return `${buildCard(b, { compact: true })}
    <dl class="kv" style="margin:18px 0">
      ${b.kind === 'package' ? `<dt>recipe</dt><dd class="wrap"><code>${esc(b.recipe_dir || b.recipe)}</code>${b.pkgrel ? ` <span class="muted">pkgrel ${esc(b.pkgrel)}</span>` : ''}</dd>` : ''}
      ${b.source?.input ? `<dt>${b.kind === 'package' ? '_commit' : 'source'}</dt><dd class="wrap">${esc(b.source.input)}</dd>` : ''}
      ${b.source?.sha ? `<dt>commit</dt><dd><code>${esc(b.source.sha)}</code></dd>` : ''}
      ${b.config_sha ? `<dt>config</dt><dd><code>${esc(b.config_sha.slice(0, 16))}</code>${b.device ? ` <span class="muted">from ${esc(b.device)}'s running kernel</span>` : ''}</dd>` : ''}
      ${b.artifact && !b.files?.length ? `<dt>artifact</dt><dd><code>${esc(b.artifact.slice(0, 16))}…</code></dd>` : ''}
      ${b.files?.length ? `<dt>files</dt><dd class="wrap bfiles">${b.files.map(f => `<div><a href="/api/builds/${enc(b.id)}/files/${enc(f.name)}" download>${ic('file')} ${esc(f.name)}</a> <span class="muted">${(f.size / 1048576).toFixed(f.size < 10485760 ? 1 : 0)} MB</span><br><code class="muted">${esc(f.sha256)}</code></div>`).join('')}</dd>` : ''}
      ${jobs.length ? `<dt>jobs</dt><dd class="wrap">${jobs.map(j => `<a href="#/jobs/${esc(j.id)}">${esc(j.id)}</a> <span class="muted">${esc(j.outcome || j.state)}</span>`).join(' · ')}</dd>` : ''}
    </dl>
    <div class="h">Build log <span class="muted" style="font-weight:400">${lines.length} lines${errs ? ` · <span class="bad">${errs} errors</span>` : ''}${warns ? ` · <span class="warn">${warns} warnings</span>` : ''} · compiler diagnostics and stage headers only</span></div>
    <pre class="term blog full" data-build="${esc(b.id)}">${lines.length ? lines.map(l => `<span class="l k-${lineKind(l)}${/^==>/.test(l) ? ' k-mark' : ''}">${esc(l)}</span>`).join('') : `<span class="l muted">${S.blog[b.id]?.loaded ? 'no output yet' : 'loading…'}</span>`}</pre>`;
}

async function loadBuildLog(id, force) {
  const bl = S.blog[id] ||= { lines: [] };
  if ((bl.loaded && !force) || bl.loading) return;
  bl.loading = true;
  try {
    const t = await api(`/api/builds/${enc(id)}/log`);
    bl.lines = String(t || '').replace(/\n$/, '').split('\n').filter(l => l.length);
    bl.loaded = true;
  } catch { bl.loaded = true; }
  finally { bl.loading = false; }
  paint();
}

async function cancelBuild(id) {
  try { await post(`/api/builds/${enc(id)}/cancel`); toast('Canceling build', id); tick(); } catch (e) { toast('Could not cancel', e.message, true); }
}

// Kernel builds boot on the Mac whose config they used; packages on any Mac.
function bootTargets(b) {
  if (b.kind !== 'package') return b.device ? [b.device] : [];
  return S.devices.map(d => d.name);
}

async function bootBuild(id, device) {
  const b = S.buildCache[id] || S.builds.find(x => x.id === id);
  if (!b?.artifact || !device) return;
  try { const j = await post('/api/jobs', { device, kernel: b.artifact, holder: 'web' }); go('#/jobs/' + j.id); }
  catch (e) { toast('Could not boot it', e.message, true); }
}

async function buildsTick() {
  const [builds, builders] = await Promise.all([api('/api/builds?limit=40').catch(() => null), api('/api/builders').catch(() => null)]);
  if (builds) { S.builds = builds; for (const b of builds) S.buildCache[b.id] = b; }
  if (builders) S.builders = builders;
  if (S.view === 'builds' && !S.buildId && S.builds[0]) S.buildId = S.builds[0].id;
  // Without the stream, running logs are re-read; with it, buildlog events append.
  const want = new Set(S.jobs.filter(j => j.state === 'building').map(buildIdOf).filter(Boolean));
  if (S.view === 'builds' && S.buildId) want.add(S.buildId);
  if (S.view === 'jobs' && buildIdOf(S.jobCache[S.jobId])) want.add(buildIdOf(S.jobCache[S.jobId]));
  for (const id of want) {
    const b = S.buildCache[id];
    if (!b && id) { try { S.buildCache[id] = await api('/api/builds/' + enc(id)); } catch { } }
    const running = S.buildCache[id]?.state === 'running' || S.buildCache[id]?.state === 'queued';
    loadBuildLog(id, running && S.stream !== 'up');
  }
}

// ——— view: live ————————————————————————————————————————————————————————————
// One Mac, live: what's on its screen, its serial console, and its logs.
S.ser = {};   // device -> [{t, line}]
S.kev = {};   // device -> [KernelEvent]
S.scr = {};   // device -> {meta, url, at, busy, err, hist: [{url, meta}], last}
S.logs = { tab: store('logtab') || 'journal', lines: +(store('loglines') || 500), unit: '', follow: false, text: null, err: '', key: '', loading: false };
S.auto = store('auto') || 'off';
S.stream = 'off';

const liveDevice = () => S.devices.find(x => x.name === S.liveDev) || S.devices[0];
const enc = encodeURIComponent;

async function blobURL(path) {
  const r = await fetch(path, { headers: authH() });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return URL.createObjectURL(await r.blob());
}

function liveLayout() {
  put('logs', `<div class="logbar"><nav class="tabs slim" id="log-tabs"></nav><span class="grow"></span>
      <input type="text" id="log-unit" placeholder="unit: lab-agent, sddm…" value="${esc(S.logs.unit)}">
      <select id="log-lines">${[200, 500, 2000, 10000].map(n => `<option ${n === S.logs.lines ? 'selected' : ''}>${n}</option>`).join('')}</select>
      <label class="tog" title="refresh every 5s"><input type="checkbox" id="log-follow" ${S.logs.follow ? 'checked' : ''}><i></i>follow</label>
      <button class="btn sm ghost" id="log-refresh" title="refresh">${ic('restart')}</button></div>
    <div id="log-body" class="logpane"></div>`);
  $('#log-unit').onchange = e => { S.logs.unit = e.target.value.trim(); loadLogs(true); };
  $('#log-lines').onchange = e => { S.logs.lines = +e.target.value; store('loglines', S.logs.lines); loadLogs(true); };
  $('#log-follow').onchange = e => { S.logs.follow = e.target.checked; };
  $('#log-refresh').onclick = () => loadLogs(true);
  S.logs.key = '';
  renderSerial(true);
  const d = liveDevice();
  if (d) { loadLogs(true); loadScreen(d); }
}

function paintLive() {
  const d = liveDevice();
  if (!d) { put('screen', `<div class="empty"><div class="big">${ic('laptop')}</div><div>No Macs enrolled.</div></div>`); return; }
  S.liveDev = d.name;
  const sc = S.scr[d.name] || {};
  const pick = S.devices.length > 1 ? `<div class="seg">${S.devices.map(x => `<button class="${x.name === d.name ? 'on' : ''}" onclick="go('#/live/${esc(x.name)}')">${esc(x.name)}</button>`).join('')}</div>` : '';
  put('sub-screen', `${esc(d.name)} · ${sc.meta ? `${sc.meta.time === 'latest' ? 'latest capture' : ago(sc.meta.time)}${sc.meta.width ? ` · ${sc.meta.width}×${sc.meta.height}` : ''}` : 'no capture yet'}`);
  put('tools-screen', `${pick}<div class="seg" title="capture automatically while this view is open">${['off', '3s', '10s', '30s'].map(a => `<button class="${S.auto === a ? 'on' : ''}" onclick="setAuto('${a}')">${a === 'off' ? 'auto off' : 'every ' + a}</button>`).join('')}</div>
    <button class="btn sm primary" onclick="capture()" ${sc.busy ? 'disabled' : ''}>${ic('camera')} ${sc.busy ? 'Capturing…' : 'Capture'}</button>`);
  hydrateCaptures(put('screen', screenBody(d, sc)));

  const o = S.oob[d.name];
  const sh = S.sh?.dev === d.name ? S.sh : null;
  const modeSeg = `<div class="seg"><button class="${S.serMode === 'log' ? 'on' : ''}" onclick="setSerMode('log')">${ic('list')} Log</button><button class="${S.serMode === 'shell' ? 'on' : ''}" onclick="setSerMode('shell')">${ic('console')} Shell</button></div>`;
  put('sub-serial', !d.oob ? 'no out-of-band controller' : S.serMode === 'shell' ? `interactive · ${esc(sh?.state || 'starting')}` : `debug UART · ${S.stream === 'up' ? 'live' : 'polling'}`);
  put('tools-serial', !d.oob ? '' : S.serMode === 'shell' ? `${modeSeg}<button class="btn sm ghost" onclick="closeShell();$('#shellhost')?.removeAttribute('data-dev');renderSerial(true)">${ic('restart')} Reconnect</button>
    <button class="btn sm ghost danger" onclick="confirmReset('${esc(d.name)}')">${ic('power')} Reset…</button>` : d.oob ? `${modeSeg}<button class="btn sm ghost" onclick="serialPause()">${ic(S.serPaused ? 'play' : 'pause')} ${S.serPaused ? 'Follow' : 'Pause'}</button>
    <button class="btn sm ghost" onclick="serialClear()">${ic('eraser')} Clear</button>
    <button class="btn sm ghost danger" onclick="confirmReset('${esc(d.name)}')">${ic('power')} Reset…</button>` : '');
  renderSerial(false);
  put('ttyfoot', !d.oob ? '' : S.serMode === 'shell' ? `${ic('console')} ${sh?.state === 'attached' ? `<span class="ok">${I.check} attached</span>` : esc(sh?.err || sh?.state || '…')}<span class="grow"></span>
    <span>debug UART · 115200 · no network needed</span><span>${esc(o?.controller || d.oob.url)}</span>` : `${ic('serial')} ${(S.ser[d.name] || []).length} lines<span class="grow"></span>
    <span>${esc(o?.controller || d.oob.url)}</span>
    <span class="${o?.serial_connected ? 'ok' : 'warn'}">${o ? (o.serial_connected ? `${I.check} connected` : 'not connected') : '…'}</span>
    ${o?.serial_last && !zero(o.serial_last) ? `<span>last line ${ago(o.serial_last)}</span>` : ''}`);

  // Reload when the source changes, or when a Mac that was offline is back.
  const retry = S.logs.err && d.alive && Date.now() - (S.logs.errAt || 0) > 8000;
  if (S.logs.tab !== 'events' && (S.logs.key !== logKey(d) || retry) && !S.logs.loading) setTimeout(() => loadLogs(true));
  if (!S.scr[d.name]?.at) loadScreen(d);
  const kev = S.kev[d.name] || [];
  put('log-tabs', [['journal', 'Journal'], ['kernel', 'Kernel'], ['events', 'Events', kev.filter(e => e.kind !== 'warning').length]].map(([k, l, n]) =>
    `<button class="${k === S.logs.tab ? 'on' : ''}" onclick="setLogTab('${k}')">${l}${n ? `<span class="cnt">${n}</span>` : ''}</button>`).join(''));
  const unit = $('#log-unit');
  if (unit) unit.hidden = S.logs.tab !== 'journal';
  const lines = $('#log-lines');
  if (lines) lines.hidden = S.logs.tab === 'events';
  const term = $('#logterm');
  const keep = term && { top: term.scrollTop, bottom: term.scrollHeight - term.scrollTop - term.clientHeight < 40, key: term.dataset.key };
  put('log-body', logBody(d, kev));
  const nt = $('#logterm');
  if (nt) nt.scrollTop = !keep || keep.key !== nt.dataset.key || keep.bottom ? nt.scrollHeight : keep.top;
}

// ——— screen ———
function screenBody(d, sc) {
  if (sc.url) {
    return `<div class="screen"><div class="bezel"><img src="${sc.url}" alt="${esc(d.name)} screen" onclick="viewer('${sc.url}')"></div>
      ${(sc.list || []).length > 1 ? `<div class="strip">${sc.list.slice(0, 14).map(f => `<button class="${f.name === sc.meta?.name ? 'on' : ''}" onclick="showCapture('${esc(d.name)}', '${esc(f.name)}')" title="${esc(new Date(f.time).toLocaleString())}"><img data-cap="${esc(d.name)}/${esc(f.name)}" alt=""><span>${hms(new Date(f.time))}</span></button>`).join('')}</div>` : ''}</div>`;
  }
  return `<div class="empty"><div class="big">${ic('monitor')}</div>
    <div class="strong" style="font-family:var(--sans);font-size:16px">${sc.err ? 'No screen capture' : `Nothing captured from ${esc(d.name)} yet`}</div>
    <div style="max-width:52ch">${sc.err ? esc(sc.err) : `Captures come from <code>grim</code> inside ${esc(d.facts?.gui_user || 'the GUI user')}'s Hyprland session. Jobs also capture after boot and after tests.`}</div>
    <button class="btn primary" onclick="capture()" ${sc.busy ? 'disabled' : ''}>${ic('camera')} ${sc.busy ? 'Capturing…' : 'Capture now'}</button></div>`;
}

// loadScreen shows the device's latest capture, fetching it only when it changed.
async function loadScreen(d, meta) {
  if (!d) return;
  const sc = S.scr[d.name] ||= { hist: [] };
  const at = meta?.time || (!zero(d.screen_at) && d.screen_at) || (sc.at ? null : 'latest');
  if (!at || sc.at === at || sc.loading === at || (sc.pinned && !meta)) return;
  sc.loading = at;
  try {
    const url = await blobURL(`/api/devices/${enc(d.name)}/screen?t=${enc(at)}`);
    const img = new Image();
    await new Promise(r => { img.onload = img.onerror = r; img.src = url; });
    sc.meta = { ...(meta || sc.meta || {}), time: at, width: meta?.width || img.naturalWidth, height: meta?.height || img.naturalHeight };
    sc.at = at; sc.url = url; sc.err = ''; sc.pinned = false;
    loadCaptureList(d).then(() => S.view === 'live' && S.liveDev === d.name && paintLive());
    sc.hist.unshift({ url, meta: sc.meta });
    for (const old of sc.hist.splice(8)) URL.revokeObjectURL(old.url);
  } catch (e) { if (!sc.url) sc.err = e.message; }
  finally { sc.loading = null; }
  if (S.view === 'live' && S.liveDev === d.name) paintLive();
}

async function capture() {
  const d = liveDevice();
  if (!d) return;
  const sc = S.scr[d.name] ||= { hist: [] };
  if (sc.busy) return;
  sc.busy = true; sc.last = Date.now(); paintLive();
  try {
    const meta = await post(`/api/devices/${enc(d.name)}/screenshot`);
    d.screen_at = meta.time;
    await loadScreen(d, meta);
  } catch (e) {
    sc.err = /404 page not found/i.test(e.message) ? 'This labd does not support screen capture yet.' : e.message;
    if (S.auto !== 'off') { S.auto = 'off'; store('auto', 'off'); }
    toast('Screen capture failed', sc.err, true);
  } finally { sc.busy = false; if (S.view === 'live') paintLive(); }
}

// Capture history from labd: thumbnails load once per file.
const caps = {};
function hydrateCaptures(root) {
  if (!root) return;
  $$('img[data-cap]', root).forEach(async img => {
    const k = img.dataset.cap;
    const [dev, file] = k.split('/');
    caps[k] ||= blobURL(`/api/devices/${enc(dev)}/screens/${enc(file)}`).catch(() => '');
    const u = await caps[k];
    if (u) img.src = u;
  });
}

async function showCapture(dev, file) {
  const sc = S.scr[dev];
  const f = sc?.list?.find(x => x.name === file);
  if (!f) return;
  const k = dev + '/' + file;
  caps[k] ||= blobURL(`/api/devices/${enc(dev)}/screens/${enc(file)}`).catch(() => '');
  const u = await caps[k];
  if (u) { sc.url = u; sc.meta = { ...f }; sc.pinned = true; paintLive(); }
}

async function loadCaptureList(d) {
  const sc = S.scr[d.name] ||= { hist: [] };
  try { sc.list = await api(`/api/devices/${enc(d.name)}/screens`); } catch { sc.list = null; }
  if (sc.meta?.time === 'latest' && sc.list?.[0]) sc.meta = { ...sc.meta, name: sc.list[0].name, time: sc.list[0].time };
}

function setAuto(a) { S.auto = a; store('auto', a); paintLive(); }
function showShot(name, i) { const sc = S.scr[name]; if (sc?.hist[i]) { sc.url = sc.hist[i].url; sc.meta = sc.hist[i].meta; paintLive(); } }
setInterval(() => {
  if (S.view !== 'live' || S.auto === 'off' || S.locked || document.hidden) return;
  const sc = S.scr[S.liveDev] || {};
  if (!sc.busy && Date.now() - (sc.last || 0) > parseInt(S.auto) * 1000) capture();
}, 1000);

// Mac-card thumbnails: one fetch per capture, shared across repaints.
const thumbs = {};
function hydrateScreens(root) {
  if (!root) return;
  $$('img[data-screen]', root).forEach(async img => {
    const k = img.dataset.screen + '|' + img.dataset.at;
    thumbs[k] ||= blobURL(`/api/devices/${enc(img.dataset.screen)}/screen?t=${enc(img.dataset.at)}`).catch(() => '');
    const u = await thumbs[k];
    if (u) img.src = u; else img.closest('.thumb')?.remove();
  });
}


// ——— interactive shell on the debug UART ———
// labd relays raw bytes both ways, so this works with the Mac's network down.
S.serMode = store('sermode') || 'log';
let xtLoad;
function loadXterm() {
  return xtLoad ||= new Promise((res, rej) => {
    document.head.appendChild(Object.assign(document.createElement('link'), { rel: 'stylesheet', href: '/ui/vendor/xterm/xterm.css' }));
    const add = src => new Promise((ok, no) => document.head.appendChild(Object.assign(document.createElement('script'), { src, onload: ok, onerror: () => no(new Error('could not load ' + src)) })));
    add('/ui/vendor/xterm/xterm.js').then(() => add('/ui/vendor/xterm/addon-fit.js')).then(res, e => { xtLoad = null; rej(e); });
  });
}

// The terminal wears the Omarchy theme's ANSI palette, like Alacritty does, on
// the same sunken surface the app's other terminal panes use (--sunken: the
// window color darkened a little), so it matches in light and dark themes.
function mixHex(a, b, t) {
  const p = h => { const v = parseInt(String(h || '#000').slice(1, 7), 16); return [v >> 16, (v >> 8) & 255, v & 255]; };
  const [x, y] = [p(a), p(b)];
  return '#' + x.map((c, i) => Math.round(c + (y[i] - c) * t).toString(16).padStart(2, '0')).join('');
}

function xtTheme() {
  const t = activeTheme() || {};
  const c = t.colors || {};
  const f = (...k) => k.map(x => c[x]).find(Boolean);
  const light = t.mode === 'light';
  const bg = mixHex(f('background') || '#1a1b26', '#000000', light ? 0.05 : 0.10);
  const fg = f('foreground') || '#c0caf5';
  const readable = h => h && contrast(h, bg) >= 2.2 ? h : fg; // a palette color that vanishes on bg falls back to text color
  let cursor = f('accent');
  if (!cursor || contrast(cursor, bg) < 1.6) cursor = fg;
  return {
    background: bg, foreground: fg, cursor, cursorAccent: bg,
    selectionBackground: mixHex(bg, fg, 0.22), selectionForeground: fg,
    black: readable(light ? f('foreground') : f('dark_background', 'lighter_background')), red: readable(f('red')), green: readable(f('green')),
    yellow: readable(f('yellow')), blue: readable(f('blue', 'accent')), magenta: readable(f('magenta')), cyan: readable(f('cyan')),
    white: readable(light ? f('dark_foreground', 'foreground') : f('foreground')),
    brightBlack: readable(f('muted', 'dark_foreground')), brightRed: readable(f('bright_red', 'red')), brightGreen: readable(f('bright_green', 'green')),
    brightYellow: readable(f('bright_yellow', 'yellow')), brightBlue: readable(f('bright_blue', 'blue')), brightMagenta: readable(f('bright_magenta', 'magenta')),
    brightCyan: readable(f('bright_cyan', 'cyan')), brightWhite: readable(f('bright_foreground', 'foreground')),
  };
}

function setSerMode(m) { S.serMode = m; store('sermode', m); if (m === 'log') closeShell(); renderSerial(true); paintLive(); }

function closeShell() {
  const sh = S.sh;
  if (!sh) return;
  S.sh = null;
  sh.ctl?.abort(); sh.ro?.disconnect(); clearTimeout(sh.timer);
  try { sh.term?.dispose(); } catch { }
}

async function openShell(dev) {
  closeShell();
  const host = $('#shellhost');
  if (!host) return;
  const sh = S.sh = { dev, state: 'loading' };
  paintLive();
  try { await loadXterm(); } catch (e) { sh.state = 'error'; sh.err = e.message; paintLive(); return; }
  if (S.sh !== sh || !host.isConnected) return;
  const term = new Terminal({
    fontFamily: '"Lab Mono", "JetBrainsMono Nerd Font", ui-monospace, monospace', fontSize: 13, lineHeight: 1.15,
    cursorBlink: true, scrollback: 5000, theme: xtTheme(), allowProposedApi: false,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(host);
  sh.term = term;
  const refit = () => { try { fit.fit(); } catch { } };
  refit();
  sh.ro = new ResizeObserver(refit);
  sh.ro.observe(host);
  term.focus();

  // Keystrokes go out in small batches so a paste is one request, not hundreds.
  // One send in flight at a time: concurrent POSTs can land out of order and
  // scramble what was typed. Keys typed meanwhile go out together next.
  let pending = '', sending = false;
  const flush = async () => {
    if (sending || !pending || S.sh !== sh) return;
    sending = true;
    const b = pending; pending = '';
    try {
      const r = await fetch(`/api/devices/${enc(dev)}/console`, { method: 'POST', headers: { ...authH(), 'Content-Type': 'application/octet-stream' }, body: new TextEncoder().encode(b) });
      if (!r.ok) term.write(`\r\n\x1b[31m[${(await r.text()).trim() || r.status}]\x1b[0m\r\n`);
    } catch (e) { term.write(`\r\n\x1b[31m[send failed: ${e.message}]\x1b[0m\r\n`); }
    finally { sending = false; if (pending) flush(); }
  };
  term.onData(d => { pending += d; clearTimeout(sh.timer); sh.timer = setTimeout(flush, 12); });

  sh.state = 'arming'; paintLive();
  try { await post(`/api/devices/${enc(dev)}/console/arm`); }
  catch (e) { term.write(`\x1b[33m[serial mode: ${e.message}]\x1b[0m\r\n`); }
  if (S.sh !== sh) return;

  const ctl = sh.ctl = new AbortController();
  try {
    const r = await fetch(`/api/devices/${enc(dev)}/console`, { headers: authH(), signal: ctl.signal });
    if (!r.ok || !r.body) throw new Error((await r.text()).trim() || r.statusText);
    sh.state = 'attached'; paintLive();
    pending += '\r'; flush(); // wake the getty so a prompt appears
    const rd = r.body.getReader();
    for (;;) {
      const { value, done } = await rd.read();
      if (done) break;
      term.write(value);
    }
    if (S.sh === sh) { sh.state = 'closed'; term.write('\r\n\x1b[2m[console stream ended — reconnect to continue]\x1b[0m\r\n'); }
  } catch (e) {
    if (S.sh === sh && e.name !== 'AbortError') { sh.state = 'closed'; sh.err = e.message; term.write(`\r\n\x1b[31m[${e.message}]\x1b[0m\r\n`); }
  }
  if (S.sh === sh) paintLive();
}

// ——— serial ———
const serLine = x => `<span class="l k-${lineKind(x.line)}"><span class="ts">${x.t ? hms(new Date(x.t)) : '        '}</span> ${esc(x.line)}</span>`;

function pushSerial(name, t, line) {
  if (!line || !line.trim()) return;
  const b = S.ser[name] ||= [];
  const x = { t, line };
  b.push(x);
  if (b.length > 4000) b.splice(0, b.length - 4000);
  if (S.view === 'live' && S.liveDev === name) appendSerial(x);
}

function renderSerial(full) {
  const d = liveDevice();
  if (!d) return;
  if (!d.oob) {
    put('serial', `<div class="empty" style="padding:30px"><div class="big">${ic('usb')}</div>
      <div class="strong" style="font-family:var(--sans);font-size:16px">${esc(d.name)} has no serial console yet</div>
      <div style="max-width:52ch">Connect another Apple Silicon Mac's DFU port to ${esc(d.name)}'s DFU port, run <code>oobd</code> there, and attach it. The console then streams here, and the lab can hard-reset ${esc(d.name)} remotely.</div>
      <pre class="term plain" style="border-radius:6px;border:1px solid var(--line);text-align:left;white-space:pre-wrap"><span class="l"><span class="ts">$</span> lab device ${esc(d.name)} --oob-url http://&lt;controller&gt;:7780 --oob-token …</span></pre></div>`);
    return;
  }
  if (S.serMode === 'shell') {
    if ($('#shellhost')?.dataset.dev !== d.name) {
      closeShell();
      put('serial', `<div class="tty"><div class="shellhost" id="shellhost" data-dev="${esc(d.name)}"></div><div class="foot" id="ttyfoot"></div></div>`);
      openShell(d.name);
    }
    return;
  }
  if (!$('#ttyterm') || $('#ttyterm').dataset.dev !== d.name) {
    put('serial', `<div class="tty"><pre class="term plain" id="ttyterm" data-dev="${esc(d.name)}"></pre><div class="foot" id="ttyfoot"></div></div>`);
    full = true;
  }
  if (!full) return;
  const el = $('#ttyterm');
  const b = S.ser[d.name] || [];
  el.innerHTML = b.length ? b.map(serLine).join('') : `<span class="l muted waiting">waiting for serial output…</span>`;
  el.scrollTop = el.scrollHeight;
}

function appendSerial(x) {
  const el = $('#ttyterm');
  if (!el) return;
  el.querySelector('.waiting')?.remove();
  const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  el.insertAdjacentHTML('beforeend', serLine(x));
  while (el.childElementCount > 4000) el.firstElementChild.remove();
  if (bottom && !S.serPaused) el.scrollTop = el.scrollHeight;
  soon(paintLive, 500);
}

function serialPause() { S.serPaused = !S.serPaused; if (!S.serPaused) { const el = $('#ttyterm'); if (el) el.scrollTop = el.scrollHeight; } paintLive(); }
function serialClear() { S.ser[S.liveDev] = []; renderSerial(true); paintLive(); }

// ——— logs ———
const logKey = d => [d.name, S.logs.tab, S.logs.lines, S.logs.tab === 'journal' ? S.logs.unit : ''].join('|');

function setLogTab(t) { S.logs.tab = t; store('logtab', t); loadLogs(true); paintLive(); }

async function loadLogs(force) {
  const d = liveDevice();
  if (!d || S.logs.tab === 'events') return;
  const key = logKey(d);
  if ((!force && key === S.logs.key) || S.logs.loading) return;
  if (key !== S.logs.key) { S.logs.text = null; S.logs.err = ''; }
  S.logs.key = key; S.logs.loading = true;
  if (S.view === 'live') paintLive();
  try {
    const q = new URLSearchParams({ source: S.logs.tab, lines: S.logs.lines });
    if (S.logs.tab === 'journal' && S.logs.unit) q.set('unit', S.logs.unit);
    const t = await api(`/api/devices/${enc(d.name)}/logs?${q}`);
    if (S.logs.key === key) { S.logs.text = typeof t === 'string' ? t : JSON.stringify(t, null, 2); S.logs.err = ''; }
  } catch (e) {
    if (S.logs.key === key) { S.logs.err = /404 page not found/i.test(e.message) ? 'This labd cannot read logs from the Mac yet.' : e.message; S.logs.errAt = Date.now(); }
  } finally { S.logs.loading = false; }
  if (S.view === 'live') paintLive();
}

function logBody(d, kev) {
  if (S.logs.tab === 'events') {
    const ev = [...kev].reverse();
    return ev.length ? `<ul class="lines" style="padding:12px">${ev.map(e => `<li style="--c:${e.kind === 'warning' ? 'var(--warn)' : 'var(--bad)'}"><span class="k">${esc(e.kind)} · ${esc(e.source)} · ${hms(new Date(e.time))}</span>${esc(e.line)}</li>`).join('')}</ul>`
      : `<div class="empty"><div class="big">${ic('shield')}</div><div>No kernel errors in the last day.</div></div>`;
  }
  if (S.logs.err) return `<div class="empty"><div class="big">${ic('alert')}</div><div style="max-width:56ch">${esc(S.logs.err)}</div><button class="btn sm" onclick="loadLogs(true)">${ic('restart')} Retry</button></div>`;
  if (S.logs.text === null) return `<div class="empty muted">reading ${esc(S.logs.tab)} from ${esc(d.name)}…</div>`;
  const lines = S.logs.text.replace(/\n$/, '').split('\n');
  return `<pre class="term" id="logterm" data-key="${esc(S.logs.key)}">${lines.map(l => `<span class="l k-${lineKind(l)}">${esc(l) || ' '}</span>`).join('')}</pre>`;
}

// ——— live polling (the stream carries most of this when it is up) ———
let liveN = 0;
async function liveTick(devices) {
  const d = devices.find(x => x.name === S.liveDev) || devices[0];
  if (!d) return;
  liveN++;
  const jobs = [];
  if (d.oob && S.stream !== 'up') {
    jobs.push(api(`/api/devices/${enc(d.name)}/serial?lines=800`).then(t => {
      const b = String(t || '').split('\n').filter(l => l.trim()).map(l => {
        const m = /^(\d{4}-\d\d-\d\dT[\d:.]+) (.*)$/.exec(l);
        return m ? { t: m[1], line: m[2] } : { t: '', line: l };
      }).filter(x => x.line.trim());
      const cur = S.ser[d.name] || [];
      if (b.length !== cur.length || b.at(-1)?.line !== cur.at(-1)?.line) { S.ser[d.name] = b; renderSerial(true); }
    }).catch(() => { }));
  }
  if (d.oob && liveN % 7 === 1) jobs.push(api(`/api/devices/${enc(d.name)}/oob`).then(o => { S.oob[d.name] = o; }).catch(e => { S.oob[d.name] = { error: e.message }; }));
  if (liveN % 4 === 1 || S.stream !== 'up') jobs.push(api(`/api/devices/${enc(d.name)}`).then(x => {
    const seen = new Set((S.kev[d.name] || []).map(e => e.time + e.line));
    for (const e of x.recent_events || []) if (!seen.has(e.time + e.line)) (S.kev[d.name] ||= []).push(e);
    (S.kev[d.name] || []).sort((a, b) => new Date(a.time) - new Date(b.time));
  }).catch(() => { }));
  if (S.logs.follow && liveN % 3 === 0) loadLogs(true);
  loadScreen(d);
  await Promise.all(jobs);
}

// ——— server-sent events ———
// labd streams device, job, serial, kernel-event and screen events. EventSource
// cannot send the admin token, so this reads the stream with fetch.
async function stream() {
  if (S.streamCtl || S.locked || (!S.token && !S.open)) return;
  const ctl = new AbortController();
  S.streamCtl = ctl;
  let retry = 3000;
  try {
    const r = await fetch('/api/stream', { headers: authH(), signal: ctl.signal });
    if (r.status === 404 || r.status === 405) { S.stream = 'none'; retry = 60000; return; }
    if (!r.ok || !r.body) throw new Error(String(r.status));
    S.stream = 'up';
    bar();
    const rd = r.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '';
    for (;;) {
      const { value, done } = await rd.read();
      if (done) break;
      buf += value.replace(/\r/g, '');
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) { onEvent(buf.slice(0, i)); buf = buf.slice(i + 2); }
    }
  } catch { } finally {
    S.streamCtl = null;
    if (S.stream === 'up') S.stream = 'down';
    bar();
    if (!S.locked) setTimeout(stream, retry);
  }
}

function onEvent(block) {
  let ev = 'message', data = '';
  for (const l of block.split('\n')) {
    if (l.startsWith(':')) continue;
    if (l.startsWith('event:')) ev = l.slice(6).trim();
    else if (l.startsWith('data:')) data += (data ? '\n' : '') + l.slice(5).replace(/^ /, '');
  }
  if (!data) return;
  let x;
  try { x = JSON.parse(data); } catch { return; }
  switch (ev) {
    case 'device': {
      const i = S.devices.findIndex(d => d.name === x.name);
      if (i >= 0) S.devices[i] = { ...S.devices[i], ...x }; else S.devices.push(x);
      soon(paint);
      break;
    }
    case 'job': soon(tick, 200); break;
    case 'build': {
      S.buildCache[x.id] = x;
      const i = S.builds.findIndex(b => b.id === x.id);
      if (i >= 0) S.builds[i] = x; else S.builds.unshift(x);
      soon(paint);
      break;
    }
    case 'buildlog': {
      const bl = S.blog[x.id] ||= { lines: [] };
      bl.lines.push(...(x.lines || []));
      if (bl.lines.length > 20000) bl.lines.splice(0, bl.lines.length - 20000);
      soon(paint, 300);
      break;
    }
    case 'serial': pushSerial(x.device, x.time, x.line); break;
    case 'kevent': (S.kev[x.device] ||= []).push(x); soon(paint); break;
    case 'screen': {
      const d = S.devices.find(d => d.name === x.device);
      if (d) d.screen_at = x.time;
      if (S.view === 'live' && x.device === S.liveDev) loadScreen(d, x);
      soon(paint);
      break;
    }
  }
}

const soonT = new Map();
function soon(f, ms = 150) {
  if (soonT.get(f)) return;
  soonT.set(f, setTimeout(() => { soonT.delete(f); f(); }, ms));
}

// ——— actions ———————————————————————————————————————————————————————————————
function modal(title, html, buttons) {
  const s = document.createElement('div');
  s.className = 'scrim';
  s.innerHTML = `<section class="win focus"><header class="titlebar"><span class="dot"></span><span class="t">${esc(title)}</span></header>
    <div class="body">${html}<div class="row end" style="margin-top:20px">${buttons.map((b, i) => `<button class="btn ${b.cls || ''}" data-i="${i}">${b.label}</button>`).join('')}</div></div></section>`;
  const close = () => s.remove();
  s.onclick = e => { if (e.target === s) close(); };
  $$('[data-i]', s).forEach(b => b.onclick = async () => { const f = buttons[+b.dataset.i].run; close(); f && await f(); });
  document.body.appendChild(s);
  $('.btn.primary, .btn.danger', s)?.focus();
}

function confirmJob(dev, kind) {
  const d = S.devices.find(x => x.name === dev);
  const copy = kind === 'baseline'
    ? `<p>${esc(dev)} reboots <b class="strong">twice</b>: once into a lab entry, once back. It proves the one-shot boot both selects and clears, and records the baseline kernel log. Nothing is installed.</p>`
    : `<p>${esc(dev)} boots a lab entry, then the agent triggers a <b class="bad">real kernel panic</b> (sysrq-c). The lab checks it comes back on its own via <code>panic=10</code> and the one-shot fallback${d?.tier === 2 ? ', with a hard reset if not' : ''}.</p>`;
  modal(kind === 'baseline' ? `Baseline ${dev}` : `Crash-test ${dev}`, copy + `<p class="muted">Anyone using ${esc(dev)} loses their session.</p>`, [
    { label: 'Cancel', cls: 'ghost' },
    { label: kind === 'baseline' ? `${ic('shield')} Run baseline` : `${ic('flash')} Panic it`, cls: kind === 'baseline' ? 'primary' : 'danger', run: async () => {
      try { const j = await post('/api/jobs', { device: dev, holder: 'web', ...(kind === 'baseline' ? { baseline: true } : { crash: 'panic' }) }); go('#/jobs/' + j.id); }
      catch (e) { toast('Could not start', e.message, true); }
    } },
  ]);
}

function confirmReset(dev) {
  const d = S.devices.find(x => x.name === dev);
  modal(`Reset ${dev}`, `<p>Runs the recovery ladder on ${esc(dev)}: soft reboot through the agent${d?.oob ? ', then a hard reset through its controller' : ''}, then a power-cycle request to a human if it still doesn't come back.</p>`, [
    { label: 'Cancel', cls: 'ghost' },
    { label: `${ic('restart')} Reset`, cls: 'danger', run: async () => { try { toast('Recovery started', await post(`/api/devices/${encodeURIComponent(dev)}/reset?by=web`)); } catch (e) { toast('Could not reset', e.message, true); } } },
  ]);
}

async function cancelJob(id) {
  try { toast('Canceling', await post(`/api/jobs/${encodeURIComponent(id)}/cancel`)); tick(); } catch (e) { toast('Could not cancel', e.message, true); }
}

// retryJob queues a finished job again: same Mac, kernel, tests and cmdline.
async function retryJob(id) {
  try { const n = await post(`/api/jobs/${enc(id)}/retry?holder=web`); go('#/jobs/' + n.id); } catch (e) { toast('Could not retry', e.message, true); }
}

function viewer(src) {
  const s = document.createElement('div');
  s.className = 'scrim';
  s.innerHTML = `<img class="full" src="${src}" alt="">`;
  s.onclick = () => s.remove();
  document.body.appendChild(s);
}

function toast(title, body = '', err = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.innerHTML = `<div class="tt">${esc(title)}</div>${body ? `<div class="tb">${esc(body)}</div>` : ''}`;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 8000 : 4000);
}

function copy(text) {
  const done = () => toast('Copied');
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(done);
  const ta = Object.assign(document.createElement('textarea'), { value: text });
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch { toast('Select and copy it by hand', '', true); }
  ta.remove();
}

// ——— menus ——————————————————————————————————————————————————————————————————
function menu(anchor, html, bind) {
  closeMenus();
  const m = document.createElement('div');
  m.className = 'menu';
  m.innerHTML = html;
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  const left = Math.min(r.left, innerWidth - m.offsetWidth - 10);
  m.style.left = Math.max(10, left) + 'px';
  m.style.top = (r.bottom + 8) + 'px';
  bind(m);
  setTimeout(() => document.addEventListener('click', closeMenus, { once: true }), 0);
}
function closeMenus() { $$('.menu').forEach(m => m.remove()); }

function mainMenu(anchor) {
  menu(anchor, `<div class="mh"><span>Omarchy · maclab</span><span class="og" style="color:var(--accent)">${OMARCHY}</span></div>
    ${VIEWS.map(([v], i) => `<button data-go="${v}" class="${v === S.view ? 'on' : ''}">${ic({ macs: 'laptop', jobs: 'history', builds: 'hammer', run: 'rocket', live: 'monitor' }[v])} ${v[0].toUpperCase() + v.slice(1)}<span class="r">${i + 1}</span></button>`).join('')}
    <hr><button data-theme>${ic('palette')} Style<span class="r">&gt;</span></button>
    ${!lockable() ? '' : `<button data-lock>${ic('lock')} Lock<span class="r">L</span></button>`}`, m => {
    $$('[data-go]', m).forEach(b => b.onclick = () => go('#/' + b.dataset.go));
    $('[data-theme]', m).onclick = e => { e.stopPropagation(); themeMenu(anchor); };
    $('[data-lock]', m) && ($('[data-lock]', m).onclick = () => lock());
  });
}

function themeMenu(anchor) {
  const cur = activeTheme();
  const sw = t => `<span class="swatch">${['background', 'accent', 'green', 'red', 'foreground'].map(k => `<i style="background:${t.colors[k] || 'transparent'}"></i>`).join('')}</span>`;
  const follow = S.themes.find(t => t.current);
  menu(anchor, `<div class="mh"><span>Style</span><span class="muted" style="font-family:var(--mono);font-size:12px">${S.themes.length} themes</span></div>
    ${follow ? `<button data-t="follow" class="${S.theme === 'follow' ? 'on' : ''}">${sw(follow)} Follow Omarchy<span class="r">${esc(follow.title)}</span></button><hr>` : ''}
    ${S.themes.map(t => `<button data-t="${esc(t.name)}" class="${S.theme !== 'follow' && t.name === cur?.name ? 'on' : ''}">${sw(t)} ${esc(t.title)}<span class="r">${t.mode === 'light' ? 'light' : ''}</span></button>`).join('')}`, m => {
    $$('[data-t]', m).forEach(b => {
      b.onclick = () => { S.theme = b.dataset.t; store('theme', S.theme); applyTheme(); paint(); };
      b.onmouseenter = () => { const keep = S.theme; S.theme = b.dataset.t; applyTheme(); S.theme = keep; };
    });
    m.onmouseleave = applyTheme;
  });
}

// ——— lock screen (hyprlock) ——————————————————————————————————————————————————
async function lock(msg = '') {
  S.locked = true;
  S.streamCtl?.abort();
  if (msg) { S.token = ''; store('token', null); }
  let l = $('.lock');
  if (!l) {
    l = document.createElement('div');
    l.className = 'lock';
    document.body.appendChild(l);
  }
  const logo = await logoSVG();
  l.innerHTML = `<div class="inner">
    <div class="logo">${logo}</div>
    <div class="time" id="lock-time"></div><div class="date" id="lock-date"></div>
    <form id="lock-form"><input type="password" id="lock-token" placeholder="labd admin token" autocomplete="current-password" autofocus>
      <div class="msg ${msg ? 'bad' : ''}" id="lock-msg">${esc(msg)}</div></form>
    <div class="hint">cat ~/.local/share/maclab/admin.token</div></div>`;
  clock();
  $('#lock-token').focus();
  $('#lock-form').onsubmit = async e => {
    e.preventDefault();
    const tok = $('#lock-token').value.trim();
    if (!tok) return;
    S.token = tok;
    try {
      // A viewer can already read /api/devices, so ask labd what the token is worth.
      const r = await fetch(S.viewer ? '/api/auth' : '/api/devices', { headers: { Authorization: 'Bearer ' + tok } });
      if (r.status === 401) throw new Error('That token was not accepted.');
      if (!r.ok) throw new Error(await r.text());
      if (S.viewer && (await r.json()).role !== 'admin') throw new Error('That token was not accepted.');
      store('token', tok);
      unlock();
    } catch (err) { $('#lock-msg').textContent = err.message; $('#lock-msg').className = 'msg bad'; $('#lock-token').select(); }
  };
}
function unlock() { S.locked = false; S.laid = null; $('.lock')?.remove(); route(); stream(); }

let logoCache;
async function logoSVG() {
  if (!logoCache) { try { logoCache = await (await fetch('/ui/omarchy-logo.svg')).text(); } catch { logoCache = ''; } }
  return logoCache.replace(/<svg /, '<svg style="width:100%;height:auto" ');
}

// ——— polling ———————————————————————————————————————————————————————————————
let ticking = false;
async function tick() {
  if (ticking || S.locked || (!S.token && !S.open)) return;
  ticking = true;
  S.lastTick = Date.now();
  try {
    const [devices, jobs] = await Promise.all([api('/api/devices'), api('/api/jobs?limit=40')]);
    S.devices = devices; S.jobs = jobs; S.online = true;
    const want = new Set(jobs.filter(j => j.state !== 'done').map(j => j.id));
    if (S.view === 'jobs' && S.jobId) want.add(S.jobId);
    for (const d of devices) if (d.active_job) want.add(d.active_job);
    await Promise.all([...want].map(async id => {
      const c = S.jobCache[id];
      if (c && c.state === 'done' && id !== S.jobId) return;
      if (c && c.state === 'done' && c.updated === jobs.find(j => j.id === id)?.updated) return;
      try { S.jobCache[id] = await api('/api/jobs/' + encodeURIComponent(id)); } catch { }
    }));
    if (S.view === 'jobs' && !S.jobId && jobs[0]) { S.jobId = jobs[0].id; }
    await buildsTick();
    if (S.view === 'live') await liveTick(devices);
  } catch (e) {
    if (e.message !== 'unauthorized') S.online = false;
  } finally { ticking = false; }
  paint();
}
setInterval(() => { if (S.stream !== 'up' || S.view === 'live' || Date.now() - (S.lastTick || 0) > 6000) tick(); }, 1500);
setInterval(() => { if (S.theme === 'follow') loadThemes(); }, 20000);

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !document.activeElement?.closest?.('.xterm')) { closeMenus(); $$('.scrim').forEach(s => s.remove()); }
  if (S.locked || /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName) || document.activeElement?.closest?.('.xterm')) return;
  const n = +e.key;
  if (n >= 1 && n <= VIEWS.length && !e.ctrlKey && !e.metaKey && !e.altKey) go('#/' + VIEWS[n - 1][0]);
  if (e.key === 'l' && !e.ctrlKey && !e.metaKey && lockable()) lock();
});

// ——— start ———————————————————————————————————————————————————————————————————
(async function start() {
  shell();
  await Promise.all([loadThemes(), logoSVG()]);
  try {
    const a = await (await fetch('/api/auth')).json();
    S.open = !a.token_required;
    S.viewer = a.role === 'viewer';
  } catch { S.open = false; }
  if (!S.open && !S.token) {
    // An older labd has no /api/auth: try without a token before asking for one.
    S.open = (await fetch('/api/devices').catch(() => null))?.ok || false;
  }
  if (!S.open && !S.token) { lock(); return; }
  route();
  stream();
})();
