// A real browser against a labd served under a prefix: headless Chromium,
// driven over the DevTools protocol with Node's own WebSocket (no packages).
// It unlocks the dashboard with a Maintainer token, waits for the lab's Mac,
// sees a change made outside the page arrive without a reload, makes an
// invite in the Enroll form, and checks that every request the page made
// stayed under the prefix.
//
//   node browser_smoke.mjs <chromium> <base URL, e.g. http://127.0.0.1:PORT/maclab> <token> <mac>
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [chrome, base, token, mac] = process.argv.slice(2);
const baseURL = new URL(base);
const prefix = baseURL.pathname.replace(/\/$/, '');
const dir = mkdtempSync(join(tmpdir(), 'maclab-browser-'));
const browser = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`,
	'--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
	'--disable-sync', '--disable-dev-shm-usage', '--disable-extensions', '--disable-gpu', '--mute-audio', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let stderr = '';
browser.stderr.on('data', b => { stderr += b; });

const fail = msg => { throw new Error(msg); };
async function until(what, f, ms = 20000) {
	for (const end = Date.now() + ms; Date.now() < end; await sleep(200)) {
		const v = await f();
		if (v) return v;
	}
	fail('timed out waiting for ' + what);
}

let ws, id = 0;
const pending = new Map(), requests = [], status = new Map(), exceptions = [], loaded = [];
function send(method, params = {}) {
	return new Promise((resolve, reject) => {
		const n = ++id;
		pending.set(n, { resolve, reject });
		ws.send(JSON.stringify({ id: n, method, params }));
	});
}
async function js(expr) {
	const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
	if (r.exceptionDetails) fail('page script: ' + JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text));
	return r.result.value;
}

try {
	const port = await until('Chromium', () => { try { return readFileSync(join(dir, 'DevToolsActivePort'), 'utf8').split('\n')[0]; } catch { return null; } });
	const page = await until('a page', async () => (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find(t => t.type === 'page'));
	ws = new WebSocket(page.webSocketDebuggerUrl);
	await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
	ws.onmessage = ev => {
		const m = JSON.parse(ev.data);
		if (m.id && pending.has(m.id)) {
			const p = pending.get(m.id); pending.delete(m.id);
			m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result);
		} else if (m.method === 'Network.requestWillBeSent') {
			requests.push(m.params.request.url);
		} else if (m.method === 'Network.responseReceived') {
			status.set(m.params.response.url, m.params.response.status);
		} else if (m.method === 'Runtime.exceptionThrown') {
			exceptions.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
		} else if (m.method === 'Page.loadEventFired') {
			loaded.push(Date.now());
		}
	};
	await send('Network.enable');
	await send('Runtime.enable');
	await send('Page.enable');

	// The dashboard, locked; the Maintainer's token unlocks it.
	await send('Page.navigate', { url: base + '/' });
	await until('the page to load', () => loaded.length > 0);
	await until('the lock screen', () => js(`!!document.querySelector('#lock-token')`));
	await js(`document.querySelector('#lock-token').value = ${JSON.stringify(token)}; document.querySelector('#lock-form').requestSubmit(); true`);
	await until('the lab\'s Mac in the dashboard', () => js(`document.body.innerText.includes(${JSON.stringify(mac)})`));
	await until('the event stream', () => [...status.entries()].some(([u, s]) => new URL(u).pathname === prefix + '/api/stream' && s === 200));

	// A change made outside the page shows up without a reload.
	const label = 'browser smoke ' + Date.now();
	const loadsBefore = loaded.length;
	const r = await fetch(`${base}/api/devices/${mac}`, { method: 'PATCH', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ label }) });
	if (!r.ok) fail('PATCH: ' + r.status);
	await until('the new label', () => js(`document.body.innerText.includes(${JSON.stringify(label)})`), 30000);
	if (loaded.length !== loadsBefore) fail('the page reloaded');

	// An invite from the Enroll form: the one-liner, with the base URL and the token on stdin.
	await js(`location.hash = '#/run'; true`);
	await until('the Enroll form', () => js(`!!document.querySelector('#en-name')`));
	await js(`document.querySelector('#en-name').value = 'browser-mac'; document.querySelector('#en-go').click(); true`);
	const cmd = await until('the one-liner', () => js(`(document.querySelector('#en-out pre')||{}).innerText || ''`));
	if (!cmd.includes(`U='${base}'`) || !cmd.includes('--token-stdin') || !cmd.includes('-H @-') || / --token /.test(cmd)) fail('the one-liner: ' + cmd);

	// Everything the page asked for stayed under the prefix.
	const outside = requests.filter(u => {
		const p = new URL(u);
		if (p.protocol === 'data:' || p.protocol === 'blob:') return false;
		return p.origin !== baseURL.origin || !(p.pathname === prefix || p.pathname.startsWith(prefix + '/'));
	});
	if (outside.length) fail('requests outside ' + base + ': ' + JSON.stringify(outside));
	if (exceptions.length) fail('page exceptions: ' + JSON.stringify(exceptions));
	const api = requests.filter(u => new URL(u).pathname.startsWith(prefix + '/api/')).length;
	console.log(JSON.stringify({ result: 'PASS', requests: requests.length, api_requests: api, one_liner_chars: cmd.length }));
} catch (e) {
	console.log(JSON.stringify({ result: 'FAIL', error: String(e && e.message || e), requests, chromium_stderr: stderr.slice(-2000) }));
	process.exitCode = 1;
} finally {
	try { ws?.close(); } catch {}
	browser.kill('SIGKILL');
	await sleep(200);
	rmSync(dir, { recursive: true, force: true });
}
