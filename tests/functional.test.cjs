'use strict';
// Functional contract 0.3.0: message deletion, attachments and clear-chat semantics.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ryadom-functional-'));
const port = 16280 + Math.floor(Math.random() * 500);
const base = `http://127.0.0.1:${port}`;
const native = 'functional-native-key-0123456789';
let proc, logs = '';

const env = {
 ...process.env,
 RYADOM_PORT: String(port),
 RYADOM_DATA: dir,
 RYADOM_NO_OPEN: '1',
 RYADOM_NATIVE_KEY: native,
 RYADOM_MSG_PER_MIN: '1000',
 RYADOM_UPLOAD_PER_MIN: '1000',
 RYADOM_PAIR_ATTEMPTS_PER_MIN: '100',
 RYADOM_MAX_TOTAL_MB: '64',
 RYADOM_MAX_DEVICE_MB: '64'
};

async function start() {
 const command = process.env.RYADOM_TEST_JAVA || process.env.RYADOM_TEST_EXE || process.execPath;
 const args = process.env.RYADOM_TEST_JAVA
  ? ['-cp', process.env.RYADOM_TEST_CLASSPATH, 'local.ryadom.chat.ServerHarness', path.resolve(__dirname, '../public')]
  : process.env.RYADOM_TEST_EXE ? [] : [path.resolve(__dirname, '../server.cjs')];
 proc = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
 proc.stdout.on('data', x => logs += x);
 proc.stderr.on('data', x => logs += x);
 for (let i = 0; i < 120; i++) {
  try { if ((await fetch(`${base}/api/health`)).ok) return; } catch {}
  await new Promise(r => setTimeout(r, 60));
 }
 throw new Error(logs);
}
async function stop() { if (proc && proc.exitCode === null) { const done = new Promise(r => proc.once('exit', r)); proc.kill(); await done; } }
before(start);
after(async () => { await stop(); fs.rmSync(dir, { recursive: true, force: true }); });

async function req(route, { method = 'GET', body, cookie, headers = {} } = {}) {
 const r = await fetch(base + route, {
  method,
  headers: {
   ...(cookie ? { Cookie: cookie } : {}),
   ...(method !== 'GET' ? { 'X-Ryadom': '1', 'Content-Type': 'application/json' } : {}),
   ...headers
  },
  body: body === undefined ? undefined : (Buffer.isBuffer(body) ? body : JSON.stringify(body))
 });
 let data = null;
 try { data = await r.json(); } catch {}
 return { r, data };
}
async function hostToken() {
 const { r, data } = await req('/api/local/host-token', { method: 'POST', headers: { 'X-Ryadom-Native': native } });
 assert.equal(r.status, 200, logs);
 return data.token;
}
async function login() {
 const token = await hostToken();
 const { r } = await req('/api/host-login', { method: 'POST', body: { token } });
 assert.equal(r.status, 200, logs);
 return r.headers.get('set-cookie').split(';')[0];
}
async function pair(host, name) {
 const state = await req('/api/state', { cookie: host });
 const code = state.data.pairing.code;
 const pending = await req('/api/pair', { method: 'POST', body: { name, code } });
 assert.equal(pending.r.status, 202, JSON.stringify(pending.data) + logs);
 const approve = await req('/api/host/pair/approve', { method: 'POST', body: { requestId: pending.data.requestId }, cookie: host });
 assert.equal(approve.r.status, 200, logs);
 const status = await fetch(`${base}/api/pair/status?requestId=${encodeURIComponent(pending.data.requestId)}`);
 assert.equal(status.status, 200, logs);
 return status.headers.get('set-cookie').split(';')[0];
}
async function text(cookie, value, requestId) {
 const { r, data } = await req('/api/messages', { method: 'POST', body: { text: value, requestId }, cookie });
 assert.equal(r.status, 201, JSON.stringify(data) + logs);
 return data;
}
async function upload(cookie, name, requestId) {
 const r = await fetch(`${base}/api/files?name=${encodeURIComponent(name)}&requestId=${encodeURIComponent(requestId)}`, {
  method: 'POST',
  headers: { Cookie: cookie, 'X-Ryadom': '1', 'Content-Type': 'application/octet-stream' },
  body: Buffer.from('attachment-bytes')
 });
 const data = await r.json();
 assert.equal(r.status, 201, JSON.stringify(data) + logs);
 return data;
}

test('author deletes own text and attachment', async () => {
 const host = await login();
 const device = await pair(host, 'Автор');
 const message = await text(device, 'удалить меня', 'delete-text-1');
 const attachment = await upload(device, 'delete.txt', 'delete-file-1');
 const before = await req('/api/state', { cookie: host });
 const revision = before.data.chat.revision;
 const deletedText = await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: device });
 assert.equal(deletedText.r.status, 200);
 assert.equal(deletedText.data.id, message.id);
 assert.equal(deletedText.data.cleanupPending, false);
 assert.ok(deletedText.data.revision > revision);
 const deletedFile = await req(`/api/messages/${attachment.id}`, { method: 'DELETE', cookie: device });
 assert.equal(deletedFile.r.status, 200);
 assert.ok(deletedFile.data.freedBytes >= 1);
 assert.equal((await req(`/files/${attachment.file.id}`, { cookie: device })).r.status, 404);
 const again = await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: device });
 assert.equal(again.r.status, 200);
 assert.equal(again.data.freedBytes, 0);
 const state = await req('/api/state', { cookie: device });
 assert.ok(!state.data.messages.some(m => m.id === message.id || m.id === attachment.id));
});

test('non-author cannot delete another message', async () => {
 const host = await login();
 const author = await pair(host, 'Автор 2');
 const stranger = await pair(host, 'Чужой');
 const message = await text(author, 'не трогать', 'delete-foreign-1');
 const result = await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: stranger });
 assert.equal(result.r.status, 403);
 assert.equal((await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: author })).r.status, 200);
});

test('host deletes any message', async () => {
 const host = await login();
 const device = await pair(host, 'Клиент');
 const message = await text(device, 'удалить главным', 'delete-host-1');
 const result = await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: host });
 assert.equal(result.r.status, 200);
 assert.equal((await req('/api/messages', { cookie: device })).data.some(m => m.id === message.id), false);
});

test('deleted requestId cannot resurrect a message', async () => {
 const host = await login();
 const device = await pair(host, 'Ретрай');
 const message = await text(device, 'исчезнет', 'delete-retry-1');
 assert.equal((await req(`/api/messages/${message.id}`, { method: 'DELETE', cookie: device })).r.status, 200);
 const retry = await req('/api/messages', { method: 'POST', body: { text: 'вернуть', requestId: 'delete-retry-1' }, cookie: device });
 assert.equal(retry.r.status, 410);
 assert.equal((await req('/api/messages', { cookie: device })).data.some(m => m.id === message.id), false);
});
