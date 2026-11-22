'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { pipeline } = require('node:stream/promises');
const { Transform } = require('node:stream');
const { DatabaseSync } = require('node:sqlite');
const sea = require('node:sea');
const VERSION = '0.4.2';
const PROTOCOL = 4;
const MAX_FILE = 512 * 1024 * 1024;
const PORT = Number(process.env.RYADOM_PORT || 4280);
const DATA = process.env.RYADOM_DATA || path.join(process.env.LOCALAPPDATA || os.homedir(), 'Ryadom');
const NATIVE_KEY = process.env.RYADOM_NATIVE_KEY || '';
const HOST_DEVICE_ID = process.env.RYADOM_DEVICE_ID || '';
const SESSION_DAYS = Number(process.env.RYADOM_SESSION_DAYS || 30);
const HOST_TOKEN_TTL = Number(process.env.RYADOM_HOST_TOKEN_TTL_MS || 120000);
const PAIR_TTL = Number(process.env.RYADOM_PAIR_TTL_MS || 120000);
const PAIR_CODE_TTL = 15 * 60 * 1000;
const MAX_TOTAL_BYTES = Number(process.env.RYADOM_MAX_TOTAL_MB || 20480) * 1024 * 1024;
const MAX_DEVICE_BYTES = Number(process.env.RYADOM_MAX_DEVICE_MB || 8192) * 1024 * 1024;
const MIN_FREE_BYTES = Number(process.env.RYADOM_MIN_FREE_MB || 256) * 1024 * 1024;
const MSG_PER_MIN = Number(process.env.RYADOM_MSG_PER_MIN || 120);
const UPLOAD_PER_MIN = Number(process.env.RYADOM_UPLOAD_PER_MIN || 30);
const MAX_PENDING = Number(process.env.RYADOM_MAX_PENDING || 5);
const PAIR_ATTEMPTS_PER_MIN = Number(process.env.RYADOM_PAIR_ATTEMPTS_PER_MIN || 8);
if (process.env.RYADOM_ROLE === 'client') { startClientProxy(); return; }
const uploads = path.join(DATA, 'files');
fs.mkdirSync(uploads, { recursive: true });
const db = new DatabaseSync(path.join(DATA, 'chat.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, token TEXT UNIQUE NOT NULL, host INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, deviceId TEXT NOT NULL, deviceName TEXT NOT NULL, text TEXT NOT NULL, file TEXT, created TEXT NOT NULL, requestId TEXT UNIQUE NOT NULL);
 CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, deviceId TEXT);
 CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, deviceId TEXT NOT NULL, created TEXT NOT NULL, lastSeen TEXT NOT NULL, expires TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, detail TEXT, ip TEXT, created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT, ownerDeviceId TEXT, created TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0, deletionRevision INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, type TEXT NOT NULL, chatId TEXT NOT NULL, actorId TEXT, status TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL, result TEXT, error TEXT);
 CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS revoked_devices (id TEXT PRIMARY KEY, revokedAt TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_members (chatId TEXT NOT NULL, deviceId TEXT NOT NULL, joinedAt TEXT NOT NULL, lastReadSeq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(chatId,deviceId));
 CREATE TABLE IF NOT EXISTS device_keys (sessionId TEXT NOT NULL, deviceId TEXT NOT NULL, publicKey TEXT NOT NULL, algorithm TEXT NOT NULL, createdAt TEXT NOT NULL, PRIMARY KEY(sessionId,deviceId));`);
function columnExists(table, column) { try { return db.prepare(`PRAGMA table_info(${table})`).all().some(x => x.name === column); } catch { return true; } }
if (!columnExists('files', 'deviceId')) { try { db.exec('ALTER TABLE files ADD COLUMN deviceId TEXT'); } catch {} }
if (!columnExists('messages', 'chatId')) { try { db.exec("ALTER TABLE messages ADD COLUMN chatId TEXT NOT NULL DEFAULT 'legacy'"); } catch {} }
if (!columnExists('messages', 'deletedAt')) { try { db.exec('ALTER TABLE messages ADD COLUMN deletedAt TEXT'); } catch {} }
if (!columnExists('messages', 'deletedBy')) { try { db.exec('ALTER TABLE messages ADD COLUMN deletedBy TEXT'); } catch {} }
if (!columnExists('files', 'chatId')) { try { db.exec("ALTER TABLE files ADD COLUMN chatId TEXT NOT NULL DEFAULT 'legacy'"); } catch {} }
if (!columnExists('files', 'messageId')) { try { db.exec('ALTER TABLE files ADD COLUMN messageId TEXT'); } catch {} }
if (!columnExists('files', 'state')) { try { db.exec("ALTER TABLE files ADD COLUMN state TEXT NOT NULL DEFAULT 'ready'"); } catch {} }
if (!columnExists('messages', 'encrypted')) { try { db.exec('ALTER TABLE messages ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0'); } catch {} }
if (!columnExists('files', 'encrypted')) { try { db.exec('ALTER TABLE files ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0'); } catch {} }
if (!columnExists('chats', 'deletionRevision')) { try { db.exec('ALTER TABLE chats ADD COLUMN deletionRevision INTEGER NOT NULL DEFAULT 0'); } catch {} }
if (!columnExists('chats', 'sessionId')) { try { db.exec("ALTER TABLE chats ADD COLUMN sessionId TEXT NOT NULL DEFAULT ''"); } catch {} }
if (!columnExists('chats', 'term')) { try { db.exec('ALTER TABLE chats ADD COLUMN term INTEGER NOT NULL DEFAULT 0'); } catch {} }
if (!columnExists('chats', 'hostDeviceId')) { try { db.exec('ALTER TABLE chats ADD COLUMN hostDeviceId TEXT'); } catch {} }
db.prepare("INSERT OR IGNORE INTO chats (id,type,title,ownerDeviceId,created,revision,deletionRevision,epoch) VALUES ('legacy','legacy','Свои устройства',NULL,?,0,0,0)").run(new Date().toISOString());
db.exec("UPDATE messages SET chatId='legacy' WHERE chatId IS NULL OR chatId=''");
db.exec("UPDATE files SET chatId='legacy' WHERE chatId IS NULL OR chatId=''");
db.exec("UPDATE files SET state='ready' WHERE state IS NULL OR state=''");
for (const row of db.prepare("SELECT id,file FROM messages WHERE file IS NOT NULL AND deletedAt IS NULL").all()) {
 try { const file = JSON.parse(row.file); if (file && file.id) db.prepare('UPDATE files SET messageId=? WHERE id=?').run(row.id, file.id); } catch {}
}
db.exec('PRAGMA user_version=4');
function metaValue(key){return db.prepare('SELECT value FROM meta WHERE key=?').get(key)?.value || '';}
function setMeta(key,value){db.prepare('INSERT INTO meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,value);}
if(!metaValue('group_id')) setMeta('group_id', crypto.randomBytes(16).toString('hex'));
function importTrustRoster() {
 try {
  const file = path.join(DATA, 'trust-roster.json');
  if (!fs.existsSync(file)) return;
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const id of Array.isArray(value.revoked) ? value.revoked : []) {
   if (!/^d1-[0-9a-f]{32}$/.test(String(id || ''))) continue;
   db.prepare('INSERT OR IGNORE INTO revoked_devices (id,revokedAt) VALUES (?,?)').run(id, now());
   db.prepare('DELETE FROM devices WHERE id=? AND host=0').run(id);
   db.prepare('DELETE FROM sessions WHERE deviceId=?').run(id);
  }
  if (typeof value.groupId === 'string' && /^[0-9a-f]{32}$/.test(value.groupId)) setMeta('group_id', value.groupId);
   for (const device of Array.isArray(value.devices) ? value.devices : []) {
   if (!device || !/^d1-[0-9a-f]{32}$/.test(String(device.id || '')) || !/^[0-9a-f]{64}$/.test(String(device.tokenHash || ''))) continue;
   if (db.prepare('SELECT id FROM revoked_devices WHERE id=?').get(device.id)) continue;
   if (db.prepare('SELECT id FROM devices WHERE id=?').get(device.id)) continue;
   db.prepare('INSERT INTO devices (id,name,token,host,created) VALUES (?,?,?,0,?)').run(device.id, cleanName(device.name).slice(0, 40), device.tokenHash, now());
  }
 } catch (e) { console.error('Не удалось импортировать trust roster:', e.message); }
}

const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const now = () => new Date().toISOString();
const iso = ms => new Date(ms).toISOString();
function chatRow(id = 'legacy') { return db.prepare('SELECT * FROM chats WHERE id=?').get(id); }
function bumpRevision(chatId = 'legacy') { db.prepare('UPDATE chats SET revision=revision+1 WHERE id=?').run(chatId); return chatRow(chatId).revision; }
function bumpDeletion(chatId = 'legacy') { db.prepare('UPDATE chats SET revision=revision+1,deletionRevision=deletionRevision+1 WHERE id=?').run(chatId); return chatRow(chatId).revision; }
function operationResponse(row) {
 let result = {}; try { result = JSON.parse(row.result || '{}'); } catch {}
 return { id: row.id, operationId: row.id, type: row.type, chatId: row.chatId, status: row.status, createdAt: row.createdAt, updatedAt: row.updatedAt, error: row.error, ...result };
}
function reconcileClearOperations() {
 const pendingFiles = db.prepare("SELECT count(*) AS n FROM files WHERE state='deleting'").get().n;
 let pendingParts = 0; try { pendingParts = fs.readdirSync(uploads).filter(name => name.endsWith('.part')).length; } catch {}
 if (pendingFiles > 0 || pendingParts > 0) return;
 for (const row of db.prepare("SELECT * FROM operations WHERE type='clear' AND status IN ('deleting','partial')").all()) {
  let result = {}; try { result = JSON.parse(row.result || '{}'); } catch {}
  result.cleanupPending = false;
  result.tempFiles = 0;
  db.prepare("UPDATE operations SET status='done',updatedAt=?,result=?,error=NULL WHERE id=?").run(now(), JSON.stringify(result), row.id);
 }
}
function cleanClearFiles(files, tempNames) {
 let freedBytes = 0, pending = false;
 for (const file of files) {
  try {
   fs.rmSync(path.join(uploads, file.id), { force: true });
   db.prepare('DELETE FROM files WHERE id=?').run(file.id);
   freedBytes += file.size;
  } catch { pending = true; }
 }
 let remaining = 0;
 for (const name of tempNames) {
  try { fs.rmSync(path.join(uploads, name), { force: true }); } catch { remaining++; }
 }
 return { freedBytes, pending, tempFiles: remaining };
}
const address = x => String(x || '').replace(/^::ffff:/, '');
function safeEqual(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }
function isPrivate(ip) {
 ip = address(ip);
 if (ip === '::1' || ip === '127.0.0.1') return true;
 const p = ip.split('.').map(Number);
 return p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255) && (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254));
}
function lanAddresses() {
 if (process.env.RYADOM_LAN_STATE) { try { const value = JSON.parse(fs.readFileSync(process.env.RYADOM_LAN_STATE, 'utf8')); return value.addresses.filter(isPrivate); } catch { return []; } }
 const entries = Object.entries(os.networkInterfaces()).flatMap(([name, items]) => (items || []).map(item => ({ ...item, name }))).filter(x => x.family === 'IPv4' && !x.internal && isPrivate(x.address));
 return [...new Set(entries.filter(a => !/virtual|vethernet|wsl|docker|vpn|tailscale|tap|loopback|happ|xray|tun/i.test(a.name)).map(x => x.address))];
}
function error(status, message) { return Object.assign(new Error(message), { status }); }
function send(res, status, data, headers = {}) {
 res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
 res.end(JSON.stringify(data));
}
async function json(req) {
 let size = 0; const chunks = [];
 for await (const chunk of req) { size += chunk.length; if (size > 65536) throw error(413, 'Слишком длинный запрос'); chunks.push(chunk); }
 try { return JSON.parse(Buffer.concat(chunks).toString()); } catch { throw error(400, 'Некорректный запрос'); }
}
function logEvent(type, detail, ip) { try { db.prepare('INSERT INTO events (type,detail,ip,created) VALUES (?,?,?,?)').run(type, detail || null, ip || null, now()); } catch {} }
function rawCookie(req) {
 const value = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('ryadom_sid='));
 return value ? value.slice(11) : '';
}
function sessionCookie(raw) {
 return `ryadom_sid=${raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}
function clearCookie() { return 'ryadom_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'; }
function newSession(deviceId) {
 const raw = crypto.randomBytes(32).toString('hex');
 const expires = iso(Date.now() + SESSION_DAYS * 86400000);
 db.prepare('INSERT INTO sessions (token,deviceId,created,lastSeen,expires) VALUES (?,?,?,?,?)').run(sha(raw), deviceId, now(), now(), expires);
 return raw;
}
function device(req) {
 const raw = rawCookie(req);
 if (!raw) return null;
 const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(sha(raw));
 if (!s) return null;
 if (Date.parse(s.expires) < Date.now()) { db.prepare('DELETE FROM sessions WHERE token=?').run(s.token); return null; }
 const d = db.prepare('SELECT * FROM devices WHERE id=?').get(s.deviceId);
 if (!d) { db.prepare('DELETE FROM sessions WHERE token=?').run(s.token); return null; }
 try { if (Date.now() - Date.parse(s.lastSeen) > 60000) db.prepare('UPDATE sessions SET lastSeen=? WHERE token=?').run(now(), s.token); } catch {}
 Object.defineProperty(d, 'sessionToken', { value: s.token });
 Object.defineProperty(d, 'sessionExpires', { value: Date.parse(s.expires) });
 return d;
}
function publicDevices() {
 const rows = db.prepare("SELECT d.id,d.name,d.host,d.created,(SELECT MAX(s.lastSeen) FROM sessions s WHERE s.deviceId=d.id) AS lastSeen FROM devices d ORDER BY d.created").all();
 return rows.map(d => ({ ...d, host: !!d.host, online: [...clients.values()].some(c => c.deviceId === d.id) }));
}
function broadcast(type, value, hostOnly = false) {
 const data = `event: ${type}\ndata: ${JSON.stringify(value)}\n\n`;
 for (const [res, c] of clients) {
  if (hostOnly && !c.host) continue;
  if (c.sessionExpires && c.sessionExpires <= Date.now()) { try { res.end(); } catch {} clients.delete(res); continue; }
  try { res.write(data); if (res.writableLength > 1024 * 1024) { res.destroy(); clients.delete(res); } } catch { clients.delete(res); }
 }
}
function closeClients(match, type) {
 for (const [res, c] of clients) {
  if (match && !match(c)) continue;
  try { res.write(`event: ${type || 'revoked'}\ndata: {}\n\n`); res.end(); } catch {}
  clients.delete(res);
 }
 broadcast('devices', publicDevices());
}
function message(row) { return { ...row, encrypted: !!row.encrypted, file: row.file ? JSON.parse(row.file) : null, sessionId: chatRow().sessionId, term: chatRow().term }; }
function addMessage(d, text, file, requestId, announce = true, chatId = 'legacy', encrypted = 0) {
 if (sessionEnding) throw error(409, 'Чат завершается. Новые сообщения недоступны');
 const old = db.prepare('SELECT * FROM messages WHERE requestId=?').get(requestId);
 if (old) { if (old.deletedAt) throw error(410, 'Сообщение было удалено'); if (old.deviceId !== d.id) throw error(409, 'Повторите отправку'); return message(old); }
 const id = crypto.randomUUID();
 db.prepare('INSERT INTO messages (id,deviceId,deviceName,text,file,created,requestId,chatId,encrypted) VALUES (?,?,?,?,?,?,?,?,?)').run(id, d.id, d.name, text, file ? JSON.stringify(file) : null, now(), requestId, chatId, encrypted ? 1 : 0);
 const result = message(db.prepare('SELECT * FROM messages WHERE id=?').get(id));
 result.revision = bumpRevision(chatId);
 result.epoch = chatRow(chatId).epoch;
 if (announce) broadcast('message', result); return result;
}
function cleanName(value) { return String(value || '').replace(/[\x00-\x1f\x7f/\\]/g, '').trim().slice(0, 180) || 'Файл'; }
function privateChatId(first, second) { return 'private-' + sha([first, second].sort().join(':')).slice(0, 24); }
function chatAccess(deviceRow, chatId) {
 const chat = chatRow(chatId);
 if (!chat) throw error(404, 'Чат не найден');
 if (chatId === 'legacy') return chat;
 const member = db.prepare('SELECT 1 FROM chat_members WHERE chatId=? AND deviceId=?').get(chatId, deviceRow.id);
 if (!member) throw error(403, 'Нет доступа к чату');
 return chat;
}
function chatSummary(deviceRow, chat) {
 const member = chat.id === 'legacy' ? null : db.prepare('SELECT lastReadSeq FROM chat_members WHERE chatId=? AND deviceId=?').get(chat.id, deviceRow.id);
 const last = db.prepare('SELECT id,deviceId,text,file,created,seq,encrypted FROM messages WHERE chatId=? AND deletedAt IS NULL ORDER BY seq DESC LIMIT 1').get(chat.id);
 const unread = chat.id === 'legacy' ? 0 : db.prepare('SELECT count(*) AS n FROM messages WHERE chatId=? AND deletedAt IS NULL AND seq>? AND deviceId<>?').get(chat.id, member ? member.lastReadSeq : 0, deviceRow.id).n;
 const members = chat.id === 'legacy' ? [] : db.prepare('SELECT d.id,d.name FROM chat_members m JOIN devices d ON d.id=m.deviceId WHERE m.chatId=? ORDER BY m.joinedAt').all(chat.id);
 return { id: chat.id, type: chat.type, title: chat.title, sessionId: chat.sessionId, revision: chat.revision, epoch: chat.epoch, unread, last: last ? { id: last.id, deviceId: last.deviceId, text: last.encrypted ? '' : last.text, encrypted: !!last.encrypted, created: last.created, seq: last.seq } : null, members };
}
function chatsFor(deviceRow) {
 const rows = db.prepare("SELECT * FROM chats WHERE id='legacy' OR id IN (SELECT chatId FROM chat_members WHERE deviceId=?) ORDER BY created").all(deviceRow.id);
 return rows.map(chat => chatSummary(deviceRow, chat));
}
function sniff(file) {
 const fd = fs.openSync(file, 'r'); const b = Buffer.alloc(32); try { fs.readSync(fd, b, 0, 32, 0); } finally { fs.closeSync(fd); }
 if (b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return 'image/png';
 if (b[0] === 255 && b[1] === 216 && b[2] === 255) return 'image/jpeg';
 if (/^GIF8[79]a/.test(b.toString('ascii', 0, 6))) return 'image/gif';
 if (b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
 if (b.toString('ascii', 4, 8) === 'ftyp') return /^hei|^mif|^avi/.test(b.toString('ascii', 8, 12)) ? 'application/octet-stream' : 'video/mp4';
 if (b.subarray(0, 4).equals(Buffer.from([26, 69, 223, 163]))) return 'video/webm';
 return 'application/octet-stream';
}
function getAsset(name) { return sea.isSea() ? Buffer.from(sea.getAsset(name)) : fs.readFileSync(path.join(__dirname, 'public', name)); }
const assets = new Map(['index.html', 'app.js', 'e2ee.js', 'style.css', 'icon.svg'].map(x => [x, getAsset(x)]));

const clients = new Map();
const attempts = new Map();
const activeUploads = new Map();
const uploadJobs = new Set();
const uploadMeta = new Map();
const hostTokens = new Map();
const pendingPairs = new Map();
const rate = new Map();

function newCode() { return crypto.randomInt(10000000, 100000000).toString(); }
let pairing = { code: newCode(), expires: Date.now() + PAIR_CODE_TTL };
function pairingDisabled() { return pairing.expires === 0 || Date.now() > pairing.expires; }
function hostDevice() {
 let d = db.prepare('SELECT * FROM devices WHERE host=1').get();
 if (!d) {
  db.prepare('INSERT INTO devices (id,name,token,host,created) VALUES (?,?,?,1,?)').run(HOST_DEVICE_ID || crypto.randomUUID(), 'Мой компьютер', sha(crypto.randomBytes(32).toString('hex')), now());
  d = db.prepare('SELECT * FROM devices WHERE host=1').get();
 }
 if (HOST_DEVICE_ID && d.id !== HOST_DEVICE_ID && !db.prepare('SELECT id FROM devices WHERE id=?').get(HOST_DEVICE_ID)) {
  db.exec('BEGIN');
  try {
   db.prepare('UPDATE sessions SET deviceId=? WHERE deviceId=?').run(HOST_DEVICE_ID, d.id);
   db.prepare('UPDATE devices SET id=? WHERE id=?').run(HOST_DEVICE_ID, d.id);
   db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  d = db.prepare('SELECT * FROM devices WHERE host=1').get();
 }
 return d;
}
const sessionMarker = path.join(DATA, 'runtime.json');
let sessionEnding = false;
function clearEphemeralData() {
 let pending = false;
 try {
  for (const name of fs.readdirSync(uploads)) {
   try { fs.rmSync(path.join(uploads, name), { force: true, recursive: true }); } catch { pending = true; }
  }
 } catch { pending = true; }
 db.exec("DELETE FROM messages; DELETE FROM files; DELETE FROM operations; DELETE FROM chat_members; DELETE FROM device_keys; DELETE FROM chats WHERE id<>'legacy';");
 db.prepare('UPDATE chats SET revision=0,deletionRevision=0,epoch=0 WHERE id=?').run('legacy');
 return pending;
}
function writeSessionMarker(value) {
 const temporary = sessionMarker + '.tmp';
 const fd = fs.openSync(temporary, 'w');
 try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
 fs.renameSync(temporary, sessionMarker);
}
function beginEphemeralSession() {
 let crashed = false;
 try { crashed = ['ACTIVE', 'ENDING'].includes(JSON.parse(fs.readFileSync(sessionMarker, 'utf8')).state); } catch {}
 const host = hostDevice();
 const pending = clearEphemeralData();
 if (pending) {
  try { writeSessionMarker({ state: 'ENDING', sessionId: chatRow().sessionId || '', term: chatRow().term || 0, hostDeviceId: HOST_DEVICE_ID || host.id, created: now() }); } catch {}
  throw new Error('Не удалось удалить остатки предыдущей истории. Закройте файлы Рядом и запустите снова.');
 }
 const chat = chatRow();
 const sessionId = crypto.randomBytes(16).toString('hex');
 const term = (chat.term || 0) + 1;
 db.prepare('UPDATE chats SET sessionId=?,term=?,hostDeviceId=? WHERE id=?').run(sessionId, term, HOST_DEVICE_ID || host.id, 'legacy');
 writeSessionMarker({ state: 'ACTIVE', sessionId, term, hostDeviceId: HOST_DEVICE_ID || host.id, created: now() });
 if (crashed) console.log('Предыдущая сессия Рядом завершилась аварийно; остатки истории очищены.');
 return { sessionId, term, hostDeviceId: HOST_DEVICE_ID || host.id };
}
function endEphemeralSession() {
 if (sessionEnding) return;
 sessionEnding = true;
 const chat = chatRow();
 try { broadcast('session_ending', { sessionId: chat.sessionId, reason: 'shutdown' }); } catch {}
 for (const meta of uploadMeta.values()) try { meta.req.destroy(); } catch {}
 const pending = clearEphemeralData();
 try { if (!pending) fs.rmSync(sessionMarker, { force: true }); } catch {}
}
function prunePairs() {
 const nowMs = Date.now();
 for (const [id, p] of pendingPairs) if (p.expires < nowMs) pendingPairs.delete(id);
}
function pendingList() {
 prunePairs();
 return [...pendingPairs.entries()].filter(([, p]) => p.status === 'pending').map(([requestId, p]) => ({ requestId, name: p.name, ip: p.ip, created: p.created }));
}
function allowRate(deviceId, kind, limit) {
 const key = deviceId + ':' + kind; const nowMs = Date.now();
 let list = rate.get(key); if (!list) { list = []; rate.set(key, list); }
 while (list.length && nowMs - list[0] > 60000) list.shift();
 if (list.length >= limit) return false;
 list.push(nowMs); return true;
}
function totalBytes() { try { return db.prepare('SELECT COALESCE(SUM(size),0) AS n FROM files').get().n; } catch { return 0; } }
function deviceBytes(deviceId) { try { return db.prepare('SELECT COALESCE(SUM(size),0) AS n FROM files WHERE deviceId=?').get(deviceId).n; } catch { return 0; } }
// Quota reservations close the window between separate parallel uploads checking the same totals.
let reservedTotal = 0;
const reservedDevice = new Map();
function reserveBytes(deviceId, size) {
 const total = totalBytes(), own = deviceBytes(deviceId), reservedOwn = reservedDevice.get(deviceId) || 0;
 if (total + reservedTotal + size > MAX_TOTAL_BYTES || own + reservedOwn + size > MAX_DEVICE_BYTES) throw error(507, 'Хранилище заполнено. Удалите старые файлы на главном устройстве');
 if (freeDiskBytes() < size + MIN_FREE_BYTES + reservedTotal) throw error(507, 'На главном устройстве мало свободного места');
 reservedTotal += size; reservedDevice.set(deviceId, reservedOwn + size);
 let released = false;
 return () => {
  if (released) return; released = true;
  reservedTotal = Math.max(0, reservedTotal - size);
  const left = (reservedDevice.get(deviceId) || 0) - size;
  if (left > 0) reservedDevice.set(deviceId, left); else reservedDevice.delete(deviceId);
 };
}
function freeDiskBytes() { try { const s = fs.statfsSync(DATA); return Number(s.bavail) * Number(s.bsize); } catch { return Number.MAX_SAFE_INTEGER; } }
function native(req) {
 if (!NATIVE_KEY) return false;
 const header = req.headers['x-ryadom-native'];
 if (typeof header === 'string' && safeEqual(header, NATIVE_KEY)) return true;
 return false;
}
function loopback(req) { return !req.socket.ryadomPeer && ['127.0.0.1', '::1'].includes(address(req.socket.remoteAddress)); }
function hostSession(req) { const d = device(req); return !!(d && d.host); }

const server = http.createServer(async (req, res) => {
 res.setHeader('X-Content-Type-Options', 'nosniff');
 res.setHeader('Referrer-Policy', 'no-referrer');
 res.setHeader('X-Frame-Options', 'DENY');
 res.setHeader('Cache-Control', 'no-store');
 res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
 try {
  const peer = req.socket.ryadomPeer || req.socket.remoteAddress;
  if (!isPrivate(peer)) throw error(403, 'Доступ только из локальной сети');
  const host = req.headers.host || '';
  if (![...lanAddresses(), '127.0.0.1', 'localhost'].some(ip => host === `${ip}:${PORT}`)) throw error(403, 'Недопустимый адрес');
  if (req.headers.origin && req.headers.origin !== `http://${host}`) throw error(403, 'Недопустимый источник');
  if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-ryadom'] !== '1') throw error(403, 'Недопустимый запрос');
  const url = new URL(req.url, `http://${host}`); const route = url.pathname;
  if (route.startsWith('/api/local/')) {
   if (req.socket.ryadomPeer || address(req.socket.remoteAddress) !== '127.0.0.1') throw error(403, 'Только на этом устройстве');
   if (route === '/api/local/choose-role' && req.method === 'POST' && process.env.RYADOM_ROLE_SIGNAL) {
    if (!native(req) && !hostSession(req)) throw error(403, 'Нужен native-ключ или сессия главного');
    fs.writeFileSync(process.env.RYADOM_ROLE_SIGNAL, 'choose');
    return send(res, 200, { ok: true });
   }
   if (!native(req)) throw error(403, 'Нужен native-ключ');
   if (route === '/api/local/status' && req.method === 'GET') return send(res, 200, { app: 'ryadom', version: VERSION, role: 'host', protocol: PROTOCOL });
   if (route === '/api/local/host-token' && req.method === 'POST') {
    const token = crypto.randomBytes(32).toString('hex');
    hostTokens.set(token, Date.now() + HOST_TOKEN_TTL);
    return send(res, 200, { token, expires: HOST_TOKEN_TTL });
   }
   if (route === '/api/local/quit' && req.method === 'POST') { send(res, 200, { ok: true }); setTimeout(shutdown, 200); return; }
   throw error(404, 'Не найдено');
  }
  if (req.method === 'GET' && ['/', '/app.js', '/style.css', '/icon.svg'].includes(route)) {
   const name = route === '/' ? 'index.html' : route.slice(1);
   res.writeHead(200, { 'Content-Type': { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8', svg: 'image/svg+xml' }[name.split('.').pop()] }); return res.end(assets.get(name));
  }
  if (route === '/api/health' && req.method === 'GET') { const chat = chatRow(); return send(res, 200, { app: 'ryadom', version: VERSION, protocol: PROTOCOL, name: os.hostname(), tls: process.env.RYADOM_TLS === '1' ? '1' : '0', fingerprint: process.env.RYADOM_TLS_FINGERPRINT || undefined, sessionId: chat.sessionId, term: chat.term, hostDeviceId: chat.hostDeviceId }); }
  if (route === '/api/host-login' && req.method === 'POST') {
   if (!loopback(req)) throw error(403, 'Откройте чат на главном устройстве');
   const body = await json(req);
   if (typeof body.token !== 'string' || !body.token) throw error(403, 'Откройте чат на главном устройстве');
   const expires = hostTokens.get(body.token);
   hostTokens.delete(body.token);
   if (!expires || expires < Date.now()) throw error(403, 'Ссылка входа устарела. Откройте приложение заново');
   const d = hostDevice();
   logEvent('host_login', d.name, address(peer));
   return send(res, 200, { ok: true, device: { id: d.id, name: d.name, host: true } }, { 'Set-Cookie': sessionCookie(newSession(d.id)) });
  }
  if (route === '/api/auth' && req.method === 'POST') {
   const body = await json(req);
   if (Number(body.protocol) !== PROTOCOL) throw error(426, 'Обновите Рядом на этом устройстве до протокола 4');
   const deviceId = String(body.deviceId || '').toLowerCase();
   const token = String(body.deviceToken || '').toLowerCase();
   if (!/^d1-[0-9a-f]{32}$/.test(deviceId) || !/^[0-9a-f]{64}$/.test(token)) throw error(400, 'Некорректная идентичность устройства');
   const d = db.prepare('SELECT * FROM devices WHERE id=? AND host=0').get(deviceId);
   if (!d || !safeEqual(d.token, sha(token))) throw error(401, 'Устройство не remembered. Подключитесь по коду');
   logEvent('device_auth', d.name, address(peer));
   return send(res, 200, { ok: true, device: { id: d.id, name: d.name, host: false } }, { 'Set-Cookie': sessionCookie(newSession(d.id)) });
  }
  if (route === '/api/pair' && req.method === 'POST') {
   const ip = address(peer); const entry = attempts.get(ip) || { count: 0, until: Date.now() + 60000 };
   if (Date.now() > entry.until) { entry.count = 0; entry.until = Date.now() + 60000; }
   attempts.set(ip, entry); if (++entry.count > PAIR_ATTEMPTS_PER_MIN) throw error(429, 'Слишком много попыток. Подождите минуту');
   prunePairs();
   const body = await json(req);
   if (Number(body.protocol) !== PROTOCOL) throw error(426, 'Обновите Рядом на этом устройстве до протокола 4');
   if (pairingDisabled()) throw error(403, 'Код истёк. Создайте новый код на главном устройстве');
   if (!safeEqual(String(body.code || '').replace(/\s/g, ''), pairing.code)) throw error(403, 'Неверный код подключения');
   const name = cleanName(body.name).slice(0, 40); if (!body.name?.trim()) throw error(400, 'Укажите имя устройства');
   const deviceId = String(body.deviceId || '').toLowerCase();
   const token = String(body.deviceToken || '').toLowerCase();
   let tokenHash = null;
   if (deviceId || token) {
    if (!/^d1-[0-9a-f]{32}$/.test(deviceId) || !/^[0-9a-f]{64}$/.test(token)) throw error(400, 'Некорректная идентичность устройства');
    if (db.prepare('SELECT id FROM revoked_devices WHERE id=?').get(deviceId)) throw error(403, 'Устройство отозвано на главном');
    const existing = db.prepare('SELECT * FROM devices WHERE id=?').get(deviceId);
    if (existing && (existing.host || !safeEqual(existing.token, sha(token)))) throw error(409, 'Идентичность устройства не совпадает');
    tokenHash = sha(token);
   }
   if (pendingList().length >= MAX_PENDING) throw error(429, 'Слишком много запросов на подключение. Подождите');
   pairing = { code: newCode(), expires: Date.now() + PAIR_CODE_TTL };
   broadcast('pairing', { code: pairing.code, expires: pairing.expires }, true);
   const requestId = crypto.randomBytes(16).toString('hex');
   pendingPairs.set(requestId, { requestId, name, ip, created: now(), expires: Date.now() + PAIR_TTL, status: 'pending', deviceId: deviceId || null, tokenHash });
   logEvent('pair_request', name, ip);
   broadcast('pair_request', { requestId, name, ip, created: now() }, true);
   return send(res, 202, { pending: true, requestId });
  }
  if (route === '/api/pair/status' && req.method === 'GET') {
   prunePairs();
   const requestId = url.searchParams.get('requestId') || '';
   const p = pendingPairs.get(requestId);
   if (!p || !safeEqual(address(peer), p.ip)) throw error(404, 'Запрос не найден');
   if (p.status === 'pending') return send(res, 202, { pending: true });
   if (p.status === 'rejected') throw error(403, 'Подключение отклонено на главном устройстве');
   const d = db.prepare('SELECT * FROM devices WHERE id=?').get(p.deviceId);
   if (!d) throw error(410, 'Устройство удалено');
   if (!p.sessionCookie) p.sessionCookie = sessionCookie(p.rawToken || newSession(d.id));
   return send(res, 200, { ok: true, device: { id: d.id, name: d.name, host: false } }, { 'Set-Cookie': p.sessionCookie });
  }
  const d = device(req); if (!d) throw error(401, 'Подключите устройство по коду');
  if (sessionEnding && req.method !== 'GET' && route !== '/api/host/stop' && route !== '/api/logout') throw error(409, 'Чат завершается. Дождитесь остановки');
  if (route === '/api/chats' && req.method === 'GET') return send(res, 200, { chats: chatsFor(d) });
  if (route === '/api/chats' && req.method === 'POST') {
   const body = await json(req);
   if (body.type !== 'private') throw error(400, 'Пока поддерживаются только личные чаты');
   const peerId = String(body.peerDeviceId || '');
   if (!peerId || peerId === d.id) throw error(400, 'Выберите другое устройство');
   const peer = db.prepare('SELECT id,name FROM devices WHERE id=?').get(peerId);
   if (!peer) throw error(404, 'Устройство не найдено');
   const id = privateChatId(d.id, peerId);
   let chat = chatRow(id);
   if (!chat) {
    db.prepare("INSERT INTO chats (id,type,title,ownerDeviceId,created,revision,deletionRevision,epoch,sessionId,term,hostDeviceId) VALUES (?,?,?,?,?,0,0,0,?,?,?)").run(id, 'private', peer.name, d.id, now(), chatRow().sessionId, chatRow().term, chatRow().hostDeviceId);
    db.prepare('INSERT OR IGNORE INTO chat_members (chatId,deviceId,joinedAt,lastReadSeq) VALUES (?,?,?,0)').run(id, d.id, now());
    db.prepare('INSERT OR IGNORE INTO chat_members (chatId,deviceId,joinedAt,lastReadSeq) VALUES (?,?,?,0)').run(id, peerId, now());
    logEvent('private_chat_created', d.name + ' ↔ ' + peer.name, '');
    chat = chatRow(id);
   }
   return send(res, 201, { chat: chatSummary(d, chat) });
  }
  if (route.startsWith('/api/chats/') && route.endsWith('/read') && req.method === 'POST') {
   const chatId = decodeURIComponent(route.slice('/api/chats/'.length, -'/read'.length));
   chatAccess(d, chatId);
   const body = await json(req);
   const seq = Math.max(0, Number(body.seq) || 0);
   if (chatId !== 'legacy') db.prepare('UPDATE chat_members SET lastReadSeq=MAX(lastReadSeq,?) WHERE chatId=? AND deviceId=?').run(seq, chatId, d.id);
   return send(res, 200, { ok: true, chatId, seq });
  }
  if (route === '/api/keys' && req.method === 'POST') {
   const body = await json(req);
   const publicKey = String(body.publicKey || '');
   const algorithm = String(body.algorithm || 'ECDH-P256').slice(0, 40);
   if (publicKey.length < 20 || publicKey.length > 4096) throw error(400, 'Некорректный публичный ключ');
   db.prepare('INSERT INTO device_keys (sessionId,deviceId,publicKey,algorithm,createdAt) VALUES (?,?,?,?,?) ON CONFLICT(sessionId,deviceId) DO UPDATE SET publicKey=excluded.publicKey,algorithm=excluded.algorithm,createdAt=excluded.createdAt').run(chatRow().sessionId, d.id, publicKey, algorithm, now());
   return send(res, 200, { ok: true });
  }
  if (route === '/api/keys' && req.method === 'GET') {
   const ids = String(url.searchParams.get('deviceIds') || '').split(',').map(x => x.trim()).filter(x => /^[a-zA-Z0-9_-]{1,80}$/.test(x));
   const keys = ids.length ? db.prepare(`SELECT deviceId,publicKey,algorithm FROM device_keys WHERE sessionId=? AND deviceId IN (${ids.map(() => '?').join(',')})`).all(chatRow().sessionId, ...ids) : [];
   return send(res, 200, { keys });
  }
  if (route === '/api/trust/roster' && req.method === 'GET') {
   const devices = db.prepare('SELECT id,name,token,created FROM devices WHERE host=0 ORDER BY created').all().map(x => ({ id: x.id, name: x.name, tokenHash: x.token, created: x.created }));
   const revoked = db.prepare('SELECT id FROM revoked_devices ORDER BY revokedAt').all().map(x => x.id);
   return send(res, 200, { groupId: metaValue('group_id'), devices, revoked });
  }
  if (route === '/api/state' && req.method === 'GET') {
   const chat = chatRow();
   const messages = db.prepare("SELECT * FROM messages WHERE deletedAt IS NULL AND chatId='legacy' ORDER BY seq DESC LIMIT 100").all().reverse().map(message);
   const state = { me: { id: d.id, name: d.name, host: !!d.host }, chat: { id: chat.id, sessionId: chat.sessionId, term: chat.term, hostDeviceId: chat.hostDeviceId, revision: chat.revision, deletionRevision: chat.deletionRevision, epoch: chat.epoch }, chats: chatsFor(d), devices: publicDevices(), messages, maxFile: MAX_FILE, total: db.prepare("SELECT count(*) AS n FROM messages WHERE deletedAt IS NULL AND chatId='legacy'").get().n, server: { addresses: lanAddresses().map(ip => `http://${ip}:${PORT}`), version: VERSION, protocol: PROTOCOL, direct: !!NATIVE_KEY, localControls: !req.socket.ryadomPeer && !!process.env.RYADOM_ROLE_SIGNAL, tls: process.env.RYADOM_TLS === '1', fingerprint: process.env.RYADOM_TLS_FINGERPRINT || undefined } };
   if (d.host) { state.pairing = pairing; state.pendingRequests = pendingList(); state.storage = { totalBytes: MAX_TOTAL_BYTES, usedBytes: totalBytes(), freeBytes: freeDiskBytes() }; }
   return send(res, 200, state);
  }
  if (route === '/api/messages' && req.method === 'GET') {
   const chatId = url.searchParams.get('chatId') || 'legacy';
   chatAccess(d, chatId);
   if (url.searchParams.has('after')) {
    const after = Math.max(0, Number(url.searchParams.get('after')) || 0);
    return send(res, 200, db.prepare('SELECT * FROM messages WHERE deletedAt IS NULL AND chatId=? AND seq>? ORDER BY seq LIMIT 100').all(chatId, after).map(message));
   }
   const before = Number(url.searchParams.get('before')) || Number.MAX_SAFE_INTEGER;
   return send(res, 200, db.prepare('SELECT * FROM messages WHERE deletedAt IS NULL AND chatId=? AND seq<? ORDER BY seq DESC LIMIT 100').all(chatId, before).reverse().map(message));
  }
  if (route === '/api/messages' && req.method === 'POST') {
   if (!allowRate(d.id, 'msg', MSG_PER_MIN)) throw error(429, 'Слишком часто. Подождите минуту');
   const body = await json(req); const text = String(body.text || '').trim();
   const chatId = String(body.chatId || 'legacy');
   chatAccess(d, chatId);
   const limit = body.encrypted ? 64000 : 12000;
   if (!text || text.length > limit) throw error(400, `Сообщение должно содержать от 1 до ${limit} символов`);
   const requestId = String(body.requestId || crypto.randomUUID()).slice(0, 80);
   return send(res, 201, addMessage(d, text, null, requestId, true, chatId, body.encrypted ? 1 : 0));
  }
  if (route.startsWith('/api/messages/') && req.method === 'DELETE') {
   const id = decodeURIComponent(route.slice('/api/messages/'.length));
   if (!id || id.length > 80) throw error(400, 'Некорректное сообщение');
   const row = db.prepare('SELECT * FROM messages WHERE id=?').get(id);
   if (!row) throw error(404, 'Сообщение не найдено');
   if (row.deletedAt) {
    const pending = db.prepare("SELECT id FROM files WHERE messageId=? AND state='deleting'").get(id);
    return send(res, 200, { ok: true, id, chatId: 'legacy', revision: chatRow().revision, deletionRevision: chatRow().deletionRevision, freedBytes: 0, cleanupPending: !!pending });
   }
   if (row.deviceId !== d.id && !d.host) throw error(403, 'Удалить можно только своё сообщение');
   let file = null;
   try { file = row.file ? JSON.parse(row.file) : null; } catch {}
   const fileRow = file && file.id ? db.prepare('SELECT * FROM files WHERE id=?').get(file.id) : null;
   let freedBytes = 0;
   let revision;
   db.exec('BEGIN');
   try {
    db.prepare('UPDATE messages SET deletedAt=?,deletedBy=?,text=?,file=NULL WHERE id=?').run(now(), d.id, '', id);
    if (fileRow) db.prepare("UPDATE files SET state='deleting' WHERE id=?").run(fileRow.id);
    revision = bumpDeletion();
    db.exec('COMMIT');
   } catch (e) { db.exec('ROLLBACK'); throw e; }
   let cleanupPending = false;
   if (fileRow) {
    try { fs.rmSync(path.join(uploads, fileRow.id), { force: true }); db.prepare('DELETE FROM files WHERE id=?').run(fileRow.id); freedBytes = fileRow.size; }
    catch { cleanupPending = true; }
   }
   logEvent('message_deleted', id, address(peer));
   broadcast('message_deleted', { id, chatId: 'legacy', revision, deletionRevision: chatRow().deletionRevision, freedBytes, deletedBy: d.id, cleanupPending });
   return send(res, 200, { ok: true, id, chatId: 'legacy', revision, deletionRevision: chatRow().deletionRevision, freedBytes, cleanupPending });
  }
  if (route === '/api/chat/clear/preview' && req.method === 'GET') {
   if (!d.host) throw error(403, 'Очистка доступна на главном устройстве');
   const chat = chatRow();
   const activeMessages = db.prepare('SELECT count(*) AS n FROM messages WHERE deletedAt IS NULL').get().n;
   const files = db.prepare("SELECT count(*) AS n, COALESCE(SUM(size),0) AS bytes FROM files WHERE chatId='legacy' AND state='ready'").get();
   const tempFiles = fs.readdirSync(uploads).filter(name => name.endsWith('.part')).length;
   return send(res, 200, { chatId: 'legacy', sessionId: chat.sessionId, term: chat.term, hostDeviceId: chat.hostDeviceId, revision: chat.revision, epoch: chat.epoch, activeMessages, activeFiles: files.n, bytes: files.bytes, tempFiles });
  }
  if (route === '/api/chat/clear' && req.method === 'POST') {
   if (!d.host) throw error(403, 'Очистка доступна на главном устройстве');
   const body = await json(req);
   if (body.confirm !== true) throw error(400, 'Подтвердите очистку');
   const operationId = String(body.operationId || '').slice(0, 80);
   if (!operationId) throw error(400, 'Нужен идентификатор операции');
   const existing = db.prepare('SELECT * FROM operations WHERE id=?').get(operationId);
   if (existing) return send(res, 200, operationResponse(existing));   const chat = chatRow();
   if (Number(body.revision) !== chat.revision) throw error(409, 'Чат изменился. Обновите данные и повторите');
   const files = db.prepare("SELECT id,size,state FROM files WHERE chatId='legacy' AND state IN ('ready','deleting')").all();
   const activeMessages = db.prepare('SELECT count(*) AS n FROM messages WHERE deletedAt IS NULL').get().n;
   const bytes = files.reduce((sum, file) => sum + file.size, 0);
   const tempNames = fs.readdirSync(uploads).filter(name => name.endsWith('.part'));
   const tempBefore = tempNames.length;
   let next;
   db.exec('BEGIN');
   try {
    db.prepare("UPDATE messages SET deletedAt=?,deletedBy=?,text='',file=NULL WHERE deletedAt IS NULL").run(now(), d.id);
    db.prepare("UPDATE files SET state='deleting' WHERE chatId='legacy' AND state IN ('ready','deleting')").run();
    db.prepare('UPDATE chats SET revision=revision+1,deletionRevision=deletionRevision+1,epoch=epoch+1 WHERE id=?').run('legacy');
    next = chatRow();
    db.prepare('INSERT INTO operations (id,type,chatId,actorId,status,createdAt,updatedAt,result,error) VALUES (?,?,?,?,?,?,?,?,?)').run(operationId, 'clear', 'legacy', d.id, 'deleting', now(), now(), JSON.stringify({ revision: next.revision, deletionRevision: next.deletionRevision, epoch: next.epoch, messages: activeMessages, files: files.length, bytes, tempFiles: tempBefore }), null);
    db.exec('COMMIT');
   } catch (e) { db.exec('ROLLBACK'); throw e; }
   const oldUploads = [...uploadMeta.entries()].filter(([, meta]) => meta.chatId === 'legacy').map(([id]) => id);
   for (const meta of uploadMeta.values()) if (meta.chatId === 'legacy') { try { meta.req.destroy(); } catch {} }
   const uploadDeadline = Date.now() + 3000;
   while (Date.now() < uploadDeadline && oldUploads.some(id => uploadJobs.has(id))) await new Promise(resolve => setTimeout(resolve, 50));
   const uploadsPending = oldUploads.some(id => uploadJobs.has(id));
   const cleaned = cleanClearFiles(files, tempNames);
   const cleanupPending = cleaned.pending || cleaned.tempFiles > 0 || uploadsPending;
   const freedBytes = cleaned.freedBytes;
   const status = cleanupPending ? 'partial' : 'done';
   const result = { revision: next.revision, deletionRevision: next.deletionRevision, epoch: next.epoch, messages: activeMessages, files: files.length, bytes, freedBytes, tempFiles: cleaned.tempFiles, cleanupPending };
   db.prepare('UPDATE operations SET status=?,updatedAt=?,result=?,error=? WHERE id=?').run(status, now(), JSON.stringify(result), cleanupPending ? 'Не все файлы удалены' : null, operationId);
   logEvent('chat_cleared', operationId, address(peer));
   broadcast('chat_cleared', { chatId: 'legacy', sessionId: next.sessionId, revision: next.revision, deletionRevision: next.deletionRevision, epoch: next.epoch, operationId, freedBytes, tempFiles: cleaned.tempFiles, cleanupPending });
   return send(res, 202, { operationId, status, revision: next.revision, deletionRevision: next.deletionRevision, epoch: next.epoch, freedBytes, tempFiles: cleaned.tempFiles, cleanupPending });
  }
  if (route.startsWith('/api/operations/') && req.method === 'GET') {
   if (!d.host) throw error(403, 'Операции доступны на главном устройстве');
   const operation = db.prepare('SELECT * FROM operations WHERE id=?').get(route.slice('/api/operations/'.length));
   if (!operation) throw error(404, 'Операция не найдена');
   return send(res, 200, operationResponse(operation));
  }
  if (route === '/api/files' && req.method === 'POST') {
   if (!allowRate(d.id, 'up', UPLOAD_PER_MIN)) throw error(429, 'Слишком много передач. Подождите минуту');   const size = Number(req.headers['content-length']);
   if (!Number.isSafeInteger(size) || size < 1 || size > MAX_FILE) throw error(413, 'Файл должен быть от 1 байта до 512 МБ');
   const requestId = String(url.searchParams.get('requestId') || crypto.randomUUID()).slice(0, 80);
   const chatId = url.searchParams.get('chatId') || 'legacy';
   chatAccess(d, chatId);
   const encrypted = url.searchParams.get('encrypted') === '1';
   const encryptedMeta = encrypted ? String(url.searchParams.get('meta') || '') : '';
   if (encryptedMeta.length > 16000) throw error(400, 'Слишком большой зашифрованный заголовок файла');
   const old = db.prepare('SELECT * FROM messages WHERE requestId=? AND deviceId=?').get(requestId, d.id);
   if (old) { if (old.deletedAt) throw error(410, 'Сообщение было удалено'); req.resume(); return send(res, 200, message(old)); }
   if (uploadJobs.has(requestId) || (activeUploads.get(d.id) || 0) >= 2) throw error(429, 'Дождитесь завершения текущей передачи');
   const requestSessionId = chatRow().sessionId;
   const epoch = chatRow().epoch;
   const release = reserveBytes(d.id, size);
   uploadJobs.add(requestId); activeUploads.set(d.id, (activeUploads.get(d.id) || 0) + 1);
   uploadMeta.set(requestId, { chatId, epoch, sessionId: chatRow().sessionId, deviceId: d.id, req });
   const id = crypto.randomUUID(); const tmp = path.join(uploads, `${id}.part`); const final = path.join(uploads, id); let committed = false;
   try {
    let count = 0;
    const limit = new Transform({ transform(chunk, enc, cb) { count += chunk.length; cb(count > MAX_FILE ? error(413, 'Файл больше 512 МБ') : null, chunk); } });
    await pipeline(req, limit, fs.createWriteStream(tmp, { flags: 'wx' }));
    if (count !== size) throw error(400, 'Передача прервалась. Отправьте файл ещё раз');
    if (!db.prepare('SELECT id FROM devices WHERE id=?').get(d.id)) throw error(401, 'Доступ устройства отозван');
    if (chatRow().epoch !== epoch || sessionEnding || chatRow().sessionId !== requestSessionId) throw error(409, 'Чат был очищен. Отправьте файл заново');
    const f = encrypted ? { id, name: 'encrypted', mime: 'application/octet-stream', size: count } : { id, name: cleanName(url.searchParams.get('name')), mime: sniff(tmp), size: count };
    fs.renameSync(tmp, final);
    db.exec('BEGIN');
    let result;
    try { result = addMessage(d, encryptedMeta, f, requestId, false, chatId, encrypted ? 1 : 0); db.prepare('INSERT INTO files (id,name,mime,size,deviceId,chatId,messageId,state,encrypted) VALUES (?,?,?,?,?,?,?,?,?)').run(id, f.name, f.mime, count, d.id, chatId, result.id, 'ready', encrypted ? 1 : 0); db.exec('COMMIT'); committed = true; }
    catch (e) { db.exec('ROLLBACK'); throw e; }
    broadcast('message', result);
    return send(res, 201, result);
   } finally { release(); uploadJobs.delete(requestId); uploadMeta.delete(requestId); activeUploads.set(d.id, Math.max(0, (activeUploads.get(d.id) || 1) - 1)); fs.rmSync(tmp, { force: true }); if (!committed) fs.rmSync(final, { force: true }); }
  }
  if (route.startsWith('/files/') && ['GET', 'HEAD'].includes(req.method)) {
   const f = db.prepare('SELECT * FROM files WHERE id=?').get(route.slice(7));
   if (!f || f.state !== 'ready' || !f.messageId || !db.prepare('SELECT id FROM messages WHERE id=? AND deletedAt IS NULL').get(f.messageId)) throw error(404, 'Файл не найден');
   chatAccess(d, f.chatId);
   const disk = path.join(uploads, f.id); if (!fs.existsSync(disk)) throw error(404, 'Файл удалён с компьютера');
   let start = 0, end = f.size - 1, status = 200;
   if (req.headers.range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
    if (!m || (!m[1] && !m[2])) { res.writeHead(416, { 'Content-Range': `bytes */${f.size}` }); return res.end(); }
    if (m[1]) { start = Number(m[1]); if (m[2]) end = Math.min(Number(m[2]), end); }
    else start = Math.max(0, f.size - Number(m[2]));
    if (start > end || start >= f.size) { res.writeHead(416, { 'Content-Range': `bytes */${f.size}` }); return res.end(); } status = 206;
   }
   const inline = !url.searchParams.has('download') && /^(image|video)\//.test(f.mime);
   const headers = { 'Content-Type': f.mime, 'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes', 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="file"; filename*=UTF-8''${encodeURIComponent(f.name)}` };
   if (status === 206) headers['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
   res.writeHead(status, headers); if (req.method === 'HEAD') return res.end();
   await pipeline(fs.createReadStream(disk, { start, end }), res); return;
  }
  if (route === '/api/events' && req.method === 'GET') {
   res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' }); res.write('retry: 1500\n\n');
   clients.set(res, { deviceId: d.id, host: !!d.host, sessionToken: d.sessionToken, sessionExpires: d.sessionExpires }); broadcast('devices', publicDevices());
   const keepalive = setInterval(() => res.write(': alive\n\n'), 20000);
   req.on('close', () => { clearInterval(keepalive); clients.delete(res); broadcast('devices', publicDevices()); }); return;
  }
  if (route === '/api/device' && req.method === 'PATCH') {
   const body = await json(req); const name = cleanName(body.name).slice(0, 40); if (!body.name?.trim()) throw error(400, 'Укажите имя');
   db.prepare('UPDATE devices SET name=? WHERE id=?').run(name, d.id); broadcast('devices', publicDevices()); return send(res, 200, { ok: true });
  }
  if (route === '/api/logout' && req.method === 'POST') {
   const raw = rawCookie(req);
   if (raw) { const tokenHash = sha(raw); db.prepare('DELETE FROM sessions WHERE token=?').run(tokenHash); closeClients(c => c.sessionToken === tokenHash, 'logout'); }
   logEvent('logout', d.name, address(peer));
   return send(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() });
  }
  if (route.startsWith('/api/host/')) {
   if (!d.host) throw error(403, 'Это действие доступно на главном компьютере');
   if (route === '/api/host/pairing' && req.method === 'POST') {
    const body = await json(req);
    pairing = body.enabled === false ? { code: newCode(), expires: 0 } : { code: newCode(), expires: Date.now() + PAIR_CODE_TTL };
    broadcast('pairing', pairing, true);
    return send(res, 200, pairing);
   }
   if (route === '/api/host/pair/approve' && req.method === 'POST') {
    prunePairs();
    const body = await json(req); const p = pendingPairs.get(String(body.requestId || ''));
    if (!p || p.status !== 'pending') throw error(404, 'Запрос не найден или устарел');
    const token = crypto.randomBytes(32).toString('hex');
    const deviceId = p.deviceId || crypto.randomUUID();
    const tokenHash = p.tokenHash || sha(token);
    const device = { id: deviceId, name: p.name.slice(0, 40), token: tokenHash, host: false, created: now() };
    const prior = db.prepare('SELECT * FROM devices WHERE id=?').get(deviceId);
    if (prior) db.prepare('UPDATE devices SET name=? WHERE id=?').run(device.name, deviceId);
    else db.prepare('INSERT INTO devices (id,name,token,host,created) VALUES (?,?,?,0,?)').run(device.id, device.name, device.token, device.created);
    p.status = 'approved'; p.deviceId = device.id; p.approved = now();
    p.rawToken = newSession(device.id); p.sessionCookie = sessionCookie(p.rawToken);
    logEvent('pair_approved', p.name, p.ip);
    broadcast('devices', publicDevices()); broadcast('pair_decided', { requestId: p.requestId, approved: true }, true);
    return send(res, 200, { ok: true, device: { id: device.id, name: device.name, host: false } });
   }
   if (route === '/api/host/pair/reject' && req.method === 'POST') {
    const body = await json(req); const p = pendingPairs.get(String(body.requestId || ''));
    if (!p || p.status !== 'pending') throw error(404, 'Запрос не найден или устарел');
    p.status = 'rejected'; logEvent('pair_rejected', p.name, p.ip);
    broadcast('pair_decided', { requestId: p.requestId, approved: false }, true);
    return send(res, 200, { ok: true });
   }
   if (route === '/api/host/logout-all' && req.method === 'POST') {
    db.prepare('DELETE FROM sessions').run();
    closeClients(() => true, 'logout_all');
    logEvent('logout_all', d.name, address(peer));
    return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(newSession(d.id)) });
   }
   if (route === '/api/host/events' && req.method === 'GET') {
    const events = db.prepare('SELECT id,type,detail,ip,created FROM events ORDER BY id DESC LIMIT 50').all();
    return send(res, 200, { events });
   }
   if (route.startsWith('/api/host/devices/') && req.method === 'DELETE') {
    const id = route.slice('/api/host/devices/'.length);
    db.prepare('DELETE FROM devices WHERE id=? AND host=0').run(id);
    db.prepare('INSERT OR IGNORE INTO revoked_devices (id,revokedAt) VALUES (?,?)').run(id, now());
    db.prepare('DELETE FROM sessions WHERE deviceId=?').run(id);
    logEvent('device_revoked', id, address(peer));
    closeClients(c => c.deviceId === id, 'revoked'); return send(res, 200, { ok: true });
   }
   if (route === '/api/host/stop' && req.method === 'POST') { send(res, 200, { ok: true }); setTimeout(shutdown, 250); return; }
  }
  throw error(404, 'Не найдено');
 } catch (e) { if (!res.headersSent && !res.destroyed) send(res, e.status || 500, { error: e.status ? e.message : 'Не удалось выполнить действие. Проверьте свободное место на компьютере' }); if (!e.status && e.code !== 'ERR_STREAM_PREMATURE_CLOSE' && e.code !== 'ECONNRESET') console.error(e); }
});
server.requestTimeout = 30 * 60 * 1000;
server.headersTimeout = 30000;
const sessionCleanup = setInterval(() => { try { db.prepare('DELETE FROM sessions WHERE expires<?').run(now()); closeClients(c => c.sessionExpires && c.sessionExpires <= Date.now(), 'expired'); } catch {} }, 60 * 1000); sessionCleanup.unref();
function openWindow() {
 if (process.env.RYADOM_NO_OPEN === '1') return;
 const url = `http://127.0.0.1:${PORT}/`;
 const { spawn } = require('node:child_process');
 if (process.platform === 'win32') {
  const edge = path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe');
  const chrome = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe');
  const browser = [edge, chrome].find(fs.existsSync);
  if (browser) { const p = spawn(browser, [`--app=${url}`, '--window-size=1180,820'], { detached: true, stdio: 'ignore' }); p.unref(); }
  else { const p = spawn('rundll32.exe', ['url.dll,FileProtocolHandler', url], { detached: true, stdio: 'ignore' }); p.unref(); }
 } else { const p = spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { stdio: 'ignore', detached: true }); p.on('error', () => {}); p.unref(); }
}
function shutdown() { if (sessionEnding) return; endEphemeralSession(); bridgeServer?.close(); for (const res of clients.keys()) res.end(); server.close(() => { db.close(); process.exit(0); }); setTimeout(() => process.exit(0), 2000).unref(); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
if (process.env.RYADOM_PARENT_PID) {
 const parent = Number(process.env.RYADOM_PARENT_PID);
 if (Number.isSafeInteger(parent) && parent > 0) setInterval(() => { try { process.kill(parent, 0); } catch { shutdown(); } }, 3000).unref();
}
server.on('error', e => { if (e.code === 'EADDRINUSE') { console.log('Рядом уже запущен.'); openWindow(); db.close(); process.exit(0); } else { console.error(e); process.exit(1); } });
let bridgeServer = null;
if (NATIVE_KEY && process.env.RYADOM_BRIDGE_PORT) {
 bridgeServer = require('node:net').createServer(socket => {
  let prefix = Buffer.alloc(0); socket.setTimeout(5000, () => socket.destroy());
  const receive = chunk => {
   prefix = Buffer.concat([prefix, chunk]); const end = prefix.indexOf('\r\n');
   if (end < 0) { if (prefix.length > 256) socket.destroy(); return; }
   socket.pause(); socket.removeListener('data', receive); const p = prefix.subarray(0, end).toString('ascii').split(' ');
   if (p.length !== 4 || p[0] !== 'RYADOM/1' || p[1] !== NATIVE_KEY || !isPrivate(p[2]) || !lanAddresses().includes(p[3])) { socket.destroy(); return; }
   socket.ryadomPeer = p[2]; socket.ryadomLocal = p[3]; socket.setTimeout(0);
   if (prefix.length > end + 2) socket.unshift(prefix.subarray(end + 2));
   server.emit('connection', socket); socket.resume();
  };
  socket.on('data', receive); socket.on('error', () => {});
 }); bridgeServer.on('error', e => { console.error(e); process.exit(1); }); bridgeServer.listen(Number(process.env.RYADOM_BRIDGE_PORT), '127.0.0.1');
}
const activeSession = beginEphemeralSession();
importTrustRoster();
server.listen(PORT, process.env.RYADOM_LAN_STATE ? '127.0.0.1' : '0.0.0.0', () => {
 for (const file of fs.readdirSync(uploads)) if (file.endsWith('.part')) try { fs.rmSync(path.join(uploads, file), { force: true }); } catch {}
 for (const row of db.prepare("SELECT id FROM files WHERE state='deleting'").all()) {
  try { fs.rmSync(path.join(uploads, row.id), { force: true }); db.prepare('DELETE FROM files WHERE id=?').run(row.id); } catch {}
 }
 reconcileClearOperations();
 process.stdout.write('\x1b]0;Рядом — личный чат\x07');
 console.log(`\n  РЯДОМ · личный чат\n\n  Чат работает. Это окно можно свернуть.\n  Закрытие окна выключит чат для всех устройств.\n\n  Адреса для телефона:\n  ${lanAddresses().map(ip => `http://${ip}:${PORT}`).join('\n  ') || 'Подключитесь к Wi-Fi и перезапустите приложение.'}\n\n  Данные: ${DATA}\n`);
 openWindow();
});

// The browser uses loopback. The native tunnel binds each outbound socket to a physical NIC.
function startClientProxy(){
 const target = new URL(process.env.RYADOM_TARGET); const tunnel = Number(process.env.RYADOM_TUNNEL_PORT); const own = `127.0.0.1:${PORT}`;
 const cookieName = 'ryadom_sid_' + crypto.createHash('sha256').update(target.origin).digest('hex').slice(0, 16);
 const proxy = http.createServer((req, res) => {
  const fail = (status, message) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ error: message })); };
  if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== own || req.headers.origin && req.headers.origin !== `http://${own}`) return fail(403, 'Недопустимый источник');
  if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-ryadom'] !== '1') return fail(403, 'Недопустимый запрос');
  if (req.url === '/api/local/status') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ app: 'ryadom', role: 'client', version: VERSION, target: target.origin })); }
  if (req.url === '/api/local/quit' && req.method === 'POST' && NATIVE_KEY && req.headers['x-ryadom-native'] === NATIVE_KEY) { res.end('{"ok":true}'); setTimeout(() => process.exit(0), 200); return; }
  if (req.url.startsWith('/api/local/') || req.url.startsWith('/api/host-login')) return fail(403, 'Недоступно при подключении к другому устройству');
  const headers = { ...req.headers, host: target.host }; delete headers['x-ryadom-native']; delete headers['proxy-authorization']; delete headers['proxy-connection']; delete headers.forwarded; delete headers['x-forwarded-for'];
  if (headers.origin) headers.origin = target.origin;
  const sid = (headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '=')); headers.cookie = sid ? 'ryadom_sid=' + sid.slice(cookieName.length + 1) : '';
  const upstream = http.request({ hostname: '127.0.0.1', port: tunnel, path: req.url, method: req.method, headers, agent: false }, reply => {
   const responseHeaders = { ...reply.headers, 'Cache-Control': 'no-store' }; if (responseHeaders['set-cookie']) responseHeaders['set-cookie'] = responseHeaders['set-cookie'].map(c => c.replace(/^ryadom_sid=/, cookieName + '='));
   if (req.url === '/api/state' && reply.statusCode === 200) { const chunks = []; reply.on('data', b => chunks.push(b)); reply.on('end', () => { try { const data = JSON.parse(Buffer.concat(chunks)); data.server.localControls = false; data.server.direct = true; const body = JSON.stringify(data); delete responseHeaders['transfer-encoding']; responseHeaders['content-length'] = Buffer.byteLength(body); res.writeHead(200, responseHeaders); res.end(body); } catch { fail(502, 'Нет ответа от главного устройства'); } }); }
   else { res.writeHead(reply.statusCode, responseHeaders); reply.pipe(res); } res.on('close', () => reply.destroy());
  });
  upstream.on('error', () => { if (res.headersSent) { res.destroy(); return; } if (req.url === '/' && req.method === 'GET') { res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'" }); res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Рядом</title><body style="font:18px Segoe UI,sans-serif;padding:10%;background:#f5f6f3;color:#36533b"><h1>Главное устройство не отвечает</h1><p>Проверьте, запущен ли чат, адрес и домашнюю сеть.</p><p>Сменить главное устройство можно через значок Рядом рядом с часами.</p><a href="/">Повторить</a>'); } else fail(502, 'Главное устройство недоступно. Проверьте локальную сеть.'); });
  req.on('aborted', () => upstream.destroy()); res.on('close', () => upstream.destroy()); req.pipe(upstream);
 });
 proxy.requestTimeout = 30 * 60 * 1000; proxy.listen(PORT, '127.0.0.1');
 if (process.env.RYADOM_PARENT_PID) setInterval(() => { try { process.kill(Number(process.env.RYADOM_PARENT_PID), 0); } catch { process.exit(0); } }, 3000).unref();
}
