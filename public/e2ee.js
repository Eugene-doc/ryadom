/* Ryadom 0.5 E2E primitives. Private keys never leave this device.
   Per-session ECDH P-256 + HKDF-SHA-256 + AES-256-GCM. */
(function (root) {
 'use strict';
 const encoder = new TextEncoder();
 const decoder = new TextDecoder();
 const DB_NAME = 'ryadom-e2e';
 const STORE = 'keys';
 const memory = new Map();

 function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
 }
 function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
 }
 function b64url(value) { return bytesToBase64(typeof value === 'string' ? encoder.encode(value) : value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
 function fromB64url(value) { const s = String(value).replace(/-/g, '+').replace(/_/g, '/'); return base64ToBytes(s + '='.repeat((4 - s.length % 4) % 4)); }
 function available() { return !!(root.crypto && root.crypto.subtle && root.crypto.getRandomValues); }

 function openDb() {
  return new Promise((resolve, reject) => {
   if (!root.indexedDB) return reject(new Error('IndexedDB unavailable'));
   const request = indexedDB.open(DB_NAME, 1);
   request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE); };
   request.onsuccess = () => resolve(request.result);
   request.onerror = () => reject(request.error || new Error('IndexedDB error'));
  });
 }
 async function readKey(sessionId, deviceId) {
  const key = sessionId + ':' + deviceId;
  if (memory.has(key)) return memory.get(key);
  try {
   const db = await openDb();
   const value = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
   });
   db.close();
   if (value) memory.set(key, value);
   return value;
  } catch { return null; }
 }
 async function saveKey(sessionId, deviceId, value) {
  const key = sessionId + ':' + deviceId;
  memory.set(key, value);
  try {
   const db = await openDb();
   await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
   });
   db.close();
  } catch { /* in-memory fallback keeps the current page usable */ }
 }

 async function ensureIdentity(sessionId, deviceId) {
  if (!available()) throw new Error('WebCrypto недоступен');
  let stored = await readKey(sessionId, deviceId);
  if (!stored) {
   const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
   const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
   const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
   stored = { privateJwk, publicJwk };
   await saveKey(sessionId, deviceId, stored);
  }
  return { publicKey: b64url(JSON.stringify(stored.publicJwk)), publicJwk: stored.publicJwk, privateJwk: stored.privateJwk };
 }

 async function importPrivate(privateJwk) { return crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']); }
 async function importPublic(publicKey) {
  const jwk = typeof publicKey === 'string' ? JSON.parse(decoder.decode(fromB64url(publicKey))) : publicKey;
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
 }
 async function deriveChatKey(privateJwk, peerPublicKey, chatId, sessionId) {
  const privateKey = await importPrivate(privateJwk);
  const peerKey = await importPublic(peerPublicKey);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
   { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode('ryadom-private'), info: encoder.encode(chatId + ':' + sessionId) },
   hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
 async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(String(text))));
  return JSON.stringify({ v: 1, iv: bytesToBase64(iv), data: bytesToBase64(data) });
 }
 async function decryptText(key, envelope) {
  const value = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
  if (!value || value.v !== 1 || !value.iv || !value.data) throw new Error('Некорректный шифротекст');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(value.iv) }, key, base64ToBytes(value.data));
  return decoder.decode(plain);
 }
 async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return { iv: bytesToBase64(iv), data };
 }
 async function decryptBytes(key, iv, bytes) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(iv) }, key, bytes));
 }
 async function sha256(text) { return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))); }
 async function safetyNumber(first, second) {
  const material = [String(first), String(second)].sort().join('\n');
  const bytes = await sha256(material);
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return hex.match(/.{1,4}/g).slice(0, 8).join(' ');
 }
 function publicKeyFingerprint(publicKey) {
  return sha256(String(publicKey)).then(bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase());
 }
 const api = { available, ensureIdentity, deriveChatKey, encryptText, decryptText, encryptBytes, decryptBytes, safetyNumber, publicKeyFingerprint, b64url, fromB64url, bytesToBase64, base64ToBytes };
 if (typeof module !== 'undefined' && module.exports) module.exports = api;
 root.RyadomE2EE = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
