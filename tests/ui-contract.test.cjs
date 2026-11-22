'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'public/app.js'), 'utf8');

test('0.3.0 UI exposes deletion, clear, downloads and version controls', () => {
 for (const id of ['delete-dialog', 'delete-confirm', 'header-clear-chat-button', 'clear-chat-button', 'clear-dialog', 'clear-confirm', 'downloads-button', 'app-version', 'chat-stats', 'forget-offline']) {
  assert.match(html, new RegExp(`id="${id}"`), `missing #${id}`);
 }
 assert.equal((html.match(/id="downloads-button"/g) || []).length, 1, 'downloads button must be unique');
 assert.ok(html.indexOf('id="search-toggle"') < html.indexOf('id="downloads-button"'), 'downloads must follow search');
 assert.match(html, /id="header-clear-chat-button"[^>]*hidden/);
 assert.match(html, /Очистить всю историю/);
 assert.match(html, /всех подключённых устройств/);
 assert.match(html, /временные незавершённые файлы/);
 assert.match(js, /header-clear-chat-button.*hidden=!me\.host|hidden=!me\.host/);
 assert.match(js, /\$\('header-clear-chat-button'\)\.onclick=openClearDialog/);
 assert.match(js, /applyChatCleared/);
 assert.match(js, /\/api\/messages\/\$\{encodeURIComponent\(message\.id\)\}/);
 assert.match(js, /\/api\/chat\/clear\/preview/);
 assert.match(js, /\/api\/chat\/clear'/);
 assert.match(js, /message_deleted/);
 assert.match(js, /chat_cleared/);
 assert.match(js, /stateGeneration/);
 assert.match(js, /deletionRevision/);
 assert.match(js, /clearOperationId/);
 assert.match(js, /openDownloads/);
 assert.match(js, /nativeAuth/);
 assert.match(js, /deviceToken/);
 assert.match(js, /ensureE2EE/);
 assert.match(html, /e2ee\.js/);
 assert.match(fs.readFileSync(path.join(root, 'public/e2ee.js'), 'utf8'), /ECDH/);
 assert.match(js, /forget-offline/);
 assert.match(html, /История и главное устройство/);
 assert.match(html, /Забыть неактивные устройства/);
 assert.match(js, /data\.server\.protocol!==4/);
});
