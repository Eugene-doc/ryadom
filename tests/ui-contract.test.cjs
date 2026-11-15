'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'public/app.js'), 'utf8');

test('0.3.0 UI exposes deletion, clear, downloads and version controls', () => {
 for (const id of ['delete-dialog', 'delete-confirm', 'clear-chat-button', 'clear-dialog', 'clear-confirm', 'downloads-button', 'app-version', 'chat-stats']) {
  assert.match(html, new RegExp(`id="${id}"`), `missing #${id}`);
 }
 assert.match(js, /\/api\/messages\/\$\{encodeURIComponent\(message\.id\)\}/);
 assert.match(js, /\/api\/chat\/clear\/preview/);
 assert.match(js, /\/api\/chat\/clear'/);
 assert.match(js, /message_deleted/);
 assert.match(js, /chat_cleared/);
 assert.match(js, /stateGeneration/);
 assert.match(js, /deletionRevision/);
 assert.match(js, /clearOperationId/);
 assert.match(js, /openDownloads/);
 assert.match(js, /data\.server\.protocol!==3/);
});
