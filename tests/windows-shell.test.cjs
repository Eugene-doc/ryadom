'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');

test('Windows shell uses WebView2 identity and embedded SDK', () => {
 const window = read('windows/ChatWindow.cs');
 const launcher = read('windows/Launcher.cs');
 const build = read('scripts/build-windows.cjs');
 assert.match(window, /WebView2Bootstrap/);
 assert.match(window, /SetLoaderDllFolderPath/);
 assert.match(window, /Downloads.*Рядом|Рядом.*Downloads/s);
 assert.match(window, /Guid\.NewGuid/);
 assert.match(window, /UserDataFolder/);
 assert.match(window, /scriptsReady/);
 assert.match(launcher, /Ryadom\.Chat/);
 assert.match(launcher, /SetCurrentProcessExplicitAppUserModelID/);
 assert.match(launcher, /new ChatWindow/);
 assert.match(launcher, /Создать ярлык/);
 assert.match(build, /WebView2\.Core\.dll/);
 assert.match(build, /WebView2Loader\.dll/);
 assert.doesNotMatch(launcher, /--app=\\"\s*\+url/);
});
