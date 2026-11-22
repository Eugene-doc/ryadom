'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');

test('0.5.0 versions and protocol are consistent', () => {
 const pkg = JSON.parse(read('package.json'));
 const server = read('server.cjs');
 assert.equal(pkg.version, '0.5.0');
 assert.match(server, /const VERSION = '0\.5\.0'/);
 assert.match(server, /const PROTOCOL = 4/);
 assert.match(read('windows/AssemblyInfo.cs'), /0\.5\.0\.0/);
 assert.match(read('windows/RolePicker.cs'), /Рядом 0\.5\.0/);
 assert.match(read('public/index.html'), /ВЕРСИЯ 0\.5\.0/);
 assert.match(read('android/AndroidManifest.xml'), /versionCode="15"/);
 assert.match(read('android/AndroidManifest.xml'), /versionName="0\.5\.0"/);
 const host = read('android/src/local/ryadom/chat/ChatHost.java');
 assert.match(host, /VERSION="0\.5\.0"/);
 assert.match(host, /PROTOCOL=4/);
 assert.match(read('android/src/local/ryadom/chat/MainActivity.java'), /Рядом 0\.5\.0/);
 assert.match(read('scripts/build-windows.cjs'), /Ryadom-Windows-\$\{version\}\.exe/);
 assert.match(read('scripts/build-android.ps1'), /Ryadom-Android-\$Version\.apk/);
 assert.match(read('scripts/sign-release.ps1'), /Ryadom-Windows-\*\.exe/);
});
