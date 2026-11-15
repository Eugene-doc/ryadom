# Ryadom 0.3.0 Functional Changes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Выпустить Ryadom 0.3.0 с надёжным удалением сообщений, полной очисткой чата и вложений, безопасным доступом к папке загрузок, показом версии и собственной Windows-оболочкой на WebView2 с правильной иконкой и закреплением.

**Architecture:** Сохраняем один общий чат (`chatId = legacy`), но вводим ревизию/эпоху чата, tombstones сообщений, учёт файлов и операций — это фундамент будущих частных/общих чатов без преждевременной миграции. Node и Android-хост реализуют одинаковый HTTP/SSE-контракт; веб-интерфейс работает с ревизиями и полной перезагрузкой при рассинхронизации. Windows остаётся на Node-хосте и C#-мосту, но вместо окна Edge получает WinForms + WebView2, собственный AppUserModelID, иконку, ярлык и перехват загрузок. iOS и многопользовательские чаты в 0.3.0 не входят.

**Tech Stack:** Node.js 26 (`node:sqlite`), Android Java 8/API 26–35, C# WinForms .NET Framework 4.x, WebView2 SDK, HTML/CSS/JS без внешних CDN, Node test runner, JVM harness.

**Spec:** `docs/ROADMAP.md` §4, пункты «Удаление отдельных сообщений», «Очистка чата…», «Кнопка „Открыть папку загрузок“», «Закрепление…», «Иконка…», «Показ версии…»; архитектурные решения зафиксированы в этой записи и в `delegations/codex-0.3-planning.md`. iOS и чаты 0.4.0 явно исключены.

## Global Constraints

- Версия продукта: **0.3.0**, `PROTOCOL = 3`; Windows `AssemblyVersion 0.3.0.0`, Android `versionCode 8`, `versionName 0.3.0`.
- Только локальная домашняя сеть; никаких облачных сервисов, аккаунтов и телеметрии.
- Сохранить TLS 1.2/TOFU, сессии, подтверждение спаривания, квоты, аудит и firewall-поведение 0.2.x.
- Совместимость: читать существующий SQLite `chat.sqlite` и Android `chat.json` без потери истории; миграция идемпотентна; откат — восстановление резервной копии, не запуск старого бинарника на новом формате.
- Один общий чат в 0.3.0; API проектируется с `chatId`, чтобы 0.4.0 добавил участников без переделки сообщений.
- Удаление в приложении означает удаление из рабочего хранилища и управляемого кэша; не обещать уничтожение внешних копий/резервных копий/SSD-следов.
- Windows: WebView2 Runtime — единственная новая внешняя зависимость; версия SDK фиксируется, загрузчик проверяется по SHA-256. Без Runtime — понятный экран и fallback на Edge с предупреждением.
- Android: никаких новых опасных разрешений; SAF/FileProvider только для файлов, созданных приложением.
- Язык интерфейса — русский; строки не выносить в внешний i18n в 0.3.0.
- Каждая задача заканчивается зелёными тестами и отдельным коммитом; сборки/подписи — после задач 1–9.
- Никаких `git commit`/`push` в задачах 1–9, кроме шага «Commit» каждой задачи; итоговый пуш — в задаче 10.

## Review Focus

- **Удаление во время передачи или после переподключения.** Пользователь ждёт, что удалённое сообщение и файл исчезнут у всех и не вернутся после retry/offline; проверить гонки upload→delete/clear, SSE и полную перезагрузку снимка.
- **Права и утечки файлов.** Не-автор не должен удалять чужое; удалённый файл не должен открываться по старому `/files/{id}`, Range, `<img>` или SSE; главный не должен получить доступ к чужому личному чату в будущем.
- **Правдивость квот и места.** После ошибки unlink/перезапуска занятое место не должно преждевременно освобождаться; `.part` и осиротевшие файлы должны переживать/убираться предсказуемо.
- **Старая история после очистки/офлайна.** Клиент, пропустивший SSE, не должен показывать удалённое; смена ревизии должна инвалидировать старые страницы, а не только последние 100 сообщений.
- **Windows-идентичность.** После закрепления пользователь должен видеть Рядом, а не Edge; повторный запуск, обновление, пути с кириллицей и отсутствие WebView2 Runtime не должны ломать запуск.

---

## Task 1: Version, protocol and storage contract

**Files:**
- Modify: `server.cjs:11-37`, `package.json`, `windows/AssemblyInfo.cs`, `windows/RolePicker.cs`, `public/index.html`, `android/AndroidManifest.xml`, `android/src/local/ryadom/chat/ChatHost.java`, `android/src/local/ryadom/chat/MainActivity.java`
- Create: `tests/version.test.cjs`
- Modify: `tests/server.test.cjs`, `android/tests/local/ryadom/chat/TlsTest.java` (version assertions)

**Interfaces:**
- Produces: `VERSION = '0.3.0'`, `PROTOCOL = 3`; `/api/health` returns `{app, version, protocol, ...}`; `/api/state` returns `server.protocol` and `chat: {id:'legacy', revision, epoch}`.
- Produces: a single `version.json`-independent, test-enforced set of version constants; no runtime file needed.

- [ ] **Step 1: Write failing version/protocol tests**

```js
// tests/version.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
test('0.3.0 versions are consistent', () => {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const server = fs.readFileSync('server.cjs', 'utf8');
  assert.equal(pkg.version, '0.3.0');
  assert.match(server, /const VERSION = '0\.3\.0'/);
  assert.match(server, /const PROTOCOL = 3/);
  assert.match(fs.readFileSync('windows/AssemblyInfo.cs', 'utf8'), /0\.3\.0\.0/);
  assert.match(fs.readFileSync('android/AndroidManifest.xml', 'utf8'), /versionCode="8"/);
});
```

Add to `tests/server.test.cjs`: health has `protocol: 3`; state `chat.id === 'legacy'`, numeric `revision`, `epoch`; `server.protocol === 3`.

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/version.test.cjs tests/server.test.cjs`
Expected: FAIL on 0.2.1/2 and missing chat metadata.

- [ ] **Step 3: Implement constants and minimal chat metadata**

In `server.cjs` add:

```js
const VERSION = '0.3.0';
const PROTOCOL = 3;
const LEGACY_CHAT = 'legacy';
```

SQLite additions (idempotent):
```sql
CREATE TABLE IF NOT EXISTS chats (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT, ownerDeviceId TEXT,
 created TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, chatId TEXT NOT NULL, actorId TEXT,
 status TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL,
 result TEXT, error TEXT
);
```
Add columns if missing: `messages.chatId TEXT NOT NULL DEFAULT 'legacy'`, `messages.deletedAt TEXT`, `messages.deletedBy TEXT`; `files.chatId TEXT NOT NULL DEFAULT 'legacy'`, `files.messageId TEXT`, `files.state TEXT NOT NULL DEFAULT 'ready'`.
Insert `legacy` chat with `INSERT OR IGNORE`. Backfill `files.messageId` by parsing each active `messages.file` JSON id. Set `PRAGMA user_version = 3`.

`/api/state` adds:
```js
chat: { id: LEGACY_CHAT, revision: chatRow.revision, epoch: chatRow.epoch }
```
and `server.protocol`. Health already includes version; set protocol 3.

Android: `VERSION="0.3.0"`, `PROTOCOL=3`, `schema=3`, add `chat` object to state with `revision`/`epoch`, create in JSON state.

Update visible version strings only (RolePicker, index eyebrow, Android caption); do not add new UI yet.

- [ ] **Step 4: Run tests**

Run: `node --test tests/version.test.cjs tests/server.test.cjs tests/security.test.cjs`
Expected: PASS except tests explicitly needing new chat behavior (none in this task).

Build Android: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-android.ps1`
Expected: `Ready: ...Ryadom-Android.apk` with versionCode 8/0.3.0.

- [ ] **Step 5: Commit**

```bash
git add server.cjs package.json windows/AssemblyInfo.cs windows/RolePicker.cs public/index.html android/AndroidManifest.xml android/src/local/ryadom/chat/ChatHost.java android/src/local/ryadom/chat/MainActivity.java tests/version.test.cjs tests/server.test.cjs
git commit -m "0.3.0: protocol 3, chat revision metadata and version bump"
```

---

## Task 2: Delete one message and its attachment (Node host)

**Files:**
- Modify: `server.cjs` (`message`, `addMessage`, routes, `message_deleted` SSE)
- Create: `tests/functional.test.cjs`
- Modify: `public/app.js` (minimal delete wiring is Task 5; API tests only here)

**Interfaces:**
- Consumes: `LEGACY_CHAT`, `chatRow`, `files.state/messageId/chatId`, `session` device.
- Produces: `DELETE /api/messages/:id` → `200 {ok:true,id,chatId,revision,freedBytes}`; `403` for non-author/non-host; `200` idempotent for already deleted; `410` when a retry would resurrect a deleted `requestId`.
- Produces: SSE `message_deleted` `{id, chatId, revision, freedBytes, deletedBy}`.
- Produces: `addMessage` rejects a deleted `requestId` with `410`.

- [ ] **Step 1: Write failing Node tests**

In `tests/functional.test.cjs` reuse `start`, `hostToken`, `login`, `newDevice` from security/serve patterns. Add:

```js
test('author deletes own message and file becomes inaccessible', async () => {
  const host = await login();
  const d = await newDevice(host, 'Автор');
  const m = await uploadText(d.cookie, 'удалить меня', 'del-1');
  const del = await req(`/api/messages/${m.id}`, { method: 'DELETE', cookie: d.cookie });
  assert.equal(del.r.status, 200);
  assert.equal(del.data.revision, 1);
  assert.equal((await req(`/files/${m.file.id}`, { cookie: d.cookie })).r.status, 404);
  assert.equal((await req(`/api/messages/${m.id}`, { method: 'DELETE', cookie: d.cookie })).r.status, 200);
});
test('non-author cannot delete another message', async () => { ... 403 ... });
test('host can delete any message', async () => { ... 200 ... });
test('retrying a deleted requestId does not resurrect', async () => {
  ... POST /api/messages with same requestId => 410; GET messages does not contain id ...
});
```

Use `uploadText` helper that posts text, not a file, for the first case; add file case with `POST /api/files`.

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/functional.test.cjs`
Expected: FAIL 404/405 for DELETE.

- [ ] **Step 3: Implement server behavior**

Add helpers:
```js
function chatRow() { return db.prepare('SELECT * FROM chats WHERE id=?').get(LEGACY_CHAT); }
function bumpRevision(chatId) { db.prepare('UPDATE chats SET revision=revision+1 WHERE id=?').run(chatId); return chatRow().revision; }
function activeMessage(id) { return db.prepare('SELECT * FROM messages WHERE id=? AND deletedAt IS NULL').get(id); }
```

`DELETE /api/messages/:id`:
1. Load message including deleted tombstone. If missing → 404; if already deleted → 200 current revision/freed 0.
2. Authorize `message.deviceId === d.id || d.host`; otherwise 403.
3. In transaction: set `deletedAt`, `deletedBy`, `text=''`, `file=NULL`; if file JSON id exists, `UPDATE files SET state='deleting' WHERE id=?`; bump revision; store `freedBytes = file.size`; commit.
4. Unlink physical file; on success `DELETE FROM files WHERE id=?`; on failure leave `state='deleting'` and return `200` with `cleanupPending:true` (access already denied; startup retry handles it).
5. Broadcast `message_deleted`; log audit `message_deleted` without text.

`GET /files/:id`: require `files.state='ready'`, `files.chatId=LEGACY_CHAT`, and `EXISTS active message with messageId=files.id`; else 404. All existing file access paths use this.

`addMessage`: if old requestId exists and `old.deletedAt` → throw 410 `'Сообщение было удалено'`; do not insert.

Update `message()` to return null file for deleted.

- [ ] **Step 4: Run tests**

Run: `node --test tests/functional.test.cjs tests/server.test.cjs tests/security.test.cjs`
Expected: PASS; file GET/HEAD/Range 404 after delete; revision increments once per deletion.

- [ ] **Step 5: Commit**

```bash
git add server.cjs tests/functional.test.cjs
git commit -m "0.3.0: delete individual messages and attachments"
```

---

## Task 3: Clear chat, cancel uploads, account for files and operations (Node host)

**Files:**
- Modify: `server.cjs` (operations, upload map, clear routes, startup GC)
- Modify: `tests/functional.test.cjs`
- Modify: `tests/security.test.cjs` (quota after clear)

**Interfaces:**
- Consumes: `chatRow()`, `bumpRevision`, `files.state`, `activeUploads`, upload epoch.
- Produces: `GET /api/chat/clear/preview` → `{chatId,revision,epoch,activeMessages,activeFiles,bytes,tempFiles}`.
- Produces: `POST /api/chat/clear` body `{confirm:true,revision,operationId}` → `202/200 {operationId,status,revision,epoch,freedBytes,cleanupPending}`; `409` on revision mismatch; `403` non-host.
- Produces: `GET /api/operations/:id` → `{id,status:'done'|'deleting'|'partial',...}`.
- Produces: SSE `chat_cleared` `{chatId,revision,epoch,freedBytes,operationId}`.
- Produces: uploads record `{id,chatId,epoch,requestId,req,deviceId}`; clear destroys them; upload finalization checks epoch.

- [ ] **Step 1: Write failing tests**

Add:
```js
test('clear preview and clear delete all history and files', async () => {
  const host=await login(); const d=await newDevice(host,'Очистка');
  const f=await uploadFile(d.cookie, Buffer.from('file'), 'clear-1');
  await req('/api/messages',{method:'POST',body:{text:'hello',requestId:'clear-msg'},cookie:d.cookie});
  const preview=await req('/api/chat/clear/preview',{cookie:host});
  assert.equal(preview.r.status,200); assert.equal(preview.data.activeMessages,2); assert.ok(preview.data.bytes>=4);
  const clear=await req('/api/chat/clear',{method:'POST',body:{confirm:true,revision:preview.data.revision,operationId:'op-1'},cookie:host});
  assert.equal(clear.r.status,202); assert.equal(clear.data.epoch,1);
  assert.equal((await req('/api/messages',{cookie:d.cookie})).data.length,0);
  assert.equal((await req(`/files/${f.file.id}`,{cookie:d.cookie})).r.status,404);
});
test('clear rejects stale revision and non-host', ...);
test('clear cancels an in-flight upload and does not commit it', async () => {...});
test('retrying requestId after clear does not recreate', ...);
test('files marked deleting are retried after restart', ...); // simulated metadata
```

- [ ] **Step 2: Run failing**

Run: `node --test tests/functional.test.cjs`
Expected: FAIL 404 for clear routes.

- [ ] **Step 3: Implement transaction and cleanup**

- Add `pendingUploads = new Map()` keyed by requestId with `{id, chatId, epoch, deviceId, req, released}`; keep existing `activeUploads` counts.
- `upload` records `chatEpoch` captured at start; in final transaction check `chatRow().epoch === chatEpoch`, else throw 409 and clean `.part`.
- Clear:
  1. Validate host, `confirm===true`, `revision===chatRow().revision`, `operationId` length 1..80.
  2. Insert operation `deleting` in transaction; collect active message/file IDs and bytes; set all `messages.deletedAt/deletedBy`, `text=''`, `file=NULL`; set files `state='deleting'`; bump revision and epoch; commit.
  3. Destroy active uploads for chat (`req.destroy()`; their `finally` removes `.part` and releases reservation).
  4. Unlink files; on success delete rows; failures remain `deleting` and operation `partial`.
  5. Mark operation done, broadcast `chat_cleared`.
- Startup GC: delete `*.part`; retry rows `state='deleting'` (unlink if exists, then remove row); remove orphan files with no `files` row; log failures without deleting metadata.
- `GET /api/operations/:id` host-only, returns operation JSON.

- [ ] **Step 4: Run tests**

Run: `node --test tests/functional.test.cjs tests/security.test.cjs tests/server.test.cjs`
Expected: PASS; quota usedBytes drops only after file row deletion; clear twice idempotent.

- [ ] **Step 5: Commit**

```bash
git add server.cjs tests/functional.test.cjs tests/security.test.cjs
git commit -m "0.3.0: clear chat with upload cancellation and cleanup operations"
```

---

## Task 4: Android host parity (JSON)

**Files:**
- Modify: `android/src/local/ryadom/chat/ChatHost.java`
- Create: `android/tests/local/ryadom/chat/FunctionalTest.java`
- Modify: `scripts/test-android.ps1`

**Interfaces:**
- Consumes: Node contract from Tasks 2–3; JSON state.
- Produces: same HTTP routes/SSE events/status codes; `chat` object, `deletedAt/deletedBy`, `files.state/messageId/chatId`; schema 3.
- Produces: Java `FunctionalTest` executable with PASS output, added to `test-android.ps1`.

- [ ] **Step 1: Write failing Java contract test**

Create `FunctionalTest` starting `ChatHost` in a temp dir, login host, pair device via existing helpers (reuse TlsTest/ServerHarness patterns), then:
- upload bytes, delete message as author → 200, `/files/id` 404;
- non-author delete → 403; host delete → 200;
- clear preview/clear → 202, revision/epoch increment, history empty;
- retry deleted `requestId` → 410.

- [ ] **Step 2: Run to fail**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-android.ps1`
Expected: compilation/test FAIL (routes absent).

- [ ] **Step 3: Implement JSON equivalents**

- Add `chat` object in state (`id`, `revision`, `epoch`), schema 3; migration from schema 2 adds fields/tombstone defaults and `files.messageId` by joining messages.
- Add `revision`/`epoch` updates in the existing atomic `change(...)`.
- Add delete/clear operations using one `change` transaction; mark files `state=deleting`; remove physical files after commit; persist operation in state (max 100, prune done).
- Add active upload tracking by requestId/epoch; clear cancels by closing request socket? `MiniHttp.Request` has `socket`; expose `close()`/`abort()` or set a cancelled flag checked before commit. Prefer `request.close()` plus epoch check; ensure `.part` deleted in upload finally.
- Add routes preserving exact JSON shapes/statuses.
- Startup: retry deleting files; remove orphan files; remove `.part`.
- SSE `message_deleted`, `chat_cleared` via existing `broadcast`.

- [ ] **Step 4: Run tests**

Run: `powershell ... scripts/build-android.ps1` and `scripts/test-android.ps1`
Expected: JVM `FunctionalTest` PASS; `node --test ...` with `RYADOM_TEST_JAVA` PASS (same contract on Java host).

- [ ] **Step 5: Commit**

```bash
git add android/src/local/ryadom/chat/ChatHost.java android/tests/local/ryadom/chat/FunctionalTest.java scripts/test-android.ps1
git commit -m "0.3.0: Android host deletion and clear parity"
```

---

## Task 5: Web UI — delete, clear, snapshot/revision, version

**Files:**
- Modify: `public/app.js`, `public/index.html`, `public/style.css`
- Create: none
- Tests: Node HTTP integration (existing `tests/functional.test.cjs`), manual browser checks in Task 10

**Interfaces:**
- Consumes: API from Tasks 2–3; `state.chat.revision/epoch`; SSE events.
- Produces: message delete button (`data-action="delete-message"`), confirm dialog; clear preview/confirm UI host-only; `applyState`/`sync` revision reset; `server.protocol !== 3` blocking update screen.
- Produces: UI strings and accessible labels; no new external assets.

- [ ] **Step 1: Add failing JS-level checks**

There is no JS DOM harness; add a Node static test `tests/ui-contract.test.cjs` that asserts the HTML contains `id="delete-message-dialog"`, `id="clear-chat-button"`, `id="downloads-button"`, `id="app-version"`, and app.js references `/api/chat/clear/preview`, `message_deleted`, `chat_cleared`, `chat.revision`. This is a contract guard, not behavioral UI test.

- [ ] **Step 2: Run to fail**

Run: `node --test tests/ui-contract.test.cjs`
Expected: FAIL missing IDs.

- [ ] **Step 3: Implement**

- Add `chat` state, `lastRevision`; on SSE open/sync, if `data.chat.revision !== lastRevision`, clear `messages`, reset pagination, fetch state/last page; do not merge stale pages.
- Render a per-message action button for `m.deviceId===me.id || me.host`; open confirm dialog; `DELETE /api/messages/:id`; remove from map/DOM; close image dialog if same file; toast freed bytes.
- Clear chat in settings: host-only; open preview dialog with counts/bytes/temp; confirm sends `operationId` + `revision`; on 202 poll `/api/operations/:id` until done/partial; then clear UI; show freed bytes and cleanup warning. On 409 refresh preview.
- Add SSE listeners `message_deleted` (remove id), `chat_cleared` (clear map, set revision/epoch, close media, render), and existing events.
- Version: `#app-version` displays native `appVersion` from `window.ryadom?.appVersion` or `server.version`; settings shows `serverVersion` separately. Do not label host version as client version.
- Protocol mismatch: if `server.protocol !== 3`, show `#update-screen` with "Обновите Рядом на всех устройствах" and do not open chat.
- Downloads button placeholder (Task 6 wires native bridge; if absent, toast "Доступно в приложении Рядом").

- [ ] **Step 4: Run tests**

Run: `node --test tests/ui-contract.test.cjs tests/functional.test.cjs`
Expected: PASS; manual browser smoke: delete own/other/host, clear with preview, offline reconnect, protocol mismatch via env.

- [ ] **Step 5: Commit**

```bash
git add public/app.js public/index.html public/style.css tests/ui-contract.test.cjs
git commit -m "0.3.0: web UI for message deletion, clear and protocol 3"
```

---

## Task 6: Android native downloads and startup version

**Files:**
- Modify: `android/src/local/ryadom/chat/MainActivity.java`, `AndroidManifest.xml`, `android/res/xml/file_paths.xml` (new), `public/app.js` (bridge contract only)
- Create: `android/src/local/ryadom/chat/Downloads.java` (or equivalent), `android/res/layout/downloads_dialog.xml` if needed
- Tests: extend `android/tests/local/ryadom/chat/AddressTest.java`/`TlsTest` for version; manual device test in Task 10

**Interfaces:**
- Produces: JavaScript bridge `window.ryadom = { appVersion, openDownloads() }`; no arbitrary path/command parameters.
- Produces: downloads saved by app are listed in a native dialog; opening uses `FileProvider` content URI; last file highlighted.
- Produces: startup screen shows `Рядом 0.3.0`.

- [ ] **Step 1: Add failing JVM/static checks**

Add to `AddressTest`/new `VersionTest`: assert `ChatHost.VERSION=="0.3.0"`, `PROTOCOL==3`, manifest versionCode 8; assert `MainActivity` source contains `addJavascriptInterface` restricted name and `openDownloads`.
Run `scripts/test-android.ps1`; expected FAIL.

- [ ] **Step 2: Implement**

- Add JS bridge in `showChat()` only for local WebView content (`addJavascriptInterface(new Bridge(), "ryadom")`); methods `appVersion()` and `openDownloads()`; methods take no arguments and are annotated `@JavascriptInterface`.
- Save downloads from WebView via `DownloadListener` into `getExternalFilesDir(DIRECTORY_DOWNLOADS)/Ryadom` using an app HTTP client that reuses cookies/TLS trust? If reusing the proxy is complex, list only files saved through the existing SAF flow and persist URIs in `SharedPreferences` (`downloads` JSON array). In either case, `openDownloads()` shows a native dialog listing saved items, opens via `ACTION_VIEW` with `FileProvider`, and shows the folder path.
- Add `file_paths.xml` for `external-files-path` and provider; no broad storage permission.
- Replace hardcoded caption `0.2.2` with `ChatHost.VERSION` / `BuildConfig`-like helper; show version in startup screen.
- If no downloads, show "Пока нет сохранённых файлов" and path.

- [ ] **Step 3: Build/test**

Run: `scripts/build-android.ps1`, `scripts/test-android.ps1`
Expected: APK 0.3.0; JVM tests PASS; manual: save file, tap downloads, open it.

- [ ] **Step 4: Commit**

```bash
git add android/src/local/ryadom/chat/MainActivity.java android/src/local/ryadom/chat/Downloads.java android/AndroidManifest.xml android/res/xml/file_paths.xml android/tests/local/ryadom/chat/AddressTest.java public/app.js
git commit -m "0.3.0: Android downloads button and version display"
```

---

## Task 7: Windows WebView2 shell, identity and downloads

**Files:**
- Create: `windows/ChatWindow.cs`, `windows/WebView2.cs` or references, `windows/Ryadom.ico`, `scripts/fetch-webview2.ps1`, `build/WebView2/...` (ignored), `tests/WindowsShellTest.cs` (if automatable)
- Modify: `windows/Launcher.cs`, `scripts/build-windows.cjs`, `windows/AssemblyInfo.cs`, `.gitignore`
- Tests: `scripts/test-windows.ps1` (existing) + manual Windows 11/10 matrix

**Interfaces:**
- Consumes: Node host/client on loopback; existing C# TLS bridge; `RolePicker` choice.
- Produces: `ChatWindow : Form` with WebView2, native toolbar (`Открыть загрузки`, version), `DownloadStarting` routed to `%USERPROFILE%\Downloads\Рядом`, `openDownloads` host object for JS.
- Produces: `SetCurrentProcessExplicitAppUserModelID("Ryadom.Chat")`, form icon, shortcut with icon and AUMID; tray actions unchanged.
- Produces: no Edge `--app` window for normal launch; fallback only if WebView2 Runtime missing.

- [ ] **Step 1: Add failing build/test guard**

Add `tests/WindowsShellTest.cs` that checks (via constants/source or a compiled helper) `ChatWindow` exists, `AppUserModelId=="Ryadom.Chat"`, download directory ends with `Downloads\Рядом`, and `Launcher` no longer starts a browser for normal open. Add to `scripts/test-windows.ps1`; expected FAIL until implementation.

- [ ] **Step 2: Fetch WebView2 SDK and wire build**

`scripts/fetch-webview2.ps1` downloads pinned `Microsoft.Web.WebView2` NuGet package (version + SHA-256 documented in script) to `.tools/webview2`; build script references `Microsoft.Web.WebView2.WinForms.dll`, `Microsoft.Web.WebView2.Core.dll`, copies `WebView2Loader.dll`. Fail build with clear message if missing; network required only for first build.

- [ ] **Step 3: Implement ChatWindow**

WinForms form with WebView2 filling client area, native toolbar; `EnsureCoreWebView2Async`; navigate to loopback URL; set `Form.Icon` from embedded ico; `SetCurrentProcessExplicitAppUserModelID`; `DownloadStarting` sets unique path under Downloads\Рядом and `Handled=true`; `openDownloads` host object uses `Process.Start("explorer.exe", ...)` fixed folder; version label from assembly; close-to-tray behavior; single-instance activation (mutex + `SetForegroundWindow` existing window).
Update `Launcher.OpenChat` to show/reuse `ChatWindow`; keep browser fallback only if WebView2 runtime unavailable, with explicit warning.

- [ ] **Step 4: Shortcut/pinning/icon**

Add menu items `Создать ярлык…` (Desktop/Start Menu) using `WScript.Shell`, icon `Ryadom.ico`, target stable `Ryadom-Windows.exe`, AUMID. Do not silently pin: add `Как закрепить на панели задач` info; attempt `Shell.Application` verb only if available and report failure. Ensure the running window uses the same icon; test pin/run/unpin on Windows 11.

- [ ] **Step 5: Build/test**

Run: `scripts/build-windows.cjs`, `scripts/test-windows.ps1`
Expected: build passes; window opens with Ryadom icon; downloaded file lands in `Downloads\Рядом`; button opens it; restart activates existing window; missing WebView2 shows message (simulate/uninstall on test machine only if safe).

- [ ] **Step 6: Commit**

```bash
git add windows/ChatWindow.cs windows/Ryadom.ico scripts/fetch-webview2.ps1 scripts/build-windows.cjs windows/Launcher.cs windows/AssemblyInfo.cs .gitignore tests/WindowsShellTest.cs
git commit -m "0.3.0: Windows WebView2 shell, icon, downloads and pinning"
```

---

## Task 8: Contract, failure and UI integration tests

**Files:**
- Modify: `tests/functional.test.cjs`, `tests/security.test.cjs`, `tests/server.test.cjs`, `scripts/test-android.ps1`, `docs/GUIDE.md`
- Create: `tests/reconnect.test.cjs` (or extend functional)
- Tests: run both hosts; no new production code unless a test exposes a bug.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: regression suite covering deletion/clear/permissions/reconnect/cleanup; docs for 0.3.0.

- [ ] **Step 1: Add tests for missed SSE and reconnect**

- Client online, delete message while SSE disconnected, reconnect with changed revision → deleted message absent.
- Clear while client offline; reconnect → empty history, files 404.
- Delete old page message; reload last page; no resurrection.
- Upload + clear concurrently: no committed file, reservation released, `.part` absent.
- Unlink failure simulated by making file path a directory/read-only; operation `partial`, quota not falsely freed; restart retry.
- Protocol 3 client gets 426/blocking screen for protocol 2 (test server behavior).
- Node and Java host run same suite (`RYADOM_TEST_JAVA`).

- [ ] **Step 2: Run all suites**

Run: `node --test tests/*.test.cjs` (including new), `scripts/test-android.ps1`, `scripts/test-windows.ps1`.
Expected: all PASS; fix discovered defects and add regressions.

- [ ] **Step 3: Update docs**

`docs/GUIDE.md`: deletion/clear semantics, downloads folder, Windows WebView2/pinning, version display, protocol 3 update warning. `CHANGELOG.md` 0.3.0; `README` version/links; `docs/ROADMAP` checkboxes for these items. Include explicit limitations: no iOS/chats in 0.3.0; external copies not deleted.

- [ ] **Step 4: Commit**

```bash
git add tests docs CHANGELOG.md README.md
git commit -m "0.3.0: integration tests and user documentation"
```

---

## Task 9: Release 0.3.0

**Files:**
- Modify: `dist` artifacts, `CHANGELOG.md`, `README.md`, `docs/ROADMAP.md`
- Scripts: existing `build-windows.cjs`, `build-android.ps1`, `sign-release.ps1`

**Interfaces:**
- Produces: signed Windows EXE (WebView2), signed APK, source zip, SHA256SUMS + SSH signature; GitHub release v0.3.0.

- [ ] **Step 1: Final version/build**

Set 0.3.0 everywhere; run Windows/Android builds; verify APK versionCode 8/signature and EXE version/icon; create source zip from final commit.

- [ ] **Step 2: Full verification**

Run all Node/Java/Windows suites + manual matrix: Windows 11/10, Android 8/12/15 (at least emulator/device available), host/client, delete/clear, downloads, pin/unpin, restart, WebView2 missing, old protocol client.

- [ ] **Step 3: Sign and publish**

Sign artifacts, push `main` and tag `v0.3.0`, create release with EXE/APK/source/SHA256SUMS/sig/START-HERE. Verify public downloads and hashes.

- [ ] **Step 4: Commit/tag**

Commit final docs/version changes, tag `v0.3.0`, push.

---

## Task 10: Independent Codex review and fixes

**Files:** none modified by reviewer; fixes in source as needed.

**Interfaces:**
- Consumes: candidate commit SHA and diff from base `21bc80d`.
- Produces: findings by severity with file:line; fixes; regression tests; final verification.

- [ ] **Step 1: Freeze candidate and prepare review packet**

Record base/candidate SHAs, scope, protocol 3 spec, deletion/clear algorithm, permission matrix, migration notes, test evidence, known manual gaps, screenshots of delete/clear/downloads/version/taskbar.

- [ ] **Step 2: Run read-only Codex review**

Use the isolated Codex CLI (or bridge if fixed) with the exact prompt: review deletion/clear under failure/concurrency, no resurrection, file access, quota truth, offline sync, Node/Java parity, native bridge security, WebView2 identity/pinning, version consistency. No edits.

- [ ] **Step 3: Triage and fix**

For each Critical/High/Medium: reproduce with a test where possible, fix, run affected suites, commit. Do not silently accept; document rejected findings with reason. Low findings either fix or record in roadmap.

- [ ] **Step 4: Re-verify**

Run all tests/builds; confirm release artifacts still match; if code changed after signing, rebuild/re-sign and update release assets.

- [ ] **Step 5: Final report**

State what was delegated, tokens, what Codex found, what was fixed, what remains unverified; link plan, commits, release.

---

## Self-Review

- **Spec coverage:** delete (Task 2/4/5), clear+files/temp (3/4/5), downloads (6/7), version (1/5/6/7), pin/icon (7). Chats and iOS explicitly out of 0.3.0 with user confirmation; recorded in plan.
- **Type consistency:** `chat.id='legacy'`, `revision`, `epoch`, `files.state`, `message.deletedAt`, `operationId` used consistently across Node/Java/UI.
- **Review Focus tests:** upload/delete race, stale revision, file access after delete, unlink failure, offline reconnect, WebView2 missing/pin.
- **Proportion:** tasks/decisions only; code bodies limited to interfaces/algorithms, not full transcripts.
