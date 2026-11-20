# 0.3 «Идентичность устройств и эфемерный чат» — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) или `executing-plans`, чтобы выполнять план по задачам. Шаги отмечены `- [ ]`.

**Goal:** Сделать устойчивую идентичность устройств/главного и один общий эфемерный чат, который очищается при завершении главного; протокол 4.

**Architecture:** История не реплицируется. Главный владеет одной сессией; смена главного завершает её и начинает пустую. Между устройствами реплицируется только control plane: публичные identity, trust roster и handoff. IP — маршрут, не идентичность. Пункт 1.1 «Постоянная идентичность главного» входит сюда; остальные пункты 1.1 не входят.

**Tech Stack:** Node.js 26 + `node:sqlite`, C# WinForms/CNG, Android Java/Keystore, TLS 1.2, WebView2.

**Spec:** [docs/superpowers/specs/2026-11-21-identity-ephemeral-chat-0.3.md](../specs/2026-11-21-identity-ephemeral-chat-0.3.md)

## Global Constraints

- Протокол: **4**. v3-клиенты не допускаются к auth/pairing и получают «обновите Рядом».
- Версия релиза: **0.4.0**, Android `versionCode 12`; версии меняются только в последней задаче.
- Один главный; без автоматического failover; handoff только явный и адресный.
- История/файлы/tombstones между главными не передаются.
- При штатном завершении главного история очищается у всех; при crash — до открытия listener.
- Настройки, identity, TLS, trust roster и known hosts сохраняются.
- Приватные ключи не покидают CNG/Keystore и не попадают в JS, URL, cookie или командную строку.
- IP не является ключом доверия; TLS pin индексируется `hostDeviceId`.
- Только пункт 1.1 «Постоянная идентичность главного»; остальные 1.1 не делать.

## Review Focus

- Смена IP при том же host ID не должна создавать новое устройство.
- Тот же IP с другим host ID/сертификатом должен блокироваться.
- Штатное выключение главного должно очищать историю, но не identity/trust.
- Kill -9 должен оставлять marker и очищать остатки до listener.
- Старые SSE/сообщения предыдущей сессии не должны воскресать в UI.
- Handoff не должен передавать историю и не должен приниматься чужим устройством.

---

### Task 1: Контракты protocol 4 и session envelope

**Files:**
- Modify: `server.cjs`, `android/src/local/ryadom/chat/ChatHost.java`, `public/app.js`
- Modify: `tests/functional.test.cjs`, `tests/ui-contract.test.cjs`, `android/tests/local/ryadom/chat/FunctionalTest.java`
- Test: `tests/protocol4.test.cjs` (create)

**Interfaces:**
- Produces: `PROTOCOL=4`; `chat.sessionId`, `chat.term`, `chat.hostDeviceId`; `sessionId` в каждом message/SSE/session event.
- Produces: `/api/state.chat` envelope; v3 → `426 update_required`.
- Consumes: existing revision/epoch/deletionRevision.

- [ ] **Step 1:** Написать failing test: Node/Android state содержит `sessionId/term/hostDeviceId`; protocol 3 отклоняется.
- [ ] **Step 2:** Запустить test, увидеть fail.
- [ ] **Step 3:** Добавить константы/protocol gate/envelope в Node, Android, UI.
- [ ] **Step 4:** Запустить `npm test` и Android functional; PASS.
- [ ] **Step 5:** Commit `feat(protocol): add session envelope and protocol 4 gate`.

### Task 2: Платформенная identity устройства

**Files:**
- Create: `windows/DeviceIdentity.cs`
- Create: `android/src/local/ryadom/chat/DeviceIdentity.java`
- Create: `tests/windows-identity.test.cjs`, `android/tests/local/ryadom/chat/DeviceIdentityTest.java`
- Modify: `windows/Launcher.cs`, `windows/RolePicker.cs`, `android/MainActivity.java`, `android/HostService.java`

**Interfaces:**
- Produces: `DeviceIdentity.Current(dataDir) -> { DeviceId, PublicKeySpki, Fingerprint, Sign(nonce) }`.
- Windows: CNG RSA-3072, non-exportable key + DPAPI/ACL; Android: Keystore alias `ryadom-device-v1`.
- Produces: `DeviceId = "d1-" + base64url(SHA256(SPKI))`.

- [ ] **Step 1:** Failing test: два вызова дают один ID; подпись проверяется публичным ключом; удаление данных создаёт новый ID.
- [ ] **Step 2:** Запустить C#/JVM tests, fail.
- [ ] **Step 3:** Реализовать Windows/Android identity и инициализацию до RolePicker/HostService.
- [ ] **Step 4:** Tests PASS; `deviceId` не меняется между перезапусками.
- [ ] **Step 5:** Commit `feat(identity): persist device key and id`.

### Task 3: Control store и trust roster

**Files:**
- Modify: `server.cjs` (таблицы `group_meta`, `trusted_devices`, `trust_operations`, `known_hosts`)
- Create: `android/src/local/ryadom/chat/TrustStore.java`
- Modify: `ChatHost.java`
- Test: `tests/trust.test.cjs`, `android/tests/.../TrustStoreTest.java`

**Interfaces:**
- Produces: `groupId`, `rosterRevision`, `rosterHeadHash`.
- Produces: `trust_operations(revision, previousHash, type, subjectDeviceId, publicKey, payload, signerDeviceId, signature)`.
- Produces: `GET /api/trust/sync?after=N` (signed, append-only).
- Consumes: DeviceIdentity public key.

- [ ] **Step 1:** Failing tests: upsert same ID/key; conflict same ID/different key; revoke survives restart; stale snapshot rejected.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement SQLite/JSON trust store and hash-chain verification.
- [ ] **Step 4:** Tests PASS, including replay/revoke.
- [ ] **Step 5:** Commit `feat(trust): add signed roster control plane`.

### Task 4: Host identity, TLS binding и `/api/identity`

**Files:**
- Modify: `server.cjs`, `ChatHost.java`, `windows/TlsIdentity.cs`, `android/TlsTrust.java`
- Test: `tests/identity.test.cjs`, `tests/WindowsTransportTest.cs`, `android/.../IdentityTest.java`

**Interfaces:**
- Produces: host signed binding `{hostDeviceId, identityFingerprint, tlsFingerprint, protocol, notAfter, signature}`.
- Produces: `GET /api/identity?nonce=...`; `/api/health` минимум.
- Consumes: DeviceIdentity private key; existing TLS cert.

- [ ] **Step 1:** Failing test: binding verifies; wrong TLS fingerprint/signature rejected; cert rotation with old identity signature accepted.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement binding and identity endpoint on Node/Android.
- [ ] **Step 4:** Tests PASS; v3 clients blocked.
- [ ] **Step 5:** Commit `feat(identity): sign host tls binding`.

### Task 5: Pairing/auth v4

**Files:**
- Modify: `server.cjs`, `ChatHost.java`, `public/app.js`, `windows/RolePicker.cs`, `android/MainActivity.java`
- Test: `tests/security.test.cjs`, `tests/functional.test.cjs`, Android `SessionSecurityTest.java`

**Interfaces:**
- Produces: `POST /api/pair` body `{deviceId, publicKey, proof, name, code}`.
- Produces: challenge-response `POST /api/auth/challenge` + `/api/auth`.
- Produces: known device reconnect without code when roster contains key/ID.
- Consumes: trust roster, DeviceIdentity.

- [ ] **Step 1:** Failing tests: known device connects without code; new device needs code+approval; same ID/different key rejected; replay challenge rejected.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement UPSERT pairing and challenge auth on both hosts; keep cookie session short-lived.
- [ ] **Step 4:** Tests PASS.
- [ ] **Step 5:** Commit `feat(auth): pair and reconnect by device identity`.

### Task 6: Session storage, sessionId и crash marker

**Files:**
- Modify: `server.cjs`, `ChatHost.java`
- Create: `windows/SessionMarker.cs` (or logic in launcher)
- Test: `tests/session.test.cjs`, Android `SessionTest.java`

**Interfaces:**
- Produces: `sessions/<sessionId>/chat.sqlite`/`chat.json`; `runtime.json {sessionId,hostDeviceId,term,state}` fsync before listen.
- Produces: startup recovery removes `.deleting-*`, `.part`, stale ACTIVE before listener.
- Consumes: existing clear/cleanup helpers.

- [ ] **Step 1:** Failing test: fresh host gets new sessionId; restart with marker ACTIVE clears old history before listener; clean stop removes marker.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Move ephemeral tables/files into session dir; marker lifecycle; recovery.
- [ ] **Step 4:** Tests PASS; old session data inaccessible after rename.
- [ ] **Step 5:** Commit `feat(session): isolate ephemeral chat and crash marker`.

### Task 7: `endSession` и штатное завершение

**Files:**
- Modify: `server.cjs`, `ChatHost.java`, `windows/Launcher.cs`, `android/HostService.java`
- Modify: `public/app.js`, `public/index.html`
- Test: `tests/session.test.cjs`, `android/.../SessionTest.java`, `tests/ui-contract.test.cjs`

**Interfaces:**
- Produces: `endSession(reason)` state machine ACTIVE→ENDING→ENDED.
- Produces: SSE `session_ending`/`session_ended`; 409 `session_ending` for new messages/uploads.
- Produces: Windows/Android stop calls endSession before process/service exit.
- Consumes: clear helper, upload cancel/wait, session dir.

- [ ] **Step 1:** Failing tests: stop clears messages/files; clients receive ending; late upload rejected; identity/trust preserved.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement endSession and wire Windows/Android stop/quit.
- [ ] **Step 4:** Tests PASS; manual stop leaves empty next session.
- [ ] **Step 5:** Commit `feat(session): end and clear ephemeral chat on shutdown`.

### Task 8: UI: session reset, stale events, copy

**Files:**
- Modify: `public/app.js`, `public/index.html`, `windows/Launcher.cs`, `android/MainActivity.java`
- Test: `tests/ui-contract.test.cjs` (+ DOM test if harness available)

**Interfaces:**
- Produces: `applySessionState` clears on sessionId change; ignores stale sessionId SSE.
- Produces: confirmation texts “история будет удалена у всех”, no “история сохранится”.
- Consumes: `chat.sessionId`, `session_ending`.

- [ ] **Step 1:** Failing UI tests: different sessionId clears; same session preserves; stale event ignored; copy contains warning.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement UI reset/copy for Windows/Android/web.
- [ ] **Step 4:** Tests PASS; no old image/dialog after session end.
- [ ] **Step 5:** Commit `feat(ui): reset on ephemeral session change`.

### Task 9: Discovery V2 и reconnect по host ID (пункт 1.1)

**Files:**
- Modify: `windows/LanTransport.cs`, `windows/RolePicker.cs`, `windows/Launcher.cs`
- Modify: `android/Discovery.java`, `MainActivity.java`
- Modify: `server.cjs` (health), `ChatHost.java`
- Test: `tests/WindowsTransportTest.cs`, Android `DiscoveryTest.java`, `tests/identity.test.cjs`

**Interfaces:**
- Produces: discovery `RYADOM_HERE_V2` fields `{protocol,groupId,hostDeviceId,identityFingerprint,tlsFingerprint,sessionId,term,rosterHeadHash,address,port,name,signature}`.
- Produces: known-host resolver `FindByHostId(hostDeviceId)`; updates `last-target` atomically.
- Consumes: host identity/binding.

- [ ] **Step 1:** Failing tests: changed IP found by host ID; same IP with other host ID rejected; fake discovery signature rejected.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement V2 discovery + resolver + pin keyed by hostDeviceId.
- [ ] **Step 4:** Tests PASS; Windows/Android reconnect after DHCP change.
- [ ] **Step 5:** Commit `feat(discovery): reconnect by host identity, not ip`.

### Task 10: Handoff и смена главного

**Files:**
- Modify: `server.cjs`, `ChatHost.java`, `windows/RolePicker.cs`, `android/MainActivity.java`, `public/app.js`
- Test: `tests/handoff.test.cjs`, Android `HandoffTest.java`

**Interfaces:**
- Produces: signed handoff `{groupId,from,to,oldSessionId,nextTerm,rosterHeadHash,nonce,expires}`.
- Produces: `POST /api/host/handoff/prepare|accept`; only target accepts, once.
- Consumes: trust roster, session end.

- [ ] **Step 1:** Failing tests: handoff clears old session, starts empty new; wrong target/replay rejected; roster preserved.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement prepare/accept and UI confirmation of target/history loss.
- [ ] **Step 4:** Tests PASS; no automatic failover.
- [ ] **Step 5:** Commit `feat(handoff): targeted ephemeral host transfer`.

### Task 11: Миграция v3 → v4

**Files:**
- Modify: `server.cjs`, `ChatHost.java`, `public/app.js`, `windows/Launcher.cs`, `android/MainActivity.java`
- Create: `docs/MIGRATION-0.4.md`
- Test: `tests/migration.test.cjs`, Android `MigrationTest.java`

**Interfaces:**
- Produces: legacy host auto-link; legacy client claim once; old address pin migration only with same cert; v3 client `426`.
- Consumes: old DB/cookies/pin files.

- [ ] **Step 1:** Failing tests: legacy cookie claims once; no key → pairing; stale pin not silently trusted; v3 blocked.
- [ ] **Step 2:** Run fail.
- [ ] **Step 3:** Implement migration and warning before first legacy clear.
- [ ] **Step 4:** Tests PASS; v3 binary cannot open new store.
- [ ] **Step 5:** Commit `feat(migration): upgrade protocol 3 to 4`.

### Task 12: Release 0.4.0, tests, Codex review

**Files:**
- Modify: versions, `README.md`, `CHANGELOG.md`, `docs/GUIDE.md`, `docs/ROADMAP.md`, `dist/START-HERE.txt`
- Create: `docs/releases/0.4.0.md`
- Modify: `tests/version.test.cjs`

- [ ] **Step 1:** Bump 0.4.0/versionCode 12/protocol 4; update docs.
- [ ] **Step 2:** Run `npm test`, build/test Windows/Android, verify v3 rejection.
- [ ] **Step 3:** Codex review (read-only) and fix findings.
- [ ] **Step 4:** Build/sign/publish v0.4.0; update roadmap completed section.
- [ ] **Step 5:** Commit/tag/push.

## Self-review

- Spec coverage: identity, trust, session, shutdown, crash, discovery, handoff, migration, release — tasks 1–12.
- 1.1 overlap: Task 9 explicitly implements permanent host identity; other 1.1 items excluded.
- Risks: split-brain unsolved by design; no history replication; no external key recovery; no v3 coexistence.
