# 0.5: частные эфемерные E2E-чаты — спецификация

**Дата:** 22.11.2026  
**Статус:** проект  
**Связано:** [ROADMAP 0.5](../ROADMAP.md)

## Контракт

- 0.5 добавляет **только** частные эфемерные E2E-диалоги. Группы, экспорт, QR и большие передачи — 0.6–0.9.
- Все чаты живут в текущей сессии главного; при её завершении сообщения, вложения и ключи сессии уничтожаются.
- Общий чат 0.4 остаётся доступен всем устройствам; частный диалог — только выбранным участникам (и UI главного не получает его содержимое).
- Сервер хранит только ciphertext, IV, метаданные чата и участников; plaintext и приватные ключи не попадают на сервер.

## E2E-модель

- Каждое устройство при открытии UI генерирует **ECDH P-256** пару на текущую `sessionId`.
- Приватный JWK хранится в IndexedDB с ключом `ryadom-key:<sessionId>`; публичный ключ отправляется на главный.
- Для личного диалога A↔B каждая сторона вычисляет ECDH shared secret из своего приватного и публичного ключа другого участника.
- Из shared secret выводится AES-256-GCM ключ через HKDF-SHA-256 с контекстом `ryadom-private:<chatId>:<sessionId>`.
- Safety number — SHA-256 от отсортированных публичных ключей A и B, показывается в диалоге. Без сверки — TOFU-предупреждение.
- Сервер может подменить публичные ключи; E2E-гарантия от хоста достигается только после сверки safety number вне канала.
- Ключи и расшифрованная история не сохраняются после завершения сессии главного.

## Модель данных

```
chats(id, type, title, created, sessionId)
chat_members(chatId, deviceId, joinedAt, lastReadSeq)
messages(..., chatId, text, encrypted INTEGER)
files(..., chatId, encrypted INTEGER)
device_keys(sessionId, deviceId, publicKey, algorithm, createdAt)
```

- `legacy` — общий чат.
- `private:<hash(sorted A,B)>` — один диалог на пару в сессии.
- `chat_members` для legacy не нужен: доступ всех устройств; для private — только участники.
- `lastReadSeq` — на устройство; сервер считает unread.

## API

```
GET  /api/chats                      список доступных чатов + unread/last
POST /api/chats {type:'private', peerDeviceId}
GET  /api/chats/:id/messages
POST /api/chats/:id/read {seq}
POST /api/keys {publicKey, algorithm}
GET  /api/keys?deviceIds=...         публичные ключи участников
POST /api/messages {chatId, text, encrypted, requestId}
POST /api/files?chatId=...           ciphertext
GET  /files/:id                       ciphertext (download then decrypt)
```

- Для private `text` — JSON `{v:1,iv,data}` (base64url); сервер валидирует размер и не логирует содержимое.
- Для private файлы шифруются на устройстве; имя/MIME передаются в зашифрованном envelope, сервер хранит только ciphertext и непрозрачный blob.
- SSE message/deleted/cleared содержат `chatId`; клиент фильтрует по активному чату и участнику.

## UI

- Список чатов в сайдбаре: «Свои устройства» (legacy) + личные диалоги; бейдж unread.
- Создание: выбрать устройство из списка, отправить приглашение; получатель принимает/отклоняет.
- При открытии private — проверка ключей, safety number, предупреждение TOFU.
- Отправка текста/файла шифруется до API; вложения отображаются через object URL после расшифровки.
- Мобильная компоновка: список чатов / активный диалог.

## Ограничения 0.5

- Только два участника; группы — 0.6.
- Ключи per-session; после перезапуска главного история и ключи исчезают.
- Нет восстановления ключей и переноса истории.
- Хост видит метаданные (кто, когда, размер), но не содержимое; при подмене ключей safety number нужно сверять.
- WebCrypto должен поддерживаться WebView2/Android WebView; при отсутствии — private chats отключаются с объяснением.
