'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const e2ee = require(path.join(__dirname, '..', 'public', 'e2ee.js'));

test('0.5 E2E derives the same chat key and encrypts text', async () => {
 const alice = await e2ee.ensureIdentity('session-1', 'alice');
 const bob = await e2ee.ensureIdentity('session-1', 'bob');
 const aliceKey = await e2ee.deriveChatKey(alice.privateJwk, bob.publicKey, 'private-alice-bob', 'session-1');
 const bobKey = await e2ee.deriveChatKey(bob.privateJwk, alice.publicKey, 'private-alice-bob', 'session-1');
 const envelope = await e2ee.encryptText(aliceKey, 'секретное сообщение');
 const plain = await e2ee.decryptText(bobKey, envelope);
 assert.equal(plain, 'секретное сообщение');
 const safetyA = await e2ee.safetyNumber(alice.publicKey, bob.publicKey);
 const safetyB = await e2ee.safetyNumber(bob.publicKey, alice.publicKey);
 assert.equal(safetyA, safetyB);
 assert.match(safetyA, /^[0-9A-F]{4}( [0-9A-F]{4}){7}$/);
 const bytes = new TextEncoder().encode('encrypted attachment bytes');
 const file = await e2ee.encryptBytes(aliceKey, bytes);
 const decrypted = await e2ee.decryptBytes(bobKey, file.iv, file.data);
 assert.equal(new TextDecoder().decode(decrypted), 'encrypted attachment bytes');
});
