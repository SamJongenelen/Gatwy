// Regression test: signToken() used to return byte-identical tokens for the same user within the
// same second (payload + iat/exp at 1 s resolution, nothing random). createLoginSession then hit
// login_sessions.token_hash UNIQUE on the second login and the route answered 500 — after the
// UPDATE that revokes the sessions of the same device had already run. Each token now carries a
// random jti.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, before, after } from 'node:test';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-token-uniq-test-'));
process.env.DATA_DIR = tmpDir;
process.env.JWT_SECRET = 'login-token-uniqueness-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute, queryAll } = await import('../src/db/helpers.js');
const { initJwt, signToken, verifyToken } = await import('../src/services/jwt.js');
const { createLoginSession, hashToken } = await import('../src/services/loginSession.js');

const USER_ID = 'user-1';
const payload = { userId: USER_ID, username: 'alice', role: 'user' };

before(async () => {
  await initDb();
  initJwt();
  execute(
    `INSERT INTO users (id, username, display_name, password_hash, role) VALUES (?, 'alice', 'Alice', 'x', 'user')`,
    [USER_ID],
  );
});

after(() => {
  stopAutoSave();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const fakeReq = (ua: string, ip: string) => ({
  headers: { 'user-agent': ua },
  socket: { remoteAddress: ip },
}) as unknown as Parameters<typeof createLoginSession>[0];

describe('login tokens are unique', () => {
  it('two tokens for the same user in the same second differ', () => {
    const a = signToken(payload);
    const b = signToken(payload);
    assert.notEqual(a, b);
    assert.notEqual(hashToken(a), hashToken(b));
  });

  it('both tokens verify and carry the same claims', () => {
    const a = verifyToken(signToken(payload));
    const b = verifyToken(signToken(payload));
    assert.equal(a.userId, USER_ID);
    assert.equal(b.username, 'alice');
    assert.equal(a.role, 'user');
  });

  it('tokens issued before this change (no jti) still verify', async () => {
    const { default: jwt } = await import('jsonwebtoken');
    const legacy = jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: 60 });
    assert.equal(verifyToken(legacy).userId, USER_ID);
  });
});

describe('createLoginSession on back-to-back logins', () => {
  it('does not throw for two logins in the same second from different devices', () => {
    createLoginSession(fakeReq('Mozilla/5.0 (Windows NT 10.0) Chrome/120', '203.0.113.1'), USER_ID, signToken(payload));
    assert.doesNotThrow(() => {
      createLoginSession(fakeReq('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/605', '203.0.113.2'), USER_ID, signToken(payload));
    });
    const rows = queryAll<{ revoked: number }>('SELECT revoked FROM login_sessions WHERE user_id = ?', [USER_ID]);
    assert.equal(rows.filter((r) => r.revoked === 0).length, 2, 'both sessions stay active');
  });

  it('does not throw for two logins in the same second from the same device (the older one is replaced by design)', () => {
    execute('DELETE FROM login_sessions');
    const req = fakeReq('Mozilla/5.0 (X11; Linux x86_64) Firefox/121', '198.51.100.7');
    const first = signToken(payload);
    createLoginSession(req, USER_ID, first);
    assert.doesNotThrow(() => createLoginSession(req, USER_ID, signToken(payload)));
    const rows = queryAll<{ token_hash: string; revoked: number }>('SELECT token_hash, revoked FROM login_sessions ORDER BY rowid');
    assert.equal(rows.length, 2);
    assert.equal(rows.find((r) => r.token_hash === hashToken(first))?.revoked, 1, 'first session replaced');
    assert.equal(rows.filter((r) => r.revoked === 0).length, 1, 'exactly one active session remains');
  });
});
