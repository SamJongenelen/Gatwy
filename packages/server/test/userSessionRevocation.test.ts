import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-usersessionrevocation-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'user-session-revocation-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { hashToken } = await import('../src/services/loginSession.js');
const { registerWs } = await import('../src/ws/wsRegistry.js');
const { authRequired } = await import('../src/middleware/auth.js');
const { default: usersRouter } = await import('../src/routes/users.js');
const { default: profileRouter } = await import('../src/routes/profile.js');
const { default: authRouter } = await import('../src/routes/auth.js');
const { default: bcrypt } = await import('bcryptjs');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let adminToken: string;

function seedUser(id: string, role: string): string {
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [id, id, 'x', id, role],
  );
  const token = signToken({ userId: id, username: id, role });
  execute(
    `INSERT INTO login_sessions (id, user_id, token_hash) VALUES (?, ?, ?)`,
    [`ls-${id}`, id, hashToken(token)],
  );
  return token;
}

before(async () => {
  await initDb();
  initJwt();

  adminToken = seedUser('admin', 'admin');

  const app = express();
  app.use(express.json());
  app.use('/api/v1/users', usersRouter);
  app.use('/api/v1/profile', profileRouter);
  app.use('/api/v1/auth', authRouter);
  // Stand-in for any authenticated route: what matters is whether authRequired lets the token in.
  app.get('/api/v1/probe', authRequired, (_req, res) => { res.json({ ok: true }); });
  await new Promise<void>((resolve) => {
    server = app.listen(0, resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1`;
});

after(() => new Promise<void>((resolve) => {
  server.close(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
    resolve();
  });
  // fetch keeps connections alive; without this close() waits on them indefinitely.
  server.closeAllConnections();
}));

function call(token: string, url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${baseUrl}${url}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
}

describe('user admin actions revoke live sessions', () => {
  it('a deleted user token stops working', async () => {
    const token = seedUser('victim-deleted', 'user');
    assert.equal((await call(token, '/probe')).status, 200);

    assert.equal((await call(adminToken, '/users/victim-deleted', { method: 'DELETE' })).status, 200);
    assert.equal(queryOne('SELECT id FROM users WHERE id = ?', ['victim-deleted']), undefined);

    assert.equal((await call(token, '/probe')).status, 401);
  });

  it('a role change invalidates the old token; unchanged role does not', async () => {
    const token = seedUser('victim-role', 'user');

    const same = await call(adminToken, '/users/victim-role', { method: 'PUT', body: JSON.stringify({ role: 'user', displayName: 'Renamed' }) });
    assert.equal(same.status, 200);
    assert.equal((await call(token, '/probe')).status, 200, 'resending the same role must not log the user out');

    const changed = await call(adminToken, '/users/victim-role', { method: 'PUT', body: JSON.stringify({ role: 'admin' }) });
    assert.equal(changed.status, 200);
    assert.equal((await call(token, '/probe')).status, 401);
  });

  it('changing your own role is rejected and revokes nothing; re-saving the same role is fine', async () => {
    const token = seedUser('self-admin', 'admin');
    // Different lifetime so the JWT (and its hash) differs from `token` even within the same second.
    const other = signToken({ userId: 'self-admin', username: 'self-admin', role: 'admin' }, 60);
    execute('INSERT INTO login_sessions (id, user_id, token_hash) VALUES (?, ?, ?)', ['ls-self-admin-2', 'self-admin', hashToken(other)]);

    const rejected = await call(token, '/users/self-admin', { method: 'PUT', body: JSON.stringify({ role: 'user' }) });
    assert.equal(rejected.status, 400);
    assert.equal(queryOne<{ role: string }>('SELECT role FROM users WHERE id = ?', ['self-admin'])?.role, 'admin');
    assert.equal((await call(token, '/probe')).status, 200);
    assert.equal((await call(other, '/probe')).status, 200, 'a rejected change must not revoke any session');

    // The client resends the unchanged role on every save of the own profile.
    const same = await call(token, '/users/self-admin', { method: 'PUT', body: JSON.stringify({ role: 'admin', displayName: 'Me' }) });
    assert.equal(same.status, 200);
    assert.equal((await call(other, '/probe')).status, 200);
  });

  it('a password reset revokes the target user sessions', async () => {
    const token = seedUser('victim-reset', 'user');
    const res = await call(adminToken, '/users/victim-reset/reset-password', { method: 'POST', body: JSON.stringify({ newPassword: 'longenough1' }) });
    assert.equal(res.status, 200);
    assert.equal((await call(token, '/probe')).status, 401);
  });

  it('a token whose user and session rows are both gone is rejected (state after FK cascade)', async () => {
    // With foreign keys enforced, deleting a user cascades its login_sessions away, so the
    // token has no session row ('not_found', which authRequired lets through). Simulate that.
    const token = seedUser('victim-cascaded', 'user');
    assert.equal((await call(token, '/probe')).status, 200);

    execute('DELETE FROM login_sessions WHERE user_id = ?', ['victim-cascaded']);
    execute('DELETE FROM users WHERE id = ?', ['victim-cascaded']);

    assert.equal((await call(token, '/probe')).status, 401);
  });

  it('changing your own password revokes your other sessions, not the current one', async () => {
    const token = seedUser('pw-changer', 'user');
    execute('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync('oldpassword1', 4), 'pw-changer']);
    const other = signToken({ userId: 'pw-changer', username: 'pw-changer', role: 'user' }, 60);
    execute('INSERT INTO login_sessions (id, user_id, token_hash) VALUES (?, ?, ?)', ['ls-pw-changer-2', 'pw-changer', hashToken(other)]);

    const res = await call(token, '/profile/password', { method: 'PUT', body: JSON.stringify({ currentPassword: 'oldpassword1', newPassword: 'newpassword1' }) });
    assert.equal(res.status, 200);
    assert.equal((await call(token, '/probe')).status, 200);
    assert.equal((await call(other, '/probe')).status, 401);
  });

  it('closes terminal sockets already open on the revoked sessions, not the spared one', async () => {
    // The proxies only check isSessionRevoked() at connect time, so a session that is
    // already open would otherwise outlive a password reset / user delete.
    const token = seedUser('ws-victim', 'user');
    const spared = signToken({ userId: 'ws-victim', username: 'ws-victim', role: 'user' }, 60);
    execute('INSERT INTO login_sessions (id, user_id, token_hash) VALUES (?, ?, ?)', ['ls-ws-victim-2', 'ws-victim', hashToken(spared)]);

    const fakeWs = () => {
      const closed: Array<[number, string]> = [];
      return { closed, on() {}, close(code: number, reason: string) { closed.push([code, reason]); } };
    };
    const revokedWs = fakeWs();
    const sparedWs = fakeWs();
    registerWs(hashToken(token), revokedWs as never);
    registerWs(hashToken(spared), sparedWs as never);

    // Spare  by acting as that session (password change from the profile page).
    execute('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync('oldpassword1', 4), 'ws-victim']);
    const res = await call(spared, '/profile/password', { method: 'PUT', body: JSON.stringify({ currentPassword: 'oldpassword1', newPassword: 'newpassword1' }) });
    assert.equal(res.status, 200);

    assert.deepEqual(revokedWs.closed, [[4001, 'Session revoked']]);
    assert.deepEqual(sparedWs.closed, []);
  });

  it('logout closes the terminal sockets open on that session, and only on it', async () => {
    const token = seedUser('logout-user', 'user');
    // Different lifetime so this JWT (and its hash) differs from `token` even within the same second.
    const other = signToken({ userId: 'logout-user', username: 'logout-user', role: 'user' }, 60);
    execute('INSERT INTO login_sessions (id, user_id, token_hash) VALUES (?, ?, ?)', ['ls-logout-user-2', 'logout-user', hashToken(other)]);

    const closed = (bucket: Array<[number, string]>) => ({ on() {}, close(code: number, reason: string) { bucket.push([code, reason]); } });
    const loggedOut: Array<[number, string]> = [];
    const untouched: Array<[number, string]> = [];
    registerWs(hashToken(token), closed(loggedOut) as never);
    registerWs(hashToken(other), closed(untouched) as never);

    const res = await call(token, '/auth/logout', { method: 'POST' });
    assert.equal(res.status, 200);

    assert.equal((await call(token, '/probe')).status, 401);
    assert.deepEqual(loggedOut, [[4001, 'Session revoked']]);
    assert.deepEqual(untouched, []);
    assert.equal((await call(other, '/probe')).status, 200);
  });
});
