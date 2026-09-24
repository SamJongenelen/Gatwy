import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-session-history-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'session-history-survives-deletion-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: sessionsRouter } = await import('../src/routes/sessions.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let ownerToken: string;
const ownerId = 'user-session-history-owner';
const connectionId = 'conn-session-history';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['session-history-role', 'Session History Role', 'can create connections', JSON.stringify(['connections.create'])],
  );
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [ownerId, 'session-history-owner', 'x', 'Session History Owner', 'session-history-role'],
  );
  ownerToken = signToken({ userId: ownerId, username: 'session-history-owner', role: 'session-history-role' });

  execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port, recording_enabled)
     VALUES (?, ?, NULL, ?, 'rdp', 'h', 3389, 1)`,
    [connectionId, ownerId, 'History Connection'],
  );
  // Global recording default is 'false' — this route only inserts a sessions row at all
  // when recording is actually on.
  execute(`UPDATE settings SET value = 'true' WHERE key = 'session.recording_enabled'`);

  const app = express();
  app.use(express.json());
  app.use('/api/v1/sessions', sessionsRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1/sessions`;
});

after(() => new Promise<void>((resolve) => server.close(() => {
  closeDb();
  fs.rmSync(dataDir, { recursive: true, force: true });
  resolve();
})));

function authedFetch(token: string, url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
}

describe('session history survives the deletion of its user and connection', () => {
  it('keeps the session row (with a readable username/connection_name snapshot) after both are gone', async () => {
    const res = await authedFetch(ownerToken, `${baseUrl}/rdp-session`, {
      method: 'POST',
      body: JSON.stringify({ connectionId }),
    });
    assert.equal(res.status, 200);
    const { sessionId } = await res.json() as { sessionId: string };
    assert.ok(sessionId, 'a session row should have been created (recording_enabled=1 on the connection, global recording turned on above)');

    // No FK on sessions.user_id/connection_id — this must succeed and must NOT
    // cascade the session row away, unlike connection_groups/connections themselves.
    execute('DELETE FROM connections WHERE id = ?', [connectionId]);
    execute('DELETE FROM users WHERE id = ?', [ownerId]);

    const row = queryOne<{ id: string; username: string | null; connection_name: string | null }>(
      'SELECT id, username, connection_name FROM sessions WHERE id = ?',
      [sessionId],
    );
    assert.ok(row, 'the session row must survive deleting its user and connection');
    assert.equal(row?.username, 'session-history-owner', 'who ran the session must stay legible even after the user is gone');
    assert.equal(row?.connection_name, 'History Connection', 'which connection must stay legible even after it is gone');
  });
});
