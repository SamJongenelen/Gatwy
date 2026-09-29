import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-sessionspurge-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'sessions-purge-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: sessionsRouter } = await import('../src/routes/sessions.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let adminToken: string;

const OWNER = 'user-purge-owner';
const CONN = 'conn-purge-owner';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    ['user-purge-admin', 'purge-admin', 'x', 'Purge Admin', 'admin'],
  );
  adminToken = signToken({ userId: 'user-purge-admin', username: 'purge-admin', role: 'admin' });

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

describe('DELETE / (sessions purge) — clears db_query_history', () => {
  it('removes query history whose connection and user no longer exist, and reports the count', async () => {
    // db_query_history has no FK on user_id/connection_id (v24) — history deliberately
    // survives deleting its user or connection. The purge is therefore the only way rows
    // for a deleted connection can ever be removed (DELETE /db/:connectionId/history 404s
    // once the connection is gone).
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [OWNER, 'purge-owner', 'x', 'Purge Owner', 'user'],
    );
    execute(
      `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port) VALUES (?, ?, NULL, ?, 'ssh', 'h', 22)`,
      [CONN, OWNER, 'Purge Conn'],
    );
    execute(
      `INSERT INTO db_query_history (id, user_id, connection_id, query_text, username, connection_name) VALUES (?, ?, ?, ?, ?, ?)`,
      ['q-orphan', OWNER, CONN, 'SELECT 1', 'purge-owner', 'Purge Conn'],
    );
    execute(
      `INSERT INTO db_query_history (id, user_id, connection_id, query_text) VALUES (?, ?, ?, ?)`,
      ['q-never-had-parent', 'ghost-user', 'ghost-conn', 'SELECT 2'],
    );

    // Delete the connection and its owner: FK enforcement is on, and the history must survive.
    execute('DELETE FROM connections WHERE id = ?', [CONN]);
    execute('DELETE FROM users WHERE id = ?', [OWNER]);
    assert.ok(queryOne('SELECT id FROM db_query_history WHERE id = ?', ['q-orphan']), 'precondition: history survives deleting its connection and user');

    const res = await authedFetch(adminToken, baseUrl, { method: 'DELETE' });
    assert.equal(res.status, 200);
    const body = await res.json() as { deletedQueryHistory: number };
    assert.equal(body.deletedQueryHistory, 2, 'both the orphaned rows and the parentless one are counted');

    assert.equal(queryOne('SELECT id FROM db_query_history WHERE id = ?', ['q-orphan']), undefined, 'orphaned history must be purged');
    assert.equal(queryOne('SELECT id FROM db_query_history WHERE id = ?', ['q-never-had-parent']), undefined, 'history with no parent rows must be purged');
  });

  it('records the deleted query-history count in the audit log', async () => {
    execute(
      `INSERT INTO db_query_history (id, user_id, connection_id, query_text) VALUES (?, ?, ?, ?)`,
      ['q-audit', 'ghost-user', 'ghost-conn', 'SELECT 3'],
    );

    const res = await authedFetch(adminToken, baseUrl, { method: 'DELETE' });
    assert.equal(res.status, 200);

    const audit = queryOne<{ details_json: string }>(
      `SELECT details_json FROM audit_log WHERE event_type = 'admin.sessions.purge' ORDER BY rowid DESC LIMIT 1`,
    );
    assert.ok(audit, 'purge must be audit-logged');
    assert.equal(JSON.parse(audit.details_json).deletedQueryHistory, 1);
  });
});
