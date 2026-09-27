import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-foldercycle-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'folder-cycle-guard-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let ownerToken: string;
const ownerId = 'user-cycle-owner';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [ownerId, 'cycle-owner', 'x', 'Cycle Owner', 'admin'],
  );
  ownerToken = signToken({ userId: ownerId, username: 'cycle-owner', role: 'admin' });

  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', ['g-cycle-root', ownerId, 'root']);
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', ['g-cycle-child', ownerId, 'child', 'g-cycle-root']);
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', ['g-cycle-grandchild', ownerId, 'grandchild', 'g-cycle-child']);

  const app = express();
  app.use(express.json());
  app.use('/api/v1/connections', connectionsRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}/api/v1/connections`;
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

describe('PUT /groups/:id — cannot reparent a folder under itself or its own descendants', () => {
  it('rejects moving a folder under itself', async () => {
    const res = await authedFetch(ownerToken, `${baseUrl}/groups/g-cycle-root`, {
      method: 'PUT',
      body: JSON.stringify({ parentId: 'g-cycle-root' }),
    });
    assert.equal(res.status, 400);
  });

  it('rejects moving a folder under its direct child', async () => {
    const res = await authedFetch(ownerToken, `${baseUrl}/groups/g-cycle-root`, {
      method: 'PUT',
      body: JSON.stringify({ parentId: 'g-cycle-child' }),
    });
    assert.equal(res.status, 400);
    const row = queryOne<{ parent_id: string | null }>('SELECT parent_id FROM connection_groups WHERE id = ?', ['g-cycle-root']);
    assert.equal(row?.parent_id, null);
  });

  it('rejects moving a folder under a deeper (grandchild) descendant', async () => {
    const res = await authedFetch(ownerToken, `${baseUrl}/groups/g-cycle-root`, {
      method: 'PUT',
      body: JSON.stringify({ parentId: 'g-cycle-grandchild' }),
    });
    assert.equal(res.status, 400);
  });

  it('still allows moving a folder under an unrelated folder', async () => {
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', ['g-cycle-unrelated', ownerId, 'unrelated']);
    const res = await authedFetch(ownerToken, `${baseUrl}/groups/g-cycle-grandchild`, {
      method: 'PUT',
      body: JSON.stringify({ parentId: 'g-cycle-unrelated' }),
    });
    assert.equal(res.status, 200);
  });
});
