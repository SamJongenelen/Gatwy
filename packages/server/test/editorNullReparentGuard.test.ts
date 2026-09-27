import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-nullreparent-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'null-reparent-bypass-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let editorToken: string;
const ownerId = 'user-nullreparent-owner';
const editorId = 'user-nullreparent-editor';
const sharedGroupId = 'g-nullreparent-shared';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['nullreparent-editor', 'Null Reparent Editor', 'editor collaborator', JSON.stringify([
      'connections.create', 'connections.edit_own',
    ])],
  );
  for (const [id, username] of [[ownerId, 'nullreparent-owner'], [editorId, 'nullreparent-editor-user']]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [id, username, 'x', username, 'nullreparent-editor'],
    );
  }
  editorToken = signToken({ userId: editorId, username: 'nullreparent-editor-user', role: 'nullreparent-editor' });

  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [sharedGroupId, ownerId, 'Shared With Editor']);
  execute(
    `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'edit')`,
    ['share-nullreparent-editor', sharedGroupId, editorId],
  );

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

describe('PUT /:id — an editor cannot move a connection to root (groupId: null) out of the shared branch', () => {
  it('rejects groupId: null and leaves the connection in the shared folder', async () => {
    const created = await authedFetch(editorToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'inside-shared', protocol: 'vnc', host: 'h', port: 5900, groupId: sharedGroupId }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ groupId: null }),
    });
    assert.equal(res.status, 400);
    const row = queryOne<{ group_id: string | null }>('SELECT group_id FROM connections WHERE id = ?', [id]);
    assert.equal(row?.group_id, sharedGroupId);
  });
});

describe('PUT /groups/:id — an editor cannot move a sub-folder to root (parentId: null) out of the shared branch', () => {
  it('rejects parentId: null and leaves the sub-folder in place', async () => {
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', ['g-nullreparent-sub', ownerId, 'sub', sharedGroupId]);

    const res = await authedFetch(editorToken, `${baseUrl}/groups/g-nullreparent-sub`, {
      method: 'PUT',
      body: JSON.stringify({ parentId: null }),
    });
    assert.equal(res.status, 400);
    const row = queryOne<{ parent_id: string | null }>('SELECT parent_id FROM connection_groups WHERE id = ?', ['g-nullreparent-sub']);
    assert.equal(row?.parent_id, sharedGroupId);
  });
});
