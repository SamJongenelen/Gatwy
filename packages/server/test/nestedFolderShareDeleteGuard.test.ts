import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-nesteddelete-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'nested-share-delete-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let editorToken: string;
const ownerId = 'user-nested-owner';
const editorId = 'user-nested-editor';
const thirdPartyId = 'user-nested-third-party';
const topRootId = 'g-nested-top-root';
const middleId = 'g-nested-middle';
const subId = 'g-nested-sub';

before(async () => {
  await initDb();
  initJwt();

  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['nested-editor', 'Nested Editor', 'editor collaborator', JSON.stringify([
      'connections.create', 'connections.edit_own', 'connections.delete_own',
    ])],
  );
  for (const [id, username] of [[ownerId, 'nested-owner'], [editorId, 'nested-editor-user'], [thirdPartyId, 'nested-third-party']]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [id, username, 'x', username, 'nested-editor'],
    );
  }
  editorToken = signToken({ userId: editorId, username: 'nested-editor-user', role: 'nested-editor' });

  // Top-level folder shared to the editor with edit capability — grants write access to
  // it AND everything beneath it, per editableSharedGroupIds' inheritance.
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [topRootId, ownerId, 'Top Root']);
  execute(
    `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'edit')`,
    ['share-nested-top-root-editor', topRootId, editorId],
  );
  // Middle folder: NOT independently shared itself (isSharedGroup is false for it) — the
  // editor can write to it purely by inheritance from topRootId.
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', [middleId, ownerId, 'Middle', topRootId]);
  // Sub-folder inside middle, independently shared to a THIRD party (not the editor).
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', [subId, ownerId, 'Independently Shared Sub', middleId]);
  execute(
    `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'view')`,
    ['share-nested-sub-third-party', subId, thirdPartyId],
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

describe('DELETE /groups/:id — deleting an unshared parent must not silently destroy an independently-shared sub-folder\'s share', () => {
  it('blocks the deletion and names the blocked sub-folder, leaving everything in place', async () => {
    const res = await authedFetch(editorToken, `${baseUrl}/groups/${middleId}`, { method: 'DELETE' });
    assert.equal(res.status, 409);
    const body = await res.json() as { error: string };
    assert.match(body.error, /Independently Shared Sub/);

    assert.ok(queryOne('SELECT id FROM connection_groups WHERE id = ?', [middleId]), 'middle folder must survive the rejected delete');
    assert.ok(queryOne('SELECT id FROM connection_groups WHERE id = ?', [subId]), 'sub-folder must survive');
    assert.ok(queryOne('SELECT id FROM resource_shares WHERE id = ?', ['share-nested-sub-third-party']), 'the sub-folder\'s own share must survive');
  });
});
