import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-groupdeleteperm-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'group-delete-permission-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let editAnyNoDeleteToken: string;
let deleteAnyToken: string;
let editorDeleteOwnToken: string;
const ownerId = 'user-groupdelete-owner';
const editAnyNoDeleteId = 'user-groupdelete-editany';
const deleteAnyId = 'user-groupdelete-deleteany';
const editorId = 'user-groupdelete-editor';

before(async () => {
  await initDb();
  initJwt();

  // Has connections.edit_any but explicitly NOT delete_any — must no longer be enough to
  // delete another user's folder outright (pre-PR this route was strictly owner-only).
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['edit-any-no-delete', 'Edit Any No Delete', 'can edit any connection, cannot delete any', JSON.stringify([
      'connections.edit_any',
    ])],
  );
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['delete-any', 'Delete Any', 'the actual permission this action should require', JSON.stringify([
      'connections.delete_any',
    ])],
  );
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['editor-delete-own', 'Editor Delete Own', 'editor collaborator floor', JSON.stringify([
      'connections.create', 'connections.edit_own', 'connections.delete_own',
    ])],
  );
  for (const [id, username, role] of [
    [ownerId, 'groupdelete-owner', 'editor-delete-own'],
    [editAnyNoDeleteId, 'groupdelete-editany', 'edit-any-no-delete'],
    [deleteAnyId, 'groupdelete-deleteany', 'delete-any'],
    [editorId, 'groupdelete-editor', 'editor-delete-own'],
  ]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [id, username, 'x', username, role],
    );
  }
  editAnyNoDeleteToken = signToken({ userId: editAnyNoDeleteId, username: 'groupdelete-editany', role: 'edit-any-no-delete' });
  deleteAnyToken = signToken({ userId: deleteAnyId, username: 'groupdelete-deleteany', role: 'delete-any' });
  editorDeleteOwnToken = signToken({ userId: editorId, username: 'groupdelete-editor', role: 'editor-delete-own' });

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

describe('DELETE /groups/:id — permission model matches DELETE /:id (connections.delete_any, not edit_any)', () => {
  it('rejects connections.edit_any alone deleting another user\'s folder', async () => {
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', ['g-perm-1', ownerId, 'perm-1']);
    const res = await authedFetch(editAnyNoDeleteToken, `${baseUrl}/groups/g-perm-1`, { method: 'DELETE' });
    assert.equal(res.status, 403);
    assert.ok(queryOne('SELECT id FROM connection_groups WHERE id = ?', ['g-perm-1']), 'folder must survive');
  });

  it('allows connections.delete_any to delete another user\'s folder', async () => {
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', ['g-perm-2', ownerId, 'perm-2']);
    const res = await authedFetch(deleteAnyToken, `${baseUrl}/groups/g-perm-2`, { method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.equal(queryOne('SELECT id FROM connection_groups WHERE id = ?', ['g-perm-2']), undefined);
  });

  it('an editor collaborator (connections.delete_own, no delete_any) can still delete a shared folder\'s unshared contents', async () => {
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', ['g-perm-3', ownerId, 'perm-3']);
    execute(
      `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'edit')`,
      ['share-perm-3-editor', 'g-perm-3', editorId],
    );
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)', ['g-perm-3-sub', ownerId, 'perm-3-sub', 'g-perm-3']);
    const res = await authedFetch(editorDeleteOwnToken, `${baseUrl}/groups/g-perm-3-sub`, { method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.equal(queryOne('SELECT id FROM connection_groups WHERE id = ?', ['g-perm-3-sub']), undefined);
  });
});
