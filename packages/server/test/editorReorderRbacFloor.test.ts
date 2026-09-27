import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-reorderfloor-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'reorder-rbac-floor-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let noFloorToken: string;
let withFloorToken: string;
const ownerId = 'user-reorderfloor-owner';
const noFloorId = 'user-reorderfloor-nofloor';
const withFloorId = 'user-reorderfloor-withfloor';
const sharedGroupId = 'g-reorderfloor-shared';
const lockedSubId = 'g-reorderfloor-locked-sub';
const thirdPartyId = 'user-reorderfloor-third-party';

before(async () => {
  await initDb();
  initJwt();

  // Holds an edit-capability folder share, but NOT connections.edit_own — should never
  // be able to reorder via the share alone.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, '[]')`,
    ['reorder-no-floor', 'Reorder No Floor', 'no base connections permission at all'],
  );
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['reorder-with-floor', 'Reorder With Floor', 'has the base floor', JSON.stringify([
      'connections.create', 'connections.edit_own',
    ])],
  );
  for (const [id, username, role] of [
    [ownerId, 'reorderfloor-owner', 'reorder-with-floor'],
    [noFloorId, 'reorderfloor-nofloor', 'reorder-no-floor'],
    [withFloorId, 'reorderfloor-withfloor', 'reorder-with-floor'],
    [thirdPartyId, 'reorderfloor-thirdparty', 'reorder-with-floor'],
  ]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [id, username, 'x', username, role],
    );
  }
  noFloorToken = signToken({ userId: noFloorId, username: 'reorderfloor-nofloor', role: 'reorder-no-floor' });
  withFloorToken = signToken({ userId: withFloorId, username: 'reorderfloor-withfloor', role: 'reorder-with-floor' });

  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [sharedGroupId, ownerId, 'Shared Root']);
  for (const uid of [noFloorId, withFloorId]) {
    execute(
      `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'edit')`,
      [`share-reorderfloor-${uid}`, sharedGroupId, uid],
    );
  }
  execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port, sort_order) VALUES (?, ?, ?, ?, 'ssh', 'h', 22, 0)`,
    ['conn-reorderfloor-1', ownerId, sharedGroupId, 'conn-1'],
  );

  // Sub-folder independently shared to a third party — must not be reorderable by the
  // editor even though it's writable-by-inheritance from sharedGroupId.
  execute('INSERT INTO connection_groups (id, user_id, name, parent_id, sort_order) VALUES (?, ?, ?, ?, 0)', [lockedSubId, ownerId, 'locked-sub', sharedGroupId]);
  execute(
    `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'view')`,
    ['share-reorderfloor-locked-sub', lockedSubId, thirdPartyId],
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

describe('PUT /reorder — an editor share never substitutes for connections.edit_own', () => {
  it('does not reorder a connection for an editor lacking the base floor', async () => {
    const res = await authedFetch(noFloorToken, `${baseUrl}/reorder`, {
      method: 'PUT',
      body: JSON.stringify({ items: [{ id: 'conn-reorderfloor-1', sortOrder: 5 }] }),
    });
    assert.equal(res.status, 200); // silently skipped, not an error
    const row = queryOne<{ sort_order: number }>('SELECT sort_order FROM connections WHERE id = ?', ['conn-reorderfloor-1']);
    assert.equal(row?.sort_order, 0, 'sort_order must be unchanged for an editor without the base floor');
  });

  it('reorders the connection for an editor who does hold the base floor', async () => {
    const res = await authedFetch(withFloorToken, `${baseUrl}/reorder`, {
      method: 'PUT',
      body: JSON.stringify({ items: [{ id: 'conn-reorderfloor-1', sortOrder: 5 }] }),
    });
    assert.equal(res.status, 200);
    const row = queryOne<{ sort_order: number }>('SELECT sort_order FROM connections WHERE id = ?', ['conn-reorderfloor-1']);
    assert.equal(row?.sort_order, 5);
  });
});

describe('PUT /groups/reorder — same base floor, plus isSharedGroup exclusion', () => {
  it('does not reorder a folder for an editor lacking the base floor', async () => {
    const res = await authedFetch(noFloorToken, `${baseUrl}/groups/reorder`, {
      method: 'PUT',
      body: JSON.stringify({ items: [{ id: sharedGroupId, sortOrder: 9 }] }),
    });
    assert.equal(res.status, 200);
    const row = queryOne<{ sort_order: number }>('SELECT sort_order FROM connection_groups WHERE id = ?', [sharedGroupId]);
    assert.notEqual(row?.sort_order, 9);
  });

  it('does not let an editor with the base floor reorder an independently-shared sub-folder', async () => {
    const res = await authedFetch(withFloorToken, `${baseUrl}/groups/reorder`, {
      method: 'PUT',
      body: JSON.stringify({ items: [{ id: lockedSubId, sortOrder: 9 }] }),
    });
    assert.equal(res.status, 200);
    const row = queryOne<{ sort_order: number }>('SELECT sort_order FROM connection_groups WHERE id = ?', [lockedSubId]);
    assert.equal(row?.sort_order, 0, 'the independently-shared sub-folder must not be reordered by this editor');
  });
});
