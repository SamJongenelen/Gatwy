import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import type { Server } from 'http';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-editorcredretarget-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'editor-credential-retarget-test-secret';
process.env.GATWY_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { initEncryption } = await import('../src/services/encryption.js');
const { default: connectionsRouter } = await import('../src/routes/connections.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let ownerToken: string;
let editorToken: string;
const ownerId = 'user-retarget-owner';
const editorId = 'user-retarget-editor';
const groupId = 'g-retarget-shared';

before(async () => {
  await initDb();
  initJwt();
  initEncryption();

  // Editor role: everything an editor collaborator needs to write inside a shared folder
  // (connections.create + edit_own), same floor PUT/DELETE /:id already require.
  execute(
    `INSERT INTO roles (id, name, description, is_builtin, permissions_json) VALUES (?, ?, ?, 0, ?)`,
    ['retarget-editor', 'Retarget Editor', 'editor collaborator', JSON.stringify([
      'connections.create', 'connections.edit_own',
    ])],
  );
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [ownerId, 'retarget-owner', 'x', 'Retarget Owner', 'retarget-editor'],
  );
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
    [editorId, 'retarget-editor-user', 'x', 'Retarget Editor', 'retarget-editor'],
  );
  ownerToken = signToken({ userId: ownerId, username: 'retarget-owner', role: 'retarget-editor' });
  editorToken = signToken({ userId: editorId, username: 'retarget-editor-user', role: 'retarget-editor' });

  execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [groupId, ownerId, 'Shared With Editor']);
  execute(
    `INSERT INTO resource_shares (id, resource_type, resource_id, share_type, target_id, capability) VALUES (?, 'group', ?, 'user', ?, 'edit')`,
    ['share-retarget-group-editor', groupId, editorId],
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

function addPrivateCredential(id: string): void {
  execute(
    `INSERT INTO credentials (id, user_id, name, type, username, encrypted_password, shared) VALUES (?, ?, ?, 'password', ?, ?, 0)`,
    [id, ownerId, 'Owner Private Cred', 'owner-user', 'encrypted-placeholder'],
  );
}

describe('POST / — an editor cannot link the folder owner\'s private credential', () => {
  it('rejects linking a private credential owned by the folder owner', async () => {
    addPrivateCredential('cred-post-private');
    const res = await authedFetch(editorToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'planted', protocol: 'rdp', host: 'attacker.example', port: 3389, groupId, credentialId: 'cred-post-private' }),
    });
    assert.equal(res.status, 400);
  });

  it('still allows the OWNER to link their own private credential inside the same folder', async () => {
    addPrivateCredential('cred-post-private-owner-ok');
    const res = await authedFetch(ownerToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'owner-made', protocol: 'rdp', host: 'real-host.example', port: 3389, groupId, credentialId: 'cred-post-private-owner-ok' }),
    });
    assert.equal(res.status, 201);
  });

  it('still allows an editor to link a SHARED credential', async () => {
    execute(
      `INSERT INTO credentials (id, user_id, name, type, username, encrypted_password, shared) VALUES (?, ?, ?, 'password', ?, ?, 1)`,
      ['cred-post-shared', ownerId, 'Shared Cred', 'shared-user', 'encrypted-placeholder'],
    );
    const res = await authedFetch(editorToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'editor-shared-cred', protocol: 'rdp', host: 'benign.example', port: 3389, groupId, credentialId: 'cred-post-shared' }),
    });
    assert.equal(res.status, 201);
  });
});

describe('PUT /:id — an editor cannot retarget a connection that carries stored credentials', () => {
  it('blocks changing host on a connection linked to the owner\'s private credential', async () => {
    addPrivateCredential('cred-existing-private');
    const created = await authedFetch(ownerToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'trusted', protocol: 'rdp', host: 'real-host.example', port: 3389, groupId, credentialId: 'cred-existing-private' }),
    });
    assert.equal(created.status, 201);
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ host: 'attacker.example' }),
    });
    assert.equal(res.status, 400);
    const row = queryOne<{ host: string }>('SELECT host FROM connections WHERE id = ?', [id]);
    assert.equal(row?.host, 'real-host.example', 'host must be unchanged after the rejected update');
  });

  it('blocks changing port and protocol too, and blocks it even without touching credentialId in the same request', async () => {
    addPrivateCredential('cred-existing-private-2');
    const created = await authedFetch(ownerToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'trusted2', protocol: 'rdp', host: 'real-host2.example', port: 3389, groupId, credentialId: 'cred-existing-private-2' }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ port: 4444 }),
    });
    assert.equal(res.status, 400);
  });

  it('blocks retargeting a connection with an inline (non-library) password too', async () => {
    const created = await authedFetch(ownerToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'inline-secret', protocol: 'ssh', host: 'real-host3.example', port: 22, groupId, username: 'root', password: 'super-secret' }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ host: 'attacker3.example' }),
    });
    assert.equal(res.status, 400);
  });

  it('still allows an editor to retarget a connection with no stored secret at all', async () => {
    const created = await authedFetch(editorToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'no-secret', protocol: 'vnc', host: 'benign.example', port: 5900, groupId }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ host: 'still-benign.example' }),
    });
    assert.equal(res.status, 200);
  });

  it('still allows an editor to rename/tag a secret-carrying connection, since host/port/protocol are untouched', async () => {
    addPrivateCredential('cred-existing-private-3');
    const created = await authedFetch(ownerToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'trusted3', protocol: 'rdp', host: 'real-host4.example', port: 3389, groupId, credentialId: 'cred-existing-private-3' }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ name: 'renamed by editor' }),
    });
    assert.equal(res.status, 200);
  });

  it('rejects an editor linking the owner\'s private credential onto an existing connection', async () => {
    addPrivateCredential('cred-relink-private');
    const created = await authedFetch(editorToken, baseUrl, {
      method: 'POST',
      body: JSON.stringify({ name: 'no-secret-yet', protocol: 'vnc', host: 'benign2.example', port: 5900, groupId }),
    });
    const { id } = await created.json() as { id: string };

    const res = await authedFetch(editorToken, `${baseUrl}/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ credentialId: 'cred-relink-private' }),
    });
    assert.equal(res.status, 400);
  });
});
