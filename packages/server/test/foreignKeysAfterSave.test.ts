import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import os from 'os';
import path from 'path';

// config reads DATA_DIR at import time, so point it at a scratch dir first.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-fk-after-save-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'fk-after-save-test-secret';

const { initDb, closeDb, getDb, persistDb } = await import('../src/db/index.js');
const { execute, queryOne } = await import('../src/db/helpers.js');

describe('foreign key enforcement survives a save cycle', () => {
  before(async () => {
    await initDb();
  });

  after(() => {
    closeDb();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('PRAGMA foreign_keys reads back ON after persistDb() (db.export() resets it otherwise)', () => {
    persistDb();
    const row = getDb().exec('PRAGMA foreign_keys');
    assert.equal(row[0]?.values[0]?.[0], 1);
  });

  it('an ON DELETE CASCADE actually fires after a save cycle, not just right after startup', () => {
    const userId = 'user-fk-cascade-check';
    const groupId = 'g-fk-cascade-check';
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [userId, 'fk-cascade-check', 'x', 'FK Cascade Check', 'user'],
    );
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [groupId, userId, 'Cascade Check Group']);

    // Simulate the autosave tick that runs every 5s in the real process — this is the
    // step that used to leave foreign_keys disabled for the rest of the connection's life.
    persistDb();

    execute('DELETE FROM users WHERE id = ?', [userId]);

    assert.equal(
      queryOne('SELECT id FROM connection_groups WHERE id = ?', [groupId]),
      undefined,
      'connection_groups.user_id ON DELETE CASCADE must remove the group once the owning user is deleted',
    );
  });

  it('ON DELETE CASCADE still fires after MULTIPLE save cycles (regression guard for the autosave interval)', () => {
    const userId = 'user-fk-cascade-check-2';
    const groupId = 'g-fk-cascade-check-2';
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)`,
      [userId, 'fk-cascade-check-2', 'x', 'FK Cascade Check 2', 'user'],
    );
    execute('INSERT INTO connection_groups (id, user_id, name, parent_id) VALUES (?, ?, ?, NULL)', [groupId, userId, 'Cascade Check Group 2']);

    persistDb();
    persistDb();
    persistDb();

    execute('DELETE FROM users WHERE id = ?', [userId]);

    assert.equal(queryOne('SELECT id FROM connection_groups WHERE id = ?', [groupId]), undefined);
  });
});
