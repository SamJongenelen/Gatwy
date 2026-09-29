// IP rules used to be IPv4-only in practice: an IPv6 address was parsed with parseInt() up to the
// first ':' (so 2001:aaaa::1 matched a 2001:db8::/32 rule while ::1/128 never matched anything),
// prefixes above 32 were silently ignored, and the API accepted any string as a rule. That made
// IPv6 rules unusable and let a typo lock everybody out of an allowlist without any warning.
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-iprules-match-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'ip-rules-matching-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute, queryAll } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { matchesCidr, isValidIpRule, evaluateIpRules } = await import('../src/middleware/ipRules.js');
const { default: settingsRouter } = await import('../src/routes/settings.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let adminToken: string;

before(async () => {
  await initDb();
  initJwt();
  execute(
    `INSERT INTO users (id, username, password_hash, display_name, role) VALUES ('admin-1', 'admin', 'x', 'Admin', 'admin')`,
  );
  adminToken = signToken({ userId: 'admin-1', username: 'admin', role: 'admin' });

  const app = express();
  app.use(express.json());
  app.use('/api/v1/settings', settingsRouter);
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

describe('matchesCidr', () => {
  it('matches IPv4 ranges and single addresses', () => {
    assert.equal(matchesCidr('10.1.2.3', '10.0.0.0/8'), true);
    assert.equal(matchesCidr('11.1.2.3', '10.0.0.0/8'), false);
    assert.equal(matchesCidr('10.1.2.3', '10.1.2.3'), true);
    assert.equal(matchesCidr('10.1.2.4', '10.1.2.3'), false);
    assert.equal(matchesCidr('10.1.2.3', '10.1.2.3/32'), true);
    assert.equal(matchesCidr('203.0.113.9', '0.0.0.0/0'), true);
  });

  it('matches IPv6 ranges and single addresses', () => {
    assert.equal(matchesCidr('2001:db8::1', '2001:db8::/32'), true);
    assert.equal(matchesCidr('::1', '::1/128'), true);
    assert.equal(matchesCidr('::1', '::1'), true);
    assert.equal(matchesCidr('fe80::1', 'fe80::/10'), true);
    assert.equal(matchesCidr('2001:0db8:0:0:0:0:0:1', '2001:db8::/32'), true);
    assert.equal(matchesCidr('2001:DB8::1', '2001:db8::/32'), true);
  });

  it('does not confuse IPv6 addresses that only share the first group', () => {
    assert.equal(matchesCidr('2001:aaaa::1', '2001:db8::/32'), false);
    assert.equal(matchesCidr('2001:db9::1', '2001:db8::/32'), false);
  });

  it('never matches across address families', () => {
    assert.equal(matchesCidr('2001:db8::1', '10.0.0.0/8'), false);
    assert.equal(matchesCidr('10.1.2.3', '2001:db8::/32'), false);
    assert.equal(matchesCidr('::1', '0.0.0.0/0'), false);
  });

  it('treats an IPv4-mapped IPv6 client as the IPv4 address and ignores a zone id', () => {
    assert.equal(matchesCidr('::ffff:10.1.2.3', '10.0.0.0/8'), true);
    assert.equal(matchesCidr('fe80::1%eth0', 'fe80::/10'), true);
  });

  it('never matches a malformed rule', () => {
    for (const rule of ['10.0.0.0/33', '::1/129', 'not-an-ip', '10.0.0.0/8/9', '10.0.0.0/', '', '10.0.0/8']) {
      assert.equal(matchesCidr('10.1.2.3', rule), false, rule);
    }
  });
});

describe('isValidIpRule', () => {
  it('accepts IPv4/IPv6 addresses and CIDR ranges', () => {
    for (const rule of ['10.0.0.0/8', '192.168.1.5', '0.0.0.0/0', '::1', '::1/128', '2001:db8::/32', 'fe80::/10']) {
      assert.equal(isValidIpRule(rule), true, rule);
    }
  });

  it('rejects anything else', () => {
    for (const rule of ['10.0.0.0/33', '::1/129', 'not-an-ip', '10.0.0.0/8/9', '10.0.0.0/', '', '10.0.0/8', '1.2.3.4/-1', '1.2.3.4/x']) {
      assert.equal(isValidIpRule(rule), false, rule);
    }
  });
});

describe('evaluateIpRules with IPv6', () => {
  function setRules(mode: 'allowlist' | 'denylist', rules: Array<[string, string]>) {
    execute('DELETE FROM ip_rules');
    rules.forEach(([type, cidr], i) => execute(
      'INSERT INTO ip_rules (id, type, cidr, description, created_by) VALUES (?, ?, ?, ?, ?)',
      [`r${i}`, type, cidr, '', null],
    ));
    execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('security.ip_rules_enabled', 'true')");
    execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('security.ip_rules_mode', ?)", [mode]);
  }

  it('an IPv6 allowlist rule admits that client and refuses the others', () => {
    setRules('allowlist', [['allow', '::1/128']]);
    assert.equal(evaluateIpRules('::1'), null);
    assert.equal(evaluateIpRules('2001:db8::1'), 'not_in_allowlist');
    assert.equal(evaluateIpRules('10.1.2.3'), 'not_in_allowlist');
  });

  it('an IPv6 denylist rule blocks that range only', () => {
    setRules('denylist', [['deny', '2001:db8::/32']]);
    assert.equal(evaluateIpRules('2001:db8::1'), 'in_denylist');
    assert.equal(evaluateIpRules('2001:aaaa::1'), null);
    assert.equal(evaluateIpRules('10.1.2.3'), null);
  });
});

describe('PUT /settings/ip-rules validates the rules', () => {
  const put = (rules: unknown[]) => fetch(`${baseUrl}/api/v1/settings/ip-rules`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ enabled: false, mode: 'allowlist', rules }),
  });
  const stored = () => queryAll<{ cidr: string }>('SELECT cidr FROM ip_rules ORDER BY rowid').map((r) => r.cidr);

  it('rejects a malformed rule and stores nothing', async () => {
    execute('DELETE FROM ip_rules');
    const res = await put([{ type: 'allow', cidr: '10.0.0.0/8' }, { type: 'allow', cidr: '10.0.0.0/33' }]);
    assert.equal(res.status, 400);
    assert.match((await res.json() as { error: string }).error, /10\.0\.0\.0\/33/);
    assert.deepEqual(stored(), []);
  });

  it('accepts valid IPv4 and IPv6 rules', async () => {
    const res = await put([{ type: 'allow', cidr: '10.0.0.0/8' }, { type: 'allow', cidr: '2001:db8::/32' }, { type: 'allow', cidr: '::1' }]);
    assert.equal(res.status, 200);
    assert.deepEqual(stored(), ['10.0.0.0/8', '2001:db8::/32', '::1']);
  });
});
