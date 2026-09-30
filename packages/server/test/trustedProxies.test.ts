// security.trusted_proxies used to be evaluated with IPv4-only arithmetic, on IPv6 strings too:
// parseInt() read the first group (or gave NaN, which became 0), so `fe80::/10` trusted every IPv6
// peer that started with a letter, `::1/128` never matched, and any client on such a peer could pick
// its own address with X-Forwarded-For (audit log, login rate limit, IP rules). It now uses the same
// matcher as the IP rules, and the setting is validated when saved.
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-trusted-proxies-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'trusted-proxies-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const { initJwt, signToken } = await import('../src/services/jwt.js');
const { getSetting, setSettings } = await import('../src/services/settings.js');
const { isTrustedProxyAddress, validateTrustedProxies, resolveClientIp } = await import('../src/services/ip.js');
const { default: settingsRouter } = await import('../src/routes/settings.js');
const { default: express } = await import('express');

let server: Server;
let baseUrl: string;
let adminToken: string;

before(async () => {
  await initDb();
  initJwt();
  execute(`INSERT INTO users (id, username, password_hash, display_name, role) VALUES ('admin-1', 'admin', 'x', 'Admin', 'admin')`);
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

const trust = (value: string) => setSettings({ 'security.trusted_proxies': value });

describe('isTrustedProxyAddress', () => {
  it('keeps the IPv4 behaviour', () => {
    trust('');
    assert.equal(isTrustedProxyAddress('127.0.0.1'), false);
    trust('false');
    assert.equal(isTrustedProxyAddress('127.0.0.1'), false);
    trust('true');
    assert.equal(isTrustedProxyAddress('203.0.113.9'), true);
    trust('*');
    assert.equal(isTrustedProxyAddress('203.0.113.9'), true);
    trust('127.0.0.1');
    assert.equal(isTrustedProxyAddress('127.0.0.1'), true);
    assert.equal(isTrustedProxyAddress('127.0.0.2'), false);
    assert.equal(isTrustedProxyAddress('::ffff:127.0.0.1'), true, 'IPv4-mapped peer');
    trust('10.0.0.0/8, 192.168.1.5');
    assert.equal(isTrustedProxyAddress('10.200.3.4'), true);
    assert.equal(isTrustedProxyAddress('11.0.0.1'), false);
    assert.equal(isTrustedProxyAddress('192.168.1.5'), true);
    assert.equal(isTrustedProxyAddress('::ffff:10.1.2.3'), true);
  });

  it('understands IPv6 addresses and ranges', () => {
    trust('::1');
    assert.equal(isTrustedProxyAddress('::1'), true);
    assert.equal(isTrustedProxyAddress('0:0:0:0:0:0:0:1'), true, 'same address written in full');
    trust('::1/128');
    assert.equal(isTrustedProxyAddress('::1'), true);
    trust('fd00::/8');
    assert.equal(isTrustedProxyAddress('fd12:3456::5'), true);
    trust('2001:db8::/32');
    assert.equal(isTrustedProxyAddress('2001:db8::1'), true);
  });

  it('does not trust IPv6 peers outside the range (used to trust nearly all of them)', () => {
    trust('fe80::/10');
    assert.equal(isTrustedProxyAddress('::1'), false);
    assert.equal(isTrustedProxyAddress('2001:db8::1'), false);
    assert.equal(isTrustedProxyAddress('fe80::1'), true);
    trust('fd00::/8');
    assert.equal(isTrustedProxyAddress('fe80::1'), false);
    assert.equal(isTrustedProxyAddress('2001:db8::1'), false);
    trust('2001:db8::/32');
    assert.equal(isTrustedProxyAddress('2001:aaaa::1'), false);
    trust('::1/128');
    assert.equal(isTrustedProxyAddress('::2'), false);
  });

  it('never mixes address families', () => {
    trust('10.0.0.0/8');
    assert.equal(isTrustedProxyAddress('fd00::1'), false);
    trust('fd00::/8');
    assert.equal(isTrustedProxyAddress('10.1.2.3'), false);
  });

  it('a malformed entry trusts nobody, the valid ones next to it still work', () => {
    trust('nginx, 10.0.0.0/33, not-an-ip');
    assert.equal(isTrustedProxyAddress('10.1.2.3'), false);
    assert.equal(isTrustedProxyAddress('::1'), false);
    trust('bogus, 127.0.0.1');
    assert.equal(isTrustedProxyAddress('127.0.0.1'), true);
  });
});

describe('resolveClientIp with an IPv6 trusted proxy', () => {
  const req = (peer: string, xff: string) => ({
    headers: { 'x-forwarded-for': xff },
    socket: { remoteAddress: peer },
  }) as unknown as Parameters<typeof resolveClientIp>[0];

  it('honours X-Forwarded-For from a peer inside the range and ignores it otherwise', () => {
    trust('fd00::/8');
    assert.equal(resolveClientIp(req('fd00::5', '203.0.113.7')), '203.0.113.7');
    assert.equal(resolveClientIp(req('fe80::1', '203.0.113.7')), 'fe80::1');
    assert.equal(resolveClientIp(req('::1', '203.0.113.7')), '::1');
  });
});

describe('validateTrustedProxies', () => {
  it('accepts the keywords, an empty value and lists of addresses and ranges', () => {
    for (const v of ['', '  ', 'true', 'false', '*', '10.0.0.1', '10.0.0.0/8, ::1', 'fd00::/8,192.168.0.0/16', ' 127.0.0.1 ']) {
      assert.equal(validateTrustedProxies(v), null, JSON.stringify(v));
    }
  });

  it('rejects anything else and names the entry', () => {
    for (const [v, entry] of [['nginx', 'nginx'], ['10.0.0.1, ', ''], ['10.0.0.0/33', '10.0.0.0/33'], ['::ffff:10.1.2.3', '::ffff:10.1.2.3'], ['10.0.0.1,bogus', 'bogus'], ['true, 10.0.0.1', 'true']] as const) {
      const msg = validateTrustedProxies(v);
      assert.ok(msg && msg.includes(`"${entry}"`), `${JSON.stringify(v)} -> ${msg}`);
    }
    assert.ok(validateTrustedProxies(123 as unknown as string));
  });
});

describe('PUT /settings validates security.trusted_proxies', () => {
  const put = (body: Record<string, unknown>) => fetch(`${baseUrl}/api/v1/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify(body),
  });

  it('rejects an invalid entry and leaves the setting alone', async () => {
    trust('10.0.0.1');
    const res = await put({ 'security.trusted_proxies': '10.0.0.1, nginx' });
    assert.equal(res.status, 400);
    assert.match((await res.json() as { error: string }).error, /nginx/);
    assert.equal(getSetting('security.trusted_proxies'), '10.0.0.1');
  });

  it('saves valid IPv4 and IPv6 entries', async () => {
    const res = await put({ 'security.trusted_proxies': '10.0.0.0/8, fd00::/8' });
    assert.equal(res.status, 200);
    assert.equal(getSetting('security.trusted_proxies'), '10.0.0.0/8, fd00::/8');
  });

  it('does not touch other settings', async () => {
    const res = await put({ 'app.name': 'Gatwy test' });
    assert.equal(res.status, 200);
    assert.equal(getSetting('app.name'), 'Gatwy test');
  });
});
