// Regression test for IP rules on WebSocket upgrades: ipRulesMiddleware is only mounted on
// /api/v1, so the SSH/RDP/VNC/Telnet WebSocket upgrades and /mlw were never checked. A one-time
// ws ticket (or, for /mlw, a session cookie) obtained from an allowed address could be used
// from any other address. The rules are now applied to every 'upgrade' before the proxies see it.
// The client IP is resolved with the trusted-proxy rule, so an untrusted peer cannot pick its own
// address by sending X-Forwarded-For.
import assert from 'node:assert/strict';
import { describe, it, before, after, beforeEach } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { WebSocket, WebSocketServer } from 'ws';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-ws-iprules-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'ws-ip-rules-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute, queryAll } = await import('../src/db/helpers.js');
const { setSettings } = await import('../src/services/settings.js');
const { resolveClientIp } = await import('../src/services/ip.js');
const { evaluateIpRules, guardUpgradesByIpRules } = await import('../src/middleware/ipRules.js');

let server: Server;
let port: number;
let upgradesReachingProxy = 0;

function setRules(mode: 'allowlist' | 'denylist', rules: Array<{ type: 'allow' | 'deny'; cidr: string }>, enabled = true) {
  execute('DELETE FROM ip_rules');
  rules.forEach((r, i) => execute(
    'INSERT INTO ip_rules (id, type, cidr, description, created_by) VALUES (?, ?, ?, ?, ?)',
    [`r${i}`, r.type, r.cidr, '', null],
  ));
  setSettings({ 'security.ip_rules_enabled': String(enabled), 'security.ip_rules_mode': mode });
}

// Resolves 'open' if the upgrade was accepted, or the HTTP status if it was refused.
function connect(headers: Record<string, string> = {}, query = ''): Promise<'open' | number> {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/ssh${query}`, { headers });
    ws.once('open', () => { ws.close(); resolve('open'); });
    ws.once('unexpected-response', (_req, res) => { res.resume(); resolve(res.statusCode ?? 0); });
    ws.once('error', () => resolve(0));
  });
}

before(async () => {
  await initDb();

  server = http.createServer();
  guardUpgradesByIpRules(server);
  // Same shape as the real proxies: their own 'upgrade' listener, registered after the guard.
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    upgradesReachingProxy += 1;
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

beforeEach(() => {
  upgradesReachingProxy = 0;
  setSettings({ 'security.trusted_proxies': '' });
  setRules('allowlist', [], false);
});

after(() => {
  server.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

describe('WebSocket upgrades honour the IP rules', () => {
  it('lets everything through when the rules are disabled', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }], false);
    assert.equal(await connect(), 'open');
  });

  it('refuses an address that is not in the allowlist, before any proxy listener runs', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    assert.equal(await connect(), 403);
    assert.equal(upgradesReachingProxy, 0);
  });

  it('accepts an address that is in the allowlist', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '127.0.0.0/8' }]);
    assert.equal(await connect(), 'open');
  });

  it('refuses an address in the denylist and accepts the others', async () => {
    setRules('denylist', [{ type: 'deny', cidr: '127.0.0.1' }]);
    assert.equal(await connect(), 403);
    setRules('denylist', [{ type: 'deny', cidr: '10.0.0.0/8' }]);
    assert.equal(await connect(), 'open');
  });

  it('ignores X-Forwarded-For from a peer that is not a trusted proxy', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    assert.equal(await connect({ 'X-Forwarded-For': '10.1.2.3' }), 403);
    setRules('denylist', [{ type: 'deny', cidr: '127.0.0.1' }]);
    assert.equal(await connect({ 'X-Forwarded-For': '10.1.2.3' }), 403);
  });

  it('believes X-Forwarded-For from a trusted proxy', async () => {
    setSettings({ 'security.trusted_proxies': '127.0.0.1' });
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    assert.equal(await connect({ 'X-Forwarded-For': '10.1.2.3' }), 'open');
    assert.equal(await connect({ 'X-Forwarded-For': '203.0.113.9' }), 403);
  });

  it('survives a blocked client that resets the connection while being refused', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    const crashes: Error[] = [];
    const onCrash = (err: Error) => { crashes.push(err); };
    process.on('uncaughtException', onCrash);
    try {
      for (let i = 0; i < 5; i++) {
        await new Promise<void>((resolve) => {
          const raw = net.connect(port, '127.0.0.1', () => {
            raw.write(
              'GET /ws/ssh HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
              'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
            );
          });
          // Reset only once the 403 has arrived, i.e. after the server has finished the upgrade
          // event and is holding a half-closed socket.
          raw.once('data', () => raw.resetAndDestroy());
          raw.on('error', () => {});
          raw.once('close', () => resolve());
        });
      }
      await new Promise((r) => setTimeout(r, 300));
    } finally {
      process.off('uncaughtException', onCrash);
    }
    assert.deepEqual(crashes.map((e) => e.message), []);
    // and the server still serves upgrades afterwards
    setRules('allowlist', [{ type: 'allow', cidr: '127.0.0.0/8' }]);
    assert.equal(await connect(), 'open');
  });

  it('logs the block without the query string (it carries the ws ticket)', async () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    execute('DELETE FROM audit_log');
    await connect({}, '?ticket=secret-ticket&connectionId=abc');
    const rows = queryAll<{ details_json: string; ip_address: string }>(
      "SELECT details_json, ip_address FROM audit_log WHERE event_type = 'security.ip_blocked'",
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].ip_address, '127.0.0.1');
    assert.doesNotMatch(rows[0].details_json, /secret-ticket/);
    assert.match(rows[0].details_json, /"path":"\/ws\/ssh"/);
  });
});

describe('evaluateIpRules', () => {
  it('reports the reason for each mode', () => {
    setRules('allowlist', [{ type: 'allow', cidr: '10.0.0.0/8' }]);
    assert.equal(evaluateIpRules('10.4.5.6'), null);
    assert.equal(evaluateIpRules('192.168.1.1'), 'not_in_allowlist');
    setRules('denylist', [{ type: 'deny', cidr: '192.168.0.0/16' }]);
    assert.equal(evaluateIpRules('192.168.1.1'), 'in_denylist');
    assert.equal(evaluateIpRules('10.4.5.6'), null);
  });
});

describe('resolveClientIp for requests without req.ip (WebSocket upgrades)', () => {
  const req = (peer: string, xff?: string) => ({
    headers: xff ? { 'x-forwarded-for': xff } : {},
    socket: { remoteAddress: peer },
  }) as unknown as Parameters<typeof resolveClientIp>[0];

  it('uses the TCP peer when it is not a trusted proxy, whatever X-Forwarded-For says', () => {
    assert.equal(resolveClientIp(req('203.0.113.7', '10.1.2.3')), '203.0.113.7');
    assert.equal(resolveClientIp(req('::ffff:203.0.113.7', '10.1.2.3')), '203.0.113.7');
  });

  it('walks the chain from the right past trusted proxies', () => {
    setSettings({ 'security.trusted_proxies': '10.0.0.0/8' });
    // client -> 10.0.0.5 -> 10.0.0.6 (peer). A value the client made up sits to the left.
    assert.equal(resolveClientIp(req('10.0.0.6', '9.9.9.9, 203.0.113.7, 10.0.0.5')), '203.0.113.7');
  });

  it('takes the leftmost entry when every hop is trusted', () => {
    setSettings({ 'security.trusted_proxies': '*' });
    assert.equal(resolveClientIp(req('10.0.0.6', '203.0.113.7, 10.0.0.5')), '203.0.113.7');
  });

  it('falls back to the peer when a trusted proxy sends no header', () => {
    setSettings({ 'security.trusted_proxies': '10.0.0.6' });
    assert.equal(resolveClientIp(req('10.0.0.6')), '10.0.0.6');
  });
});
