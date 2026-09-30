// Regression test for OIDC login-CSRF: the `state` used to live only in a server-side map,
// not tied to the browser that started the flow. Anyone who completed the IdP login could hand
// the resulting /oidc/callback?code=…&state=… link to a victim and get the victim's browser
// logged in as the attacker. The callback now requires the gatwy_oidc_state cookie set by
// /oidc/authorize to match the `state` query parameter.
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-oidc-state-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'oidc-state-binding-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { initJwt } = await import('../src/services/jwt.js');
const { setSettings } = await import('../src/services/settings.js');
const { default: authRouter } = await import('../src/routes/auth.js');
const { default: express } = await import('express');
const { default: cookieParser } = await import('cookie-parser');

let idp: Server;
let app: Server;
let baseUrl: string;
let tokenCalls = 0;

before(async () => {
  await initDb();
  initJwt();

  idp = http.createServer((req, res) => {
    const origin = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') {
      res.end(JSON.stringify({
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        userinfo_endpoint: `${origin}/userinfo`,
      }));
    } else if (req.url === '/token') {
      tokenCalls += 1;
      res.end(JSON.stringify({ access_token: 'at' }));
    } else if (req.url === '/userinfo') {
      res.end(JSON.stringify({ sub: 'idp-user-1', preferred_username: 'alice', email: 'alice@example.com' }));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise<void>((resolve) => idp.listen(0, '127.0.0.1', resolve));
  const idpUrl = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;

  setSettings({
    'auth.oidc_enabled': 'true',
    'auth.oidc_provider_url': idpUrl,
    'auth.oidc_client_id': 'gatwy',
    'auth.oidc_redirect_uri': 'https://gatwy.example/api/v1/auth/oidc/callback',
  });

  const a = express();
  a.use(cookieParser());
  a.use('/api/v1/auth', authRouter);
  app = a.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => app.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
});

after(() => {
  app.close();
  idp.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
  // Module-level cleanup timers in the auth/oidc services keep the event loop alive.
  setTimeout(() => process.exit(0), 50).unref();
});

// Starts a flow the way the SPA does and returns the state plus the Set-Cookie header.
async function startFlow(): Promise<{ state: string; setCookie: string }> {
  const res = await fetch(`${baseUrl}/api/v1/auth/oidc/authorize`);
  const { url } = await res.json() as { url: string };
  const state = new URL(url).searchParams.get('state')!;
  return { state, setCookie: res.headers.get('set-cookie') ?? '' };
}

async function callback(state: string, cookie?: string) {
  return fetch(`${baseUrl}/api/v1/auth/oidc/callback?code=abc&state=${state}`, {
    redirect: 'manual',
    headers: cookie ? { Cookie: cookie } : {},
  });
}

describe('OIDC state is bound to the browser that started the flow', () => {
  it('authorize sets an HttpOnly, Secure, SameSite=Lax cookie carrying the state', async () => {
    const { state, setCookie } = await startFlow();
    assert.match(setCookie, new RegExp(`gatwy_oidc_state=${state}`));
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /Secure/i);
    assert.match(setCookie, /SameSite=Lax/i);
  });

  it('callback from the same browser (cookie matches) signs the user in', async () => {
    const { state } = await startFlow();
    const res = await callback(state, `gatwy_oidc_state=${state}`);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?sso=success');
    assert.match(res.headers.get('set-cookie') ?? '', /gatwy_token=/);
  });

  it('callback without the cookie (link handed to a victim) is rejected before the code is exchanged', async () => {
    const { state } = await startFlow();
    const before = tokenCalls;
    const res = await callback(state);
    assert.equal(res.headers.get('location'), '/?sso_error=auth_failed');
    assert.doesNotMatch(res.headers.get('set-cookie') ?? '', /gatwy_token=/);
    assert.equal(tokenCalls, before, 'authorization code must not be sent to the token endpoint');
  });

  it("callback with another flow's cookie is rejected", async () => {
    const victim = await startFlow();
    const attacker = await startFlow();
    const res = await callback(attacker.state, `gatwy_oidc_state=${victim.state}`);
    assert.equal(res.headers.get('location'), '/?sso_error=auth_failed');
    assert.doesNotMatch(res.headers.get('set-cookie') ?? '', /gatwy_token=/);
  });

  it('the state cookie is cleared by the callback even when the flow is rejected', async () => {
    const { state } = await startFlow();
    const res = await callback(state, 'gatwy_oidc_state=not-the-state');
    assert.match(res.headers.get('set-cookie') ?? '', /gatwy_oidc_state=;/);
  });
});
