// Regression test for two PR-review blockers found when Gatwy runs behind a reverse-proxy
// path prefix (BASE_PATH, see config.ts#normalizeBasePath):
//
// 1. OIDC SSO was broken under a prefix: the `gatwy_oidc_state` cookie's Path attribute was
//    hardcoded to '/api/v1/auth/oidc', so when the whole app (including this route) is mounted
//    under `${BASE_PATH}/api/v1/auth/oidc`, the browser never attached the cookie back on the
//    callback request — the Path attribute is matched literally, not resolved against BASE_PATH.
//    The post-login/error redirects also hardcoded the domain root ('/') instead of
//    `${BASE_PATH}/`, so a successful or failed SSO landed the user outside the prefixed app.
//
// 2. Session/trusted-device cookies used Path=/ unconditionally — under a prefix that hands the
//    Gatwy session cookie to every other app on the same shared domain, since Path=/ covers the
//    whole origin, not just the prefix Gatwy is served under.
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-oidc-basepath-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'oidc-basepath-test-secret';
process.env.BASE_PATH = '/sys/ftp';

const { config } = await import('../src/config.js');
const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { initJwt } = await import('../src/services/jwt.js');
const { setSettings } = await import('../src/services/settings.js');
const { default: authRouter } = await import('../src/routes/auth.js');
const { default: express } = await import('express');
const { default: cookieParser } = await import('cookie-parser');

let idp: Server;
let app: Server;
let baseUrl: string;
const bp = config.basePathPrefix; // '/sys/ftp'

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
    'auth.oidc_redirect_uri': `https://gatwy.example${bp}/api/v1/auth/oidc/callback`,
  });

  // Mount exactly like index.ts does: every route lives under the BASE_PATH prefix.
  const a = express();
  a.use(cookieParser());
  a.use(`${bp}/api/v1/auth`, authRouter);
  app = a.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => app.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
});

after(() => {
  app.close();
  idp.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
  delete process.env.BASE_PATH;
  setTimeout(() => process.exit(0), 50).unref();
});

async function startFlow(): Promise<{ state: string; setCookie: string }> {
  const res = await fetch(`${baseUrl}${bp}/api/v1/auth/oidc/authorize`);
  const { url } = await res.json() as { url: string };
  const state = new URL(url).searchParams.get('state')!;
  return { state, setCookie: res.headers.get('set-cookie') ?? '' };
}

async function callback(state: string, cookie?: string) {
  return fetch(`${baseUrl}${bp}/api/v1/auth/oidc/callback?code=abc&state=${state}`, {
    redirect: 'manual',
    headers: cookie ? { Cookie: cookie } : {},
  });
}

describe('OIDC + session cookies under a reverse-proxy BASE_PATH prefix', () => {
  it('scopes the OIDC state cookie Path to the prefixed route, not the unprefixed one', async () => {
    const { setCookie } = await startFlow();
    assert.match(setCookie, new RegExp(`Path=${bp.replace(/\//g, '\\/')}\\/api\\/v1\\/auth\\/oidc(;|$)`));
  });

  it('completes the flow when the cookie is sent back on the prefixed callback path (no silent drop)', async () => {
    const { state } = await startFlow();
    const res = await callback(state, `gatwy_oidc_state=${state}`);
    assert.equal(res.status, 302);
    assert.match(res.headers.get('set-cookie') ?? '', /gatwy_token=/);
  });

  it('redirects success/error back under BASE_PATH, not the domain root', async () => {
    const ok = await startFlow();
    const okRes = await callback(ok.state, `gatwy_oidc_state=${ok.state}`);
    assert.equal(okRes.headers.get('location'), `${bp}/?sso=success`);

    const bad = await startFlow();
    const badRes = await callback(bad.state); // no cookie sent -> rejected
    assert.equal(badRes.headers.get('location'), `${bp}/?sso_error=auth_failed`);
  });

  it('scopes the session cookie Path to BASE_PATH, not Path=/ (would leak to every app on the domain)', async () => {
    const { state } = await startFlow();
    const res = await callback(state, `gatwy_oidc_state=${state}`);
    const setCookie = res.headers.get('set-cookie') ?? '';
    assert.match(setCookie, new RegExp(`gatwy_token=.*Path=${bp.replace(/\//g, '\\/')}(;|$)`));
    assert.doesNotMatch(setCookie, /gatwy_token=[^;]*;[^;]*Path=\/;/);
  });
});
