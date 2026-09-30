// Regression test for OIDC id_token handling: the payload used to be base64-decoded and merged
// into the user claims with no checks at all (nonce was generated and stored but never compared,
// aud/iss/exp ignored, userinfo sub never matched against the id_token sub, and a malformed
// id_token was silently treated as empty). Signature verification is intentionally not part of
// this: the token arrives from the token endpoint over TLS (OIDC Core 3.1.3.7).
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-oidc-idtoken-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'oidc-idtoken-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { setSettings } = await import('../src/services/settings.js');
const { buildOidcAuthUrl, handleOidcCallback, checkIdTokenClaims } = await import('../src/services/oidc.js');

const CLIENT_ID = 'gatwy';
let idp: Server;
let idpUrl: string;

// What the fake IdP answers, set per test.
let discoveryIssuer: string | undefined;
let idTokenFor: ((nonce: string) => string | undefined) | null;
let userinfoSub = 'sub-alice';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: Record<string, unknown>) => `${b64({ alg: 'RS256' })}.${b64(payload)}.not-checked`;
const inAnHour = () => Math.floor(Date.now() / 1000) + 3600;

function goodClaims(nonce: string): Record<string, unknown> {
  return { iss: idpUrl, aud: CLIENT_ID, exp: inAnHour(), nonce, sub: 'sub-alice' };
}

before(async () => {
  await initDb();

  idp = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') {
      res.end(JSON.stringify({
        issuer: discoveryIssuer,
        authorization_endpoint: `${idpUrl}/authorize`,
        token_endpoint: `${idpUrl}/token`,
        userinfo_endpoint: `${idpUrl}/userinfo`,
      }));
    } else if (req.url === '/token') {
      const nonce = currentNonce;
      const idToken = idTokenFor ? idTokenFor(nonce) : undefined;
      res.end(JSON.stringify({ access_token: 'at', ...(idToken ? { id_token: idToken } : {}) }));
    } else if (req.url === '/userinfo') {
      res.end(JSON.stringify({ sub: userinfoSub, preferred_username: 'alice', email: 'alice@example.com' }));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise<void>((resolve) => idp.listen(0, '127.0.0.1', resolve));
  idpUrl = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;

  setSettings({
    'auth.oidc_enabled': 'true',
    'auth.oidc_provider_url': idpUrl,
    'auth.oidc_client_id': CLIENT_ID,
    'auth.oidc_redirect_uri': 'https://gatwy.example/api/v1/auth/oidc/callback',
  });
});

after(() => {
  idp.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
  // Module-level cleanup timer in services/oidc.ts keeps the event loop alive.
  setTimeout(() => process.exit(0), 50).unref();
});

let currentNonce = '';

// Runs a whole authorize -> callback round trip against the fake IdP.
async function login(opts: {
  idToken?: (nonce: string) => string | undefined;
  issuer?: string | undefined;
  sub?: string;
}) {
  discoveryIssuer = 'issuer' in opts ? opts.issuer : idpUrl;
  idTokenFor = opts.idToken ?? null;
  userinfoSub = opts.sub ?? 'sub-alice';
  const auth = await buildOidcAuthUrl();
  assert.ok('url' in auth, 'authorize URL built');
  const params = new URL(auth.url).searchParams;
  currentNonce = params.get('nonce')!;
  return handleOidcCallback('code', params.get('state')!);
}

describe('OIDC id_token claim validation', () => {
  it('accepts a well-formed id_token', async () => {
    const user = await login({ idToken: (n) => jwt(goodClaims(n)) });
    assert.equal(user?.username, 'alice');
  });

  it('still works when the IdP returns no id_token (userinfo only)', async () => {
    const user = await login({});
    assert.equal(user?.username, 'alice');
  });

  it('rejects a wrong nonce', async () => {
    assert.equal(await login({ idToken: () => jwt(goodClaims('someone-elses-nonce')) }), null);
  });

  it('rejects an id_token without nonce', async () => {
    assert.equal(await login({ idToken: (n) => { const c = goodClaims(n); delete c.nonce; return jwt(c); } }), null);
  });

  it('rejects an id_token issued for another client (aud)', async () => {
    assert.equal(await login({ idToken: (n) => jwt({ ...goodClaims(n), aud: 'another-client' }) }), null);
  });

  it('accepts aud as an array that contains our client id', async () => {
    const user = await login({ idToken: (n) => jwt({ ...goodClaims(n), aud: ['other', CLIENT_ID] }) });
    assert.equal(user?.username, 'alice');
  });

  it('rejects an expired id_token', async () => {
    assert.equal(await login({ idToken: (n) => jwt({ ...goodClaims(n), exp: Math.floor(Date.now() / 1000) - 3600 }) }), null);
  });

  it('rejects an id_token without exp', async () => {
    assert.equal(await login({ idToken: (n) => { const c = goodClaims(n); delete c.exp; return jwt(c); } }), null);
  });

  it('rejects a different issuer', async () => {
    assert.equal(await login({ idToken: (n) => jwt({ ...goodClaims(n), iss: 'https://evil.example' }) }), null);
  });

  it('ignores a trailing slash difference in the issuer', async () => {
    const user = await login({ idToken: (n) => jwt({ ...goodClaims(n), iss: `${idpUrl}/` }) });
    assert.equal(user?.username, 'alice');
  });

  it('skips the issuer check for a templated (multi-tenant) discovery issuer', async () => {
    const user = await login({
      issuer: 'https://login.example/{tenantid}/v2.0',
      idToken: (n) => jwt({ ...goodClaims(n), iss: 'https://login.example/1234/v2.0' }),
    });
    assert.equal(user?.username, 'alice');
  });

  it('skips the issuer check when discovery does not advertise one', async () => {
    const user = await login({ issuer: undefined, idToken: (n) => jwt({ ...goodClaims(n), iss: 'whatever' }) });
    assert.equal(user?.username, 'alice');
  });

  it('rejects a malformed id_token instead of treating it as empty', async () => {
    assert.equal(await login({ idToken: () => 'not-a-jwt' }), null);
    assert.equal(await login({ idToken: () => `${b64({})}.!!!.sig` }), null);
  });

  it('rejects userinfo whose sub differs from the id_token sub', async () => {
    assert.equal(await login({ idToken: (n) => jwt(goodClaims(n)), sub: 'sub-mallory' }), null);
  });
});

describe('checkIdTokenClaims', () => {
  const expected = { clientId: CLIENT_ID, nonce: 'n1', issuer: 'https://idp.example' };
  const claims = () => ({ iss: 'https://idp.example', aud: CLIENT_ID, exp: inAnHour(), nonce: 'n1' });

  it('returns null for valid claims', () => {
    assert.equal(checkIdTokenClaims(claims(), expected), null);
  });

  it('tolerates a few seconds of clock skew on exp', () => {
    assert.equal(checkIdTokenClaims({ ...claims(), exp: Math.floor(Date.now() / 1000) - 10 }, expected), null);
  });

  it('reports the failing claim', () => {
    assert.match(checkIdTokenClaims({ ...claims(), nonce: 'x' }, expected) ?? '', /nonce/);
    assert.match(checkIdTokenClaims({ ...claims(), aud: 'x' }, expected) ?? '', /aud/);
    assert.match(checkIdTokenClaims({ ...claims(), iss: 'x' }, expected) ?? '', /iss/);
  });
});
