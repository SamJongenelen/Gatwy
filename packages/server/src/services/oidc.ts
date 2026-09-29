import { getSetting } from './settings.js';
import { decrypt } from './encryption.js';
import { randomBytes } from 'crypto';

// In-memory state store for OIDC flows (state → { nonce, createdAt })
const stateStore = new Map<string, { nonce: string; createdAt: number }>();
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of stateStore) {
    if (now - v.createdAt > STATE_TTL_MS) stateStore.delete(k);
  }
}, 60_000);

export interface OidcUserInfo {
  sub: string;
  username: string;
  email: string | null;
  displayName: string | null;
  isAdmin: boolean;
}

interface OidcConfig {
  clientId: string;
  clientSecret: string;
  providerUrl: string;
  redirectUri: string;
  scope: string;
}

type TokenAuthMethod = 'client_secret_basic' | 'client_secret_post';

// Env OIDC_TOKEN_AUTH_METHOD overrides the UI setting. Accepts basic|post|client_secret_*.
function resolveTokenAuthMethod(): TokenAuthMethod {
  const raw = (
    process.env.OIDC_TOKEN_AUTH_METHOD ||
    getSetting('auth.oidc_token_auth_method') ||
    'client_secret_basic'
  )
    .trim()
    .toLowerCase();

  if (raw === 'client_secret_post' || raw === 'post') return 'client_secret_post';
  return 'client_secret_basic';
}

function getOidcConfig(): OidcConfig | null {
  const providerUrl = getSetting('auth.oidc_provider_url');
  const clientId = getSetting('auth.oidc_client_id');
  const encSecret = getSetting('auth.oidc_client_secret');
  const redirectUri = getSetting('auth.oidc_redirect_uri');
  if (!providerUrl || !clientId || !redirectUri) return null;
  const clientSecret = encSecret
    ? (() => { try { return decrypt(encSecret); } catch { return encSecret; } })()
    : '';
  const scope = getSetting('auth.oidc_scope') || 'openid email profile';
  return { clientId, clientSecret, providerUrl, redirectUri, scope };
}

export async function buildOidcAuthUrl(): Promise<{ url: string; state: string } | { error: string }> {
  const cfg = getOidcConfig();
  if (!cfg) {
    if (!getSetting('auth.oidc_provider_url')) return { error: 'OIDC provider URL is not configured' };
    if (!getSetting('auth.oidc_client_id'))   return { error: 'OIDC client ID is not configured' };
    if (!getSetting('auth.oidc_redirect_uri')) return { error: 'OIDC redirect URI is not configured' };
    return { error: 'OIDC configuration is incomplete' };
  }

  const discoveryUrl = cfg.providerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
  let authEndpoint: string;
  try {
    const res = await fetch(discoveryUrl);
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${discoveryUrl}`);
    const doc = await res.json() as { authorization_endpoint: string };
    authEndpoint = doc.authorization_endpoint;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[OIDC] Discovery error:', msg);
    return { error: `OIDC discovery failed: ${msg}. Verify the Provider URL points to the base of your IdP (e.g. https://accounts.google.com, not the discovery URL itself).` };
  }

  const state = randomBytes(16).toString('hex');
  const nonce = randomBytes(16).toString('hex');
  stateStore.set(state, { nonce, createdAt: Date.now() });

  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: 'code',
    scope: cfg.scope,
    state,
    nonce,
  });

  return { url: `${authEndpoint}?${params.toString()}`, state };
}

const ID_TOKEN_CLOCK_SKEW_MS = 60_000;

export function decodeIdTokenClaims(idToken: string): Record<string, unknown> | null {
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as unknown;
    return claims && typeof claims === 'object' && !Array.isArray(claims) ? claims as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// The id_token comes straight from the token endpoint over TLS in exchange for our
// authenticated code, so per OIDC Core 3.1.3.7 the signature check may be skipped;
// the claims still have to be validated. Returns a description of the first problem, or null.
export function checkIdTokenClaims(
  claims: Record<string, unknown>,
  expected: { clientId: string; nonce: string; issuer?: string },
): string | null {
  // Multi-tenant issuers (e.g. Azure "common") are templates such as {tenantid}: not comparable
  if (expected.issuer && !expected.issuer.includes('{')) {
    const trim = (s: string) => s.replace(/\/$/, '');
    if (typeof claims['iss'] !== 'string' || trim(claims['iss']) !== trim(expected.issuer)) return 'iss mismatch';
  }
  const aud = claims['aud'];
  if (!(aud === expected.clientId || (Array.isArray(aud) && aud.includes(expected.clientId)))) return 'aud mismatch';
  const exp = claims['exp'];
  if (typeof exp !== 'number' || exp * 1000 + ID_TOKEN_CLOCK_SKEW_MS < Date.now()) return 'expired or missing exp';
  if (claims['nonce'] !== expected.nonce) return 'nonce mismatch';
  return null;
}

export async function handleOidcCallback(
  code: string,
  state: string,
): Promise<OidcUserInfo | null> {
  const stored = stateStore.get(state);
  if (!stored) {
    console.error('[OIDC] Unknown or expired state');
    return null;
  }
  stateStore.delete(state);

  if (Date.now() - stored.createdAt > STATE_TTL_MS) {
    console.error('[OIDC] State expired');
    return null;
  }

  const cfg = getOidcConfig();
  if (!cfg) return null;

  const discoveryUrl = cfg.providerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
  let tokenEndpoint: string;
  let userinfoEndpoint: string;
  let issuer: string | undefined;
  try {
    const res = await fetch(discoveryUrl);
    const doc = await res.json() as { token_endpoint: string; userinfo_endpoint: string; issuer?: string };
    tokenEndpoint = doc.token_endpoint;
    userinfoEndpoint = doc.userinfo_endpoint;
    issuer = doc.issuer;
  } catch (err) {
    console.error('[OIDC] Discovery error:', err instanceof Error ? err.message : err);
    return null;
  }

  let accessToken: string;
  let idTokenClaims: Record<string, unknown>;
  try {
    const tokenAuth = resolveTokenAuthMethod();
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: cfg.redirectUri,
    });
    const tokenHeaders: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (tokenAuth === 'client_secret_post') {
      tokenBody.set('client_id', cfg.clientId);
      tokenBody.set('client_secret', cfg.clientSecret);
    } else {
      tokenHeaders.Authorization =
        'Basic ' + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
    }

    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: tokenHeaders,
      body: tokenBody.toString(),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error('[OIDC] Token exchange failed:', errBody);
      return null;
    }

    const tokenData = await tokenRes.json() as { access_token: string; id_token?: string };
    accessToken = tokenData.access_token;

    if (tokenData.id_token) {
      const claims = decodeIdTokenClaims(tokenData.id_token);
      const problem = claims
        ? checkIdTokenClaims(claims, { clientId: cfg.clientId, nonce: stored.nonce, issuer })
        : 'malformed id_token';
      if (problem || !claims) {
        console.error(`[OIDC] Rejected id_token: ${problem}`);
        return null;
      }
      idTokenClaims = claims;
    } else {
      idTokenClaims = {};
    }
  } catch (err) {
    console.error('[OIDC] Token exchange error:', err instanceof Error ? err.message : err);
    return null;
  }

  let userinfo: Record<string, unknown>;
  try {
    const uiRes = await fetch(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!uiRes.ok) throw new Error(`Userinfo failed: ${uiRes.status}`);
    userinfo = await uiRes.json() as Record<string, unknown>;
    // OIDC Core 5.3.2: the userinfo sub must match the id_token sub
    if (idTokenClaims['sub'] !== undefined && userinfo['sub'] !== undefined && idTokenClaims['sub'] !== userinfo['sub']) {
      console.error('[OIDC] Userinfo sub does not match id_token sub');
      return null;
    }
  } catch (err) {
    console.error('[OIDC] Userinfo error:', err instanceof Error ? err.message : err);
    userinfo = idTokenClaims;
  }

  const merged = { ...idTokenClaims, ...userinfo };

  const usernameClaim = getSetting('auth.oidc_username_claim') || 'preferred_username';
  const displayNameClaim = getSetting('auth.oidc_display_name_claim') || 'name';
  const adminGroupClaim = getSetting('auth.oidc_admin_group_claim');
  const adminGroupValue = getSetting('auth.oidc_admin_group_value');

  const sub = String(merged['sub'] ?? '');
  const rawUsername = String(merged[usernameClaim] ?? merged['email'] ?? sub);
  const username = rawUsername.toLowerCase().replace(/[^a-z0-9._-]/g, '_').slice(0, 64);
  const email = merged['email'] ? String(merged['email']) : null;
  const displayName = merged[displayNameClaim] ? String(merged[displayNameClaim]) : null;

  let isAdmin = false;
  if (adminGroupClaim && adminGroupValue) {
    const claimVal = merged[adminGroupClaim];
    if (Array.isArray(claimVal)) {
      isAdmin = claimVal.includes(adminGroupValue);
    } else if (claimVal) {
      isAdmin = String(claimVal) === adminGroupValue;
    }
  }

  if (!sub || !username) return null;

  return { sub, username, email, displayName, isAdmin };
}

export function isOidcEnabled(): boolean {
  return getSetting('auth.oidc_enabled') === 'true';
}
