import type { IncomingMessage } from 'http';
import { getSetting } from './settings.js';
import { matchesCidr, isValidIpRule } from './cidr.js';

/**
 * Whether `ip` is one of the reverse proxies configured in `security.trusted_proxies`
 * ("true"/"*" = everything, "false"/empty = nothing, otherwise a comma-separated list of
 * IPv4 addresses or CIDRs). Read on every call so UI changes take effect without a restart.
 * Used both as Express's `trust proxy` predicate and for WebSocket upgrades.
 */
export function isTrustedProxyAddress(ip: string): boolean {
  const val = getSetting('security.trusted_proxies').trim();
  if (!val || val === 'false') return false;
  if (val === 'true' || val === '*') return true;
  // IPv4 and IPv6 addresses and CIDR ranges. Node reports IPv4 clients as ::ffff:x.x.x.x on
  // dual-stack sockets: matchesCidr strips that prefix. A malformed entry trusts nobody.
  return val.split(',').some((entry) => matchesCidr(ip, entry));
}

/**
 * Validates a value for `security.trusted_proxies`; returns a message for the first problem, or null.
 * Accepts "", "true", "false", "*" or a comma-separated list of IPv4/IPv6 addresses and CIDR ranges.
 */
export function validateTrustedProxies(value: unknown): string | null {
  if (typeof value !== 'string') return 'security.trusted_proxies must be a string';
  const val = value.trim();
  if (!val || val === 'true' || val === 'false' || val === '*') return null;
  for (const raw of val.split(',')) {
    const entry = raw.trim();
    if (!isValidIpRule(entry)) {
      return `Invalid trusted proxy entry: "${entry}". Use IPv4/IPv6 addresses or CIDR ranges (an IPv4 address, not ::ffff:x.x.x.x).`;
    }
  }
  return null;
}

/**
 * Resolve the real client IP for both HTTP and WebSocket requests.
 *
 * HTTP routes benefit from Express's trust-proxy middleware which sets req.ip
 * correctly. WebSocket upgrade requests arrive before Express can set req.ip,
 * so we resolve it manually with the same rule Express uses: X-Forwarded-For is only
 * believed when the TCP peer is a trusted proxy, and the client is the first address
 * (walking the chain from the right) that is not itself a trusted proxy. An untrusted
 * peer can therefore not choose its own address by sending the header.
 */
export function resolveClientIp(req: IncomingMessage & { ip?: string }): string {
  // For HTTP routes Express already resolved trust proxy → req.ip is correct.
  // For WS upgrade requests req.ip is undefined; fall back to manual resolution.
  if (req.ip) {
    return stripMappedPrefix(req.ip);
  }

  const peer = req.socket?.remoteAddress ?? 'unknown';
  if (!isTrustedProxyAddress(peer)) return stripMappedPrefix(peer);

  // X-Forwarded-For may contain a comma-separated list, one entry per hop.
  const forwarded = req.headers['x-forwarded-for'];
  const chain = (Array.isArray(forwarded) ? forwarded.join(',') : forwarded ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (let i = chain.length - 1; i >= 0; i--) {
    if (!isTrustedProxyAddress(chain[i])) return stripMappedPrefix(chain[i]);
  }
  // Every hop is a trusted proxy (e.g. trusted_proxies = "*"): the leftmost is the client.
  return stripMappedPrefix(chain[0] ?? peer);
}

/** Strip IPv4-mapped IPv6 prefix: "::ffff:192.168.1.1" → "192.168.1.1" */
function stripMappedPrefix(ip: string): string {
  return ip.replace(/^::ffff:/i, '');
}
