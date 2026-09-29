import type { IncomingMessage } from 'http';
import { getSetting } from './settings.js';

/**
 * Whether `ip` is one of the reverse proxies configured in `security.trusted_proxies`
 * ("true"/"*" = everything, "false"/empty = nothing, otherwise a comma-separated list of
 * IPv4 addresses or CIDRs). Read on every call so UI changes take effect without a restart.
 * Used both as Express's `trust proxy` predicate and for WebSocket upgrades.
 */
export function isTrustedProxyAddress(ip: string): boolean {
  // Node.js reports IPv4 clients as ::ffff:x.x.x.x on dual-stack sockets.
  // Strip the IPv6-mapped prefix so configured entries like "192.168.1.1"
  // or "192.168.1.0/24" match correctly.
  const addr = stripMappedPrefix(ip);
  const val = getSetting('security.trusted_proxies').trim();
  if (!val || val === 'false') return false;
  if (val === 'true' || val === '*') return true;
  const entries = val.split(',').map((s) => s.trim()).filter(Boolean);
  return entries.some((entry) => {
    if (entry.includes('/')) {
      // CIDR match (IPv4 only)
      try {
        const [range, bitsStr] = entry.split('/');
        const bits = parseInt(bitsStr, 10);
        if (bits < 0 || bits > 32) return false;
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        const toNum = (s: string) =>
          s.split('.').reduce((acc, o) => ((acc << 8) + parseInt(o, 10)) >>> 0, 0) >>> 0;
        return (toNum(addr) & mask) === (toNum(range) & mask);
      } catch { return false; }
    }
    return entry === addr;
  });
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
