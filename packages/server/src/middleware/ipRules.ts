import net from 'node:net';
import type { Request, Response, NextFunction } from 'express';
import type { IncomingMessage, Server } from 'http';
import type { Duplex } from 'stream';
import { queryAll } from '../db/helpers.js';
import { getSetting } from '../services/settings.js';
import { logAudit } from '../services/audit.js';
import { resolveClientIp } from '../services/ip.js';

interface IpRuleRow {
  type: string;
  cidr: string;
}

type Family = 'ipv4' | 'ipv6';

/** "10.0.0.0/8", "2001:db8::/32", "192.168.1.5", "::1" → parsed, or null if it is none of those. */
function parseIpRule(rule: string): { family: Family; address: string; prefix: number | null } | null {
  const [address, prefixStr, ...extra] = rule.trim().split('/');
  if (extra.length > 0) return null;
  const kind = net.isIP(address);
  if (kind === 0) return null;
  const family: Family = kind === 4 ? 'ipv4' : 'ipv6';
  if (prefixStr === undefined) return { family, address, prefix: null };
  if (!/^\d{1,3}$/.test(prefixStr)) return null;
  const prefix = Number(prefixStr);
  if (prefix > (family === 'ipv4' ? 32 : 128)) return null;
  return { family, address, prefix };
}

/** Whether `rule` is a valid IPv4/IPv6 address or CIDR range (used to validate input). */
export function isValidIpRule(rule: string): boolean {
  return parseIpRule(rule) !== null;
}

export function matchesCidr(ip: string, rule: string): boolean {
  const parsed = parseIpRule(rule);
  if (!parsed) return false;
  // strip an IPv6 zone id ("fe80::1%eth0") and the IPv4-mapped prefix
  const client = ip.split('%')[0].replace(/^::ffff:/i, '');
  const kind = net.isIP(client);
  if (kind === 0 || (kind === 4 ? 'ipv4' : 'ipv6') !== parsed.family) return false;
  const list = new net.BlockList();
  if (parsed.prefix === null) list.addAddress(parsed.address, parsed.family);
  else list.addSubnet(parsed.address, parsed.prefix, parsed.family);
  return list.check(client, parsed.family);
}

export type IpRuleVerdict = 'not_in_allowlist' | 'in_denylist' | null;

/** Applies the configured IP rules to `clientIp`; returns why it is blocked, or null if allowed. */
export function evaluateIpRules(clientIp: string): IpRuleVerdict {
  const enabled = getSetting('security.ip_rules_enabled') === 'true';
  if (!enabled) return null;

  const mode = getSetting('security.ip_rules_mode'); // 'allowlist' | 'denylist'
  const rules = queryAll<IpRuleRow>('SELECT type, cidr FROM ip_rules ORDER BY rowid');

  if (mode === 'allowlist') {
    const allowed = rules
      .filter((r) => r.type === 'allow')
      .some((r) => matchesCidr(clientIp, r.cidr));
    return allowed ? null : 'not_in_allowlist';
  }
  // denylist
  const denied = rules
    .filter((r) => r.type === 'deny')
    .some((r) => matchesCidr(clientIp, r.cidr));
  return denied ? 'in_denylist' : null;
}

export function ipRulesMiddleware(req: Request, res: Response, next: NextFunction): void {
  const clientIp = resolveClientIp(req);
  const verdict = evaluateIpRules(clientIp);
  if (verdict) {
    logAudit({
      eventType: 'security.ip_blocked',
      ipAddress: clientIp,
      details: { reason: verdict, path: req.path, method: req.method },
    });
    res.status(403).json({ error: 'Access denied' });
    return;
  }
  next();
}

/**
 * Applies the IP rules to every WebSocket upgrade on `server` (SSH/RDP/VNC/Telnet, /mlw).
 * Each proxy attaches its own 'upgrade' listener and Express never sees these requests, so
 * ipRulesMiddleware cannot cover them. Wrapping emit keeps this in one place and rejects the
 * upgrade before any of those listeners runs. Call it before the proxies are set up.
 */
export function guardUpgradesByIpRules(server: Server): void {
  const originalEmit = server.emit.bind(server) as (event: string | symbol, ...args: unknown[]) => boolean;
  server.emit = ((event: string | symbol, ...args: unknown[]): boolean => {
    if (event === 'upgrade') {
      const [req, socket] = args as [IncomingMessage, Duplex];
      const clientIp = resolveClientIp(req);
      const verdict = evaluateIpRules(clientIp);
      if (verdict) {
        logAudit({
          eventType: 'security.ip_blocked',
          ipAddress: clientIp,
          // pathname only: the query string carries the one-time ws ticket
          details: { reason: verdict, path: (req.url ?? '').split('?')[0], method: 'UPGRADE' },
        });
        // After 'upgrade' the HTTP parser no longer handles socket errors; without a listener a
        // blocked client resetting the connection (ECONNRESET) would crash the process.
        socket.on('error', () => { /* peer went away while being refused */ });
        socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        return true;
      }
    }
    return originalEmit(event, ...args);
  }) as typeof server.emit;
}
