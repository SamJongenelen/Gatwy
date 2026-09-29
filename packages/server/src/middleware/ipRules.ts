import type { Request, Response, NextFunction } from 'express';
import type { IncomingMessage, Server } from 'http';
import type { Duplex } from 'stream';
import { queryAll } from '../db/helpers.js';
import { getSetting } from '../services/settings.js';
import { logAudit } from '../services/audit.js';
import { resolveClientIp } from '../services/ip.js';
import { matchesCidr, isValidIpRule } from '../services/cidr.js';

// re-exported: the matcher moved to services/cidr.ts so trusted-proxy handling can share it
export { matchesCidr, isValidIpRule };

interface IpRuleRow {
  type: string;
  cidr: string;
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
