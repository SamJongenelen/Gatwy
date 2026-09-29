import net from 'node:net';

type Family = 'ipv4' | 'ipv6';

/** "10.0.0.0/8", "2001:db8::/32", "192.168.1.5", "::1" → parsed, or null if it is none of those. */
function parseIpRule(rule: string): { family: Family; address: string; prefix: number | null } | null {
  const [address, prefixStr, ...extra] = rule.trim().split('/');
  if (extra.length > 0) return null;
  const kind = net.isIP(address);
  if (kind === 0) return null;
  // Clients are normalised to plain IPv4 before matching, so an IPv4-mapped rule would never match
  if (kind === 6 && /^::ffff:/i.test(address)) return null;
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

/** Whether `ip` is the address `rule` names or inside the range it names. A malformed rule matches nothing. */
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
