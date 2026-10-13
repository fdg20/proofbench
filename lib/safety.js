import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const blocked = new BlockList();
blocked.addSubnet('169.254.0.0', 16, 'ipv4');
blocked.addSubnet('fe80::', 10, 'ipv6');
blocked.addAddress('0.0.0.0', 'ipv4');
blocked.addAddress('255.255.255.255', 'ipv4');
blocked.addAddress('::', 'ipv6');

const localNets = new BlockList();
localNets.addSubnet('10.0.0.0', 8, 'ipv4');
localNets.addSubnet('172.16.0.0', 12, 'ipv4');
localNets.addSubnet('192.168.0.0', 16, 'ipv4');
localNets.addSubnet('127.0.0.0', 8, 'ipv4');
localNets.addAddress('::1', 'ipv6');
localNets.addSubnet('fc00::', 7, 'ipv6');

const BLOCKED_NAMES = new Set([
  'metadata.google.internal',
  'metadata.goog',
]);

const hostCache = new Map();

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function remember(host, value) {
  if (hostCache.size > 100) hostCache.clear();
  hostCache.set(host, { ...value, at: Date.now() });
}

function recall(host) {
  const hit = hostCache.get(host);
  if (!hit) return null;
  if (Date.now() - hit.at > 30_000) {
    hostCache.delete(host);
    return null;
  }
  return hit;
}

function mappedAddresses(address) {
  const candidates = [address];
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) candidates.push(mapped[1]);
  return candidates;
}

function isBlocked(address) {
  return mappedAddresses(address).some((ip) => {
    try {
      return blocked.check(ip);
    } catch {
      return false;
    }
  });
}

function isLocalAddress(address) {
  return mappedAddresses(address).some((ip) => {
    try {
      return localNets.check(ip);
    } catch {
      return false;
    }
  });
}

export function parseHttpUrl(input) {
  if (typeof input !== 'string') throw fail(400, 'Enter a URL.');
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2000) throw fail(400, 'Enter a URL.');
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    throw fail(400, 'Enter a full URL, including https://');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw fail(400, 'Use an http or https URL.');
  }
  if (url.username || url.password) {
    throw fail(400, 'Remove the username and password from the URL.');
  }
  url.hash = '';
  return url;
}

async function resolveHost(host) {
  let timer;
  const pending = lookup(host, { all: true, verbatim: true }).then(
    (value) => ({ ok: true, value }),
    () => ({ ok: false }),
  );
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ ok: false, timeout: true }), 5000);
  });
  try {
    const result = await Promise.race([pending, timeout]);
    if (result.timeout || !result.ok) {
      throw fail(422, result.timeout
        ? 'The host name did not resolve in time.'
        : 'The host name did not resolve.');
    }
    return result.value.map((record) => record.address);
  } finally {
    clearTimeout(timer);
  }
}

export async function inspectUrl(input) {
  const url = typeof input === 'string' ? parseHttpUrl(input) : input;
  if (!(url instanceof URL)) throw fail(400, 'Enter a URL.');
  const host = url.hostname.replace(/\.$/, '').toLowerCase();
  if (!host || BLOCKED_NAMES.has(host) || host.endsWith('.metadata.google.internal')) {
    throw fail(400, 'That host is not allowed.');
  }

  const cached = recall(host);
  if (cached) {
    return { href: url.href, url, addresses: cached.addresses, local: cached.local };
  }

  let addresses;
  if (host === 'localhost' || host.endsWith('.localhost')) {
    addresses = ['127.0.0.1'];
  } else if (isIP(host)) {
    addresses = [host];
  } else {
    addresses = await resolveHost(host);
  }

  if (!addresses.length || addresses.some((address) => isBlocked(address))) {
    throw fail(400, 'That host is not allowed.');
  }

  const local = host === 'localhost'
    || host.endsWith('.localhost')
    || host.endsWith('.local')
    || addresses.every((address) => isLocalAddress(address));
  remember(host, { addresses, local });
  return { href: url.href, url, addresses, local };
}
