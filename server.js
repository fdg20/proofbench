/**
 * Proofbench — local checks for a site you are allowed to test.
 * Start with: node server.js
 * Then open the printed address.
 *
 * Listens on 127.0.0.1 only. Load tests are capped.
 * Bodies from sensitive paths are discarded and never returned.
 */
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EXPOSURE_PATHS,
  analyzeDelivery,
  analyzeExposure,
  analyzeLinks,
  analyzePerformance,
  analyzeQuality,
  analyzeSecurity,
  classifyPrefix,
  extractLinks,
  summarize,
} from './lib/checks.js';
import { inspectUrl } from './lib/safety.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function findPublicDir() {
  const candidates = [
    path.join(__dirname, 'public'),
    path.join(process.cwd(), 'public'),
  ];
  return candidates.find((dir) => existsSync(path.join(dir, 'index.html'))) || candidates[0];
}

const publicDir = findPublicDir();
const UA = 'Proofbench/1.0 (local authorized site check)';
const LIMITS = {
  maxConcurrency: 8,
  minDurationSec: 3,
  maxDurationSec: 10,
  maxRequests: 80,
  maxLinks: 12,
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
};

let locked = false;

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function securityHeaders() {
  return {
    'content-security-policy': "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'cross-origin-opener-policy': 'same-origin',
  };
}

function publicError(err) {
  const code = err.cause?.code || err.code || '';
  const blob = `${err.message || ''} ${err.cause?.message || ''} ${code}`;
  if (err.status && err.message && err.status < 500) return err.message;
  if (/CERT_|certificate|UNABLE_TO_VERIFY|SELF_SIGNED/i.test(blob)) return 'The TLS certificate was rejected.';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'The host name did not resolve.';
  if (code === 'ECONNREFUSED') return 'The connection was refused.';
  if (code === 'ECONNRESET') return 'The connection was reset.';
  if (
    err.name === 'TimeoutError'
    || code === 'UND_ERR_CONNECT_TIMEOUT'
    || code === 'UND_ERR_HEADERS_TIMEOUT'
    || code === 'UND_ERR_BODY_TIMEOUT'
  ) {
    return 'The site did not respond in time.';
  }
  return 'The site could not be fetched.';
}

function clampInt(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.round(number)));
}

function requireAuthorized(body) {
  if (!body || body.authorized !== true) {
    throw httpError(403, 'Confirm you are allowed to test this site.');
  }
}

function readChecks(body) {
  const keys = ['security', 'exposure', 'quality', 'performance', 'links'];
  const source = body.checks && typeof body.checks === 'object' ? body.checks : {};
  const checks = {};
  for (const key of keys) checks[key] = source[key] === true;
  if (!Object.values(checks).some(Boolean)) throw httpError(400, 'Choose at least one check.');
  return checks;
}

async function withLock(work) {
  if (locked) throw httpError(429, 'A test is already running.');
  locked = true;
  try {
    return await work();
  } finally {
    locked = false;
  }
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 32_000) throw httpError(400, 'Request is too large.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw httpError(400, 'Request was not valid JSON.');
  }
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    ...securityHeaders(),
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function sendText(res, status, text) {
  res.writeHead(status, {
    ...securityHeaders(),
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
  });
  res.end(text);
}

async function readLimited(res, max) {
  if (!res.body) return { buffer: Buffer.alloc(0), truncated: false };
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  try {
    while (total < max) {
      const { done, value } = await reader.read();
      if (done) break;
      const buf = Buffer.from(value);
      const room = max - total;
      if (buf.length > room) {
        chunks.push(buf.subarray(0, room));
        total += room;
        truncated = true;
        break;
      }
      chunks.push(buf);
      total += buf.length;
    }
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
  return {
    buffer: total ? Buffer.concat(chunks, total) : Buffer.alloc(0),
    truncated,
  };
}

async function mapPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index], index);
    }
  }
  const workers = Math.min(limit, items.length);
  if (workers > 0) await Promise.all(Array.from({ length: workers }, () => worker()));
  return results;
}

function pickHeaders(headers) {
  const names = [
    'content-security-policy',
    'content-security-policy-report-only',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'x-powered-by',
    'server',
    'access-control-allow-origin',
    'access-control-allow-credentials',
    'content-encoding',
    'content-type',
  ];
  const picked = {};
  for (const name of names) picked[name] = headers.get(name) || '';
  return picked;
}

function previewHeaders(headers) {
  const rows = [];
  headers.forEach((value, key) => {
    if (/cookie|authorization|token|secret|api-key|password/i.test(key)) return;
    rows.push({ name: key, value: String(value).slice(0, 180) });
  });
  return rows.slice(0, 40);
}

async function fetchDocument(href) {
  const started = performance.now();
  let current = href;
  const chain = [];
  let local = false;
  for (let hop = 0; hop < 6; hop += 1) {
    const inspected = await inspectUrl(current);
    current = inspected.href;
    local = inspected.local;
    const hopStart = performance.now();
    const res = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(12000),
      headers: {
        'user-agent': UA,
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en',
      },
    });
    chain.push({
      url: current,
      status: res.status,
      ms: Math.round(performance.now() - hopStart),
    });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get('location');
      await res.body?.cancel().catch(() => {});
      if (!location || hop === 5) throw httpError(422, 'The site redirected too many times.');
      current = new URL(location, current).href;
      continue;
    }
    const headerMs = performance.now() - started;
    const { buffer, truncated } = await readLimited(res, 1_000_000);
    return {
      res,
      html: buffer.toString('utf8').replace(/\0/g, ''),
      chain,
      bytes: buffer.length,
      truncated,
      finalUrl: current,
      headerMs,
      totalMs: performance.now() - started,
      local,
    };
  }
  throw httpError(422, 'The site redirected too many times.');
}

async function probeHttpUpgrade(targetUrl) {
  if (targetUrl.protocol !== 'https:') return null;
  if (targetUrl.port && targetUrl.port !== '443') return null;
  const httpUrl = new URL(targetUrl.href);
  httpUrl.protocol = 'http:';
  httpUrl.port = '';
  try {
    await inspectUrl(httpUrl);
    const res = await fetch(httpUrl.href, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
      headers: { 'user-agent': UA, accept: '*/*' },
    });
    const location = res.headers.get('location');
    await res.body?.cancel().catch(() => {});
    if ([301, 302, 303, 307, 308].includes(res.status) && location) {
      const next = new URL(location, httpUrl);
      if (next.protocol === 'https:') return { result: 'redirect', status: res.status };
    }
    if (res.status >= 200 && res.status < 300) return { result: 'open', status: res.status };
    return { result: 'other', status: res.status };
  } catch (err) {
    const code = err.cause?.code || err.code || '';
    if (code === 'ECONNREFUSED') return { result: 'refused' };
    if (err.name === 'TimeoutError' || code === 'UND_ERR_CONNECT_TIMEOUT') return { result: 'timeout' };
    return { result: 'other', error: publicError(err) };
  }
}

async function probeExposure(target, sensitive) {
  await inspectUrl(target);
  const res = await fetch(target, {
    method: 'GET',
    redirect: 'manual',
    cache: 'no-store',
    signal: AbortSignal.timeout(6000),
    headers: { 'user-agent': UA, accept: '*/*' },
  });
  let kind = 'unknown';
  if (sensitive && res.status >= 200 && res.status < 300) {
    const { buffer } = await readLimited(res, 180);
    kind = classifyPrefix(buffer, res.headers.get('content-type') || '');
  } else {
    await res.body?.cancel().catch(() => {});
  }
  return { status: res.status, kind };
}

async function checkExposure(origin) {
  return mapPool(EXPOSURE_PATHS, 4, async (item) => {
    const url = new URL(item.path, origin).href;
    try {
      const probed = await probeExposure(url, item.sensitive);
      return { path: item.path, sensitive: item.sensitive, ...probed };
    } catch (err) {
      return { path: item.path, sensitive: item.sensitive, error: publicError(err) };
    }
  });
}

async function checkLinks(links) {
  return mapPool(links, 4, async (link) => {
    try {
      await inspectUrl(link);
      const res = await fetch(link, {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
        headers: { 'user-agent': UA, accept: '*/*' },
      });
      await res.body?.cancel().catch(() => {});
      return { url: link, status: res.status };
    } catch (err) {
      return { url: link, error: publicError(err) };
    }
  });
}

async function runAudit(body) {
  requireAuthorized(body);
  const checks = readChecks(body);
  const target = await inspectUrl(body.url);
  let doc;
  try {
    doc = await fetchDocument(target.href);
  } catch (err) {
    if (err.status) throw err;
    throw httpError(422, publicError(err));
  }

  const finalUrl = new URL(doc.finalUrl);
  const headers = pickHeaders(doc.res.headers);
  const cookies = typeof doc.res.headers.getSetCookie === 'function' ? doc.res.headers.getSetCookie() : [];
  const https = finalUrl.protocol === 'https:';

  const exposurePromise = checks.exposure ? checkExposure(finalUrl.origin) : Promise.resolve([]);
  const linkList = checks.links ? extractLinks(doc.html, doc.finalUrl).slice(0, LIMITS.maxLinks) : [];
  const linksPromise = checks.links ? checkLinks(linkList) : Promise.resolve([]);
  const probePromise = probeHttpUpgrade(finalUrl);

  const [exposure, links, httpProbe] = await Promise.all([exposurePromise, linksPromise, probePromise]);
  const findings = [
    ...analyzeDelivery({
      status: doc.res.status,
      https,
      local: doc.local,
      chainLength: doc.chain.length,
      httpProbe,
    }),
  ];
  if (checks.security) {
    findings.push(...analyzeSecurity({ headers, cookies, https, html: doc.html }));
  }
  if (checks.exposure) findings.push(...analyzeExposure(exposure));
  if (checks.quality) findings.push(...analyzeQuality(doc.html, headers['content-type']));
  if (checks.performance) {
    findings.push(...analyzePerformance({
      headerMs: doc.headerMs,
      totalMs: doc.totalMs,
      bytes: doc.bytes,
      truncated: doc.truncated,
      encoding: headers['content-encoding'],
      status: doc.res.status,
    }));
  }
  if (checks.links) findings.push(...analyzeLinks(links));

  const ran = { delivery: true, ...checks };
  return {
    requestedUrl: target.href,
    finalUrl: doc.finalUrl,
    chain: doc.chain,
    summary: summarize(findings, ran),
    findings,
    headers: previewHeaders(doc.res.headers),
    meta: {
      status: doc.res.status,
      contentType: headers['content-type'],
      bytes: doc.bytes,
      truncated: doc.truncated,
      headerMs: Math.round(doc.headerMs),
      totalMs: Math.round(doc.totalMs),
      local: doc.local,
      https,
      origin: finalUrl.origin,
    },
    ran,
    fetchedAt: new Date().toISOString(),
  };
}

async function timedFetch(href) {
  const started = performance.now();
  let current = href;
  for (let hop = 0; hop < 3; hop += 1) {
    const inspected = await inspectUrl(current);
    current = inspected.href;
    const res = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
      headers: { 'user-agent': UA, accept: 'text/html,*/*;q=0.8' },
    });
    if ([301, 302, 303, 307, 308].includes(res.status) && hop < 2) {
      const location = res.headers.get('location');
      await res.body?.cancel().catch(() => {});
      if (!location) return { status: res.status, ms: performance.now() - started };
      current = new URL(location, current).href;
      continue;
    }
    await readLimited(res, 256 * 1024);
    return { status: res.status, ms: performance.now() - started };
  }
  return { error: 'The site redirected too many times.', ms: performance.now() - started };
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Math.round(sorted[index]);
}

function latencyBuckets(values) {
  const cuts = [
    { label: '<100 ms', min: 0, max: 100 },
    { label: '<300 ms', min: 100, max: 300 },
    { label: '<800 ms', min: 300, max: 800 },
    { label: '<1.5 s', min: 800, max: 1500 },
    { label: 'slower', min: 1500, max: Infinity },
  ];
  return cuts.map((cut) => ({
    label: cut.label,
    count: values.filter((value) => value >= cut.min && value < cut.max).length,
  }));
}

async function runLoad(body) {
  requireAuthorized(body);
  const target = await inspectUrl(body.url);
  const concurrency = clampInt(body.concurrency, 1, LIMITS.maxConcurrency, 4);
  const durationSec = clampInt(body.durationSec, LIMITS.minDurationSec, LIMITS.maxDurationSec, 5);
  const latencies = [];
  const statuses = {};
  const reasonMap = new Map();
  let successes = 0;
  let failures = 0;
  let completed = 0;
  const end = Date.now() + durationSec * 1000;
  const started = performance.now();

  async function one() {
    try {
      const result = await timedFetch(target.href);
      if (result.status) {
        statuses[result.status] = (statuses[result.status] || 0) + 1;
        latencies.push(result.ms);
        if (result.status >= 500) failures += 1;
        else successes += 1;
      } else {
        failures += 1;
        const message = result.error || 'The request failed.';
        reasonMap.set(message, (reasonMap.get(message) || 0) + 1);
      }
    } catch (err) {
      failures += 1;
      const message = publicError(err);
      reasonMap.set(message, (reasonMap.get(message) || 0) + 1);
    }
  }

  async function worker() {
    while (Date.now() < end && completed < LIMITS.maxRequests) {
      completed += 1;
      await one();
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const elapsedMs = Math.max(1, Math.round(performance.now() - started));
  const sorted = latencies.map((value) => Math.round(value)).sort((a, b) => a - b);
  const reasons = [...reasonMap.entries()]
    .map(([message, count]) => ({ message, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 3);

  return {
    url: target.href,
    startedAt: new Date(Date.now() - elapsedMs).toISOString(),
    elapsedMs,
    applied: {
      concurrency,
      durationSec,
      maxRequests: LIMITS.maxRequests,
    },
    stoppedBecause: completed >= LIMITS.maxRequests ? 'request cap' : 'time window',
    successes,
    failures,
    statuses,
    rps: Number(((sorted.length / elapsedMs) * 1000).toFixed(1)),
    min: sorted.length ? sorted[0] : null,
    max: sorted.length ? sorted[sorted.length - 1] : null,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    buckets: latencyBuckets(sorted),
    reasons,
  };
}

async function serveStatic(pathname, req, res) {
  const relUrl = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  if (!relUrl || relUrl.includes('\0') || relUrl.includes(':')) {
    sendText(res, 404, 'Not found.');
    return;
  }
  const filePath = path.join(publicDir, relUrl);
  const rel = path.relative(publicDir, filePath);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    sendText(res, 404, 'Not found.');
    return;
  }
  try {
    const body = await fs.readFile(filePath);
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      ...securityHeaders(),
      'content-type': type,
      'content-length': body.length,
      'cache-control': 'no-cache',
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (err) {
    if (err.code === 'ENOENT') sendText(res, 404, 'Not found.');
    else throw err;
  }
}

async function onRequest(req, res) {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/api/health') {
      sendJson(res, 200, { ok: true, limits: LIMITS });
      return;
    }
    if (url.pathname === '/api/audit' || url.pathname === '/api/load') {
      if (req.method !== 'POST') throw httpError(405, 'Use POST for this check.');
      const body = await readJson(req);
      const result = await withLock(() => (
        url.pathname === '/api/audit' ? runAudit(body) : runLoad(body)
      ));
      sendJson(res, 200, result);
      return;
    }
    if (url.pathname.startsWith('/api/')) {
      sendJson(res, 404, { error: 'Not found.' });
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendText(res, 405, 'Method not allowed.');
      return;
    }
    const pathname = decodeURIComponent(url.pathname);
    const favicon = pathname === '/favicon.ico' || pathname === '/favicon.png';
    await serveStatic(favicon ? '/favicon.svg' : pathname, req, res);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) console.error(err);
    if (!res.headersSent) {
      const message = status >= 500 ? 'The bench hit an unexpected error.' : (err.message || 'The check failed.');
      sendJson(res, status, { error: message });
    }
  }
}

const server = createServer(onRequest);

function listen(port) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.off('error', onError);
      reject(err);
    };
    server.once('error', onError);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', onError);
      resolve(server);
    });
  });
}

async function main() {
  const preferred = Number(process.env.PORT) || 4173;
  let listening = null;
  let port = preferred;
  for (let offset = 0; offset < 10; offset += 1) {
    try {
      listening = await listen(preferred + offset);
      port = preferred + offset;
      break;
    } catch (err) {
      if (err.code !== 'EADDRINUSE') throw err;
    }
  }
  if (!listening) throw new Error('No free port from 4173 to 4182.');
  console.log(`Proofbench is running at http://127.0.0.1:${port}`);
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : '';
const launchedDirectly = invoked === path.resolve(fileURLToPath(import.meta.url));
if (launchedDirectly && !process.env.VERCEL) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

export default server;
