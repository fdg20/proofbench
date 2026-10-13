import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeDelivery,
  analyzeExposure,
  analyzeQuality,
  analyzeSecurity,
  extractLinks,
  summarize,
} from './checks.js';
import { inspectUrl } from './safety.js';
import server from '../server.js';

test('public HTTP fails transport and local HTTP does not', () => {
  const publicHttp = analyzeDelivery({ status: 200, https: false, local: false, chainLength: 1, httpProbe: null });
  assert.equal(publicHttp.find((item) => item.id === 'transport').status, 'fail');
  const localHttp = analyzeDelivery({ status: 200, https: false, local: true, chainLength: 1, httpProbe: null });
  assert.equal(localHttp.find((item) => item.id === 'transport').status, 'note');
});

test('missing HSTS on HTTPS is a failure and cookie values are not reported', () => {
  const findings = analyzeSecurity({
    headers: {},
    cookies: ['session=super-secret-value; HttpOnly'],
    https: true,
    html: '<html></html>',
  });
  assert.equal(findings.find((item) => item.id === 'hsts').status, 'fail');
  assert.equal(findings.find((item) => item.id === 'cookies').status, 'fail');
  assert.equal(JSON.stringify(findings).includes('super-secret-value'), false);
});

test('quality flags the practice-page issues', () => {
  const html = `<!DOCTYPE html><html lang="en"><head><title>Practice page</title></head><body>
    <h1>Practice page</h1><h3>Skipped</h3><h1>Second</h1>
    <img alt="ok" src="x"><img src="y">
    <input type="email" placeholder="Email">
    <button></button><button>Send</button>
  </body></html>`;
  const findings = analyzeQuality(html, 'text/html');
  assert.equal(findings.find((item) => item.id === 'description').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'viewport').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'h1').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'headings').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'alt').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'labels').status, 'warn');
  assert.equal(findings.find((item) => item.id === 'buttons').status, 'warn');
});

test('exposure results do not include response bodies', () => {
  const findings = analyzeExposure([
    { path: '/.env', sensitive: true, status: 200, kind: 'file' },
    { path: '/.git/HEAD', sensitive: true, status: 200, kind: 'html' },
    { path: '/backup.sql', sensitive: true, status: 404 },
    { path: '/robots.txt', sensitive: false, status: 200 },
  ]);
  const env = findings.find((item) => item.id === '/.env');
  const git = findings.find((item) => item.id === '/.git/HEAD');
  assert.equal(env.status, 'fail');
  assert.equal(git.status, 'warn');
  assert.match(env.detail, /not saved/i);
  assert.equal(JSON.stringify(findings).includes('DB_PASSWORD'), false);
});

test('unquoted viewport and language are recognized', () => {
  const html = '<!doctype html><html lang=en><head><meta name=viewport content="width=device-width,initial-scale=1"><title>Example Domain</title></head><body><h1>Example</h1></body></html>';
  const findings = analyzeQuality(html, 'text/html');
  assert.equal(findings.find((item) => item.id === 'viewport').status, 'pass');
  assert.equal(findings.find((item) => item.id === 'lang').status, 'pass');
  assert.equal(findings.find((item) => item.id === 'h1').status, 'pass');
});

test('link extraction stays on the same site and skips mail and script links', () => {
  const html = `
    <a href="/one">One</a>
    <a href="/one#part">Repeat</a>
    <a href="mailto:a@example.com">Mail</a>
    <a href="javascript:void(0)">Script</a>
    <a href="https://other.example/away">Away</a>
    ${Array.from({ length: 20 }, (_, index) => `<a href="/p${index}">P</a>`).join('')}
  `;
  const links = extractLinks(html, 'https://shop.example/page');
  assert.equal(links.length, 12);
  assert.equal(links[0], 'https://shop.example/one');
  assert.equal(links.some((link) => link.includes('other.example')), false);
});

test('score weights a security failure more than a quality warning', () => {
  const summary = summarize([
    { group: 'Security', status: 'fail', title: 'HSTS', detail: 'missing' },
    { group: 'Quality', status: 'warn', title: 'Alt', detail: 'missing' },
  ]);
  assert.equal(summary.score, 82);
  assert.equal(summary.grade, 'Fair');
});

test('the server is exported for Vercel and does not listen on import', () => {
  assert.equal(typeof server.listen, 'function');
  assert.equal(server.listening, false);
});

test('blocked and local addresses are classified without fetching them', async () => {
  await assert.rejects(() => inspectUrl('http://169.254.169.254/latest/meta-data/'), /not allowed/);
  await assert.rejects(() => inspectUrl('http://metadata.google.internal/'), /not allowed/);
  await assert.rejects(() => inspectUrl('http://user:pass@example.com/'), /password/);
  await assert.rejects(() => inspectUrl('file:///c:/windows'), /http/);
  const local = await inspectUrl('http://127.0.0.1:4173/sample.html');
  assert.equal(local.local, true);
});
