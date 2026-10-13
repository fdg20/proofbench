export const EXPOSURE_PATHS = [
  { path: '/.env', sensitive: true },
  { path: '/.git/HEAD', sensitive: true },
  { path: '/.git/config', sensitive: true },
  { path: '/wp-config.php', sensitive: true },
  { path: '/server-status', sensitive: true },
  { path: '/phpinfo.php', sensitive: true },
  { path: '/backup.sql', sensitive: true },
  { path: '/web.config', sensitive: true },
  { path: '/robots.txt', sensitive: false },
];

export const GROUPS = ['Delivery', 'Security', 'Exposure', 'Quality', 'Performance', 'Links'];

const PENALTY = {
  Delivery: { fail: 16, warn: 5 },
  Security: { fail: 16, warn: 5 },
  Exposure: { fail: 18, warn: 5 },
  Quality: { fail: 6, warn: 2 },
  Performance: { fail: 8, warn: 3 },
  Links: { fail: 6, warn: 3 },
};

const STRONG_REFERRER = new Set([
  'no-referrer',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);

export function formatBytes(bytes) {
  const size = Number(bytes) || 0;
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(1)} MB`;
}

function clip(value, max = 500) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function finding(group, status, title, detail, id) {
  return { id, group, status, title: clip(title, 140), detail: clip(detail, 500) };
}

function decode(value) {
  return String(value || '')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, ' ');
}

function cleanText(value) {
  return decode(String(value || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function attr(tag, name) {
  const match = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\`]+))`, 'i').exec(tag || '');
  if (!match) return null;
  return decode(match[1] ?? match[2] ?? match[3] ?? '').trim();
}

function stripEmbedded(html) {
  return String(html || '')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ');
}

function isHtml(html, contentType) {
  const type = String(contentType || '').toLowerCase();
  if (type.includes('html') || type.includes('xhtml')) return true;
  return /^\s*(?:<!doctype html|<html)/i.test(html || '');
}

export function classifyPrefix(buffer, contentType) {
  const raw = Buffer.isBuffer(buffer) ? buffer.subarray(0, 180).toString('utf8') : String(buffer || '').slice(0, 180);
  const text = raw.replace(/^\uFEFF/, '').trim().toLowerCase();
  const type = String(contentType || '').toLowerCase();
  if (type.includes('html') || type.includes('xhtml') || text.startsWith('<!doctype html') || text.startsWith('<html')) {
    return 'html';
  }
  return 'file';
}

function hasFrameProtection(headers) {
  const xfo = String(headers['x-frame-options'] || '').toLowerCase();
  if (/\b(deny|sameorigin)\b/.test(xfo)) return true;
  const match = /(?:^|;)\s*frame-ancestors\s+([^;]+)/i.exec(headers['content-security-policy'] || '');
  if (!match) return false;
  const value = match[1].trim().toLowerCase();
  return Boolean(value) && value !== '*' && value !== "'*'";
}

export function analyzeDelivery({ status, https, local, chainLength, httpProbe }) {
  const findings = [];
  if (status >= 200 && status < 300) {
    findings.push(finding('Delivery', 'pass', 'Response status', `The final response was HTTP ${status}.`, 'status'));
  } else if (status === 401 || status === 403) {
    findings.push(finding('Delivery', 'warn', 'Response status', `HTTP ${status}. The page is not available to a logged-out visitor, so later checks only describe that response.`, 'status'));
  } else if (status === 429) {
    findings.push(finding('Delivery', 'warn', 'Response status', 'The site returned HTTP 429, so it was rate limiting this check.', 'status'));
  } else if (status >= 500) {
    findings.push(finding('Delivery', 'fail', 'Response status', `The final response was HTTP ${status}.`, 'status'));
  } else if (status >= 400) {
    findings.push(finding('Delivery', 'fail', 'Response status', `The final response was HTTP ${status}.`, 'status'));
  } else {
    findings.push(finding('Delivery', 'warn', 'Response status', `The final response was HTTP ${status}.`, 'status'));
  }

  if (!https && local) {
    findings.push(finding('Delivery', 'note', 'Plain HTTP on a local address', 'Local HTTP is normal for a dev server. Do not serve public traffic this way.', 'transport'));
  } else if (!https) {
    findings.push(finding('Delivery', 'fail', 'Page is served over HTTP', 'Anyone on the network path can read or alter this response. Serve it over HTTPS.', 'transport'));
  } else {
    findings.push(finding('Delivery', 'pass', 'HTTPS', 'The final page was fetched over HTTPS.', 'transport'));
  }

  const redirects = Math.max(0, Number(chainLength || 1) - 1);
  if (redirects >= 4) {
    findings.push(finding('Delivery', 'fail', 'Redirect chain', `The browser would follow ${redirects} redirects before the final page.`, 'redirects'));
  } else if (redirects >= 2) {
    findings.push(finding('Delivery', 'warn', 'Redirect chain', `The browser would follow ${redirects} redirects before the final page.`, 'redirects'));
  } else if (redirects === 1) {
    findings.push(finding('Delivery', 'pass', 'Redirect chain', 'There is one redirect before the final page.', 'redirects'));
  } else {
    findings.push(finding('Delivery', 'pass', 'Redirect chain', 'The first response was the final page.', 'redirects'));
  }

  if (https && httpProbe) {
    if (httpProbe.result === 'redirect') {
      findings.push(finding('Delivery', 'pass', 'HTTP redirects to HTTPS', `Port 80 answered with HTTP ${httpProbe.status} and sent browsers to HTTPS.`, 'https-upgrade'));
    } else if (httpProbe.result === 'open') {
      findings.push(finding('Delivery', 'fail', 'HTTP copy is still served', `Port 80 returned HTTP ${httpProbe.status} instead of redirecting to HTTPS.`, 'https-upgrade'));
    } else if (httpProbe.result === 'refused') {
      findings.push(finding('Delivery', 'pass', 'Plain HTTP is closed', 'Port 80 refused the connection, so a plain HTTP copy is not being served.', 'https-upgrade'));
    } else if (httpProbe.result === 'timeout') {
      findings.push(finding('Delivery', 'note', 'Plain HTTP could not be confirmed', 'Port 80 did not answer in time.', 'https-upgrade'));
    } else {
      findings.push(finding('Delivery', 'note', 'Plain HTTP check was inconclusive', httpProbe.error || `Port 80 returned HTTP ${httpProbe.status || 'unknown'}.`, 'https-upgrade'));
    }
  }

  return findings;
}

export function analyzeSecurity({ headers = {}, cookies = [], https = false, html = '' }) {
  const findings = [];
  const hsts = headers['strict-transport-security'] || '';
  if (!https) {
    findings.push(finding('Security', 'note', 'HSTS', 'HSTS only takes effect after the site is served over HTTPS.', 'hsts'));
  } else {
    const age = Number(/max-age\s*=\s*(\d+)/i.exec(hsts)?.[1] || 0);
    if (age >= 15552000) {
      findings.push(finding('Security', 'pass', 'HSTS', `Strict-Transport-Security max-age is ${age} seconds.`, 'hsts'));
    } else if (age > 0) {
      findings.push(finding('Security', 'warn', 'HSTS', `Strict-Transport-Security max-age is only ${age} seconds. Use at least 15552000 (180 days).`, 'hsts'));
    } else {
      findings.push(finding('Security', 'fail', 'HSTS', 'This HTTPS response has no Strict-Transport-Security header.', 'hsts'));
    }
  }

  const csp = headers['content-security-policy'] || '';
  const reportOnly = headers['content-security-policy-report-only'] || '';
  if (!csp && reportOnly) {
    findings.push(finding('Security', 'warn', 'Content Security Policy', 'A report-only policy is present, so the browser is not enforcing it yet.', 'csp'));
  } else if (!csp) {
    findings.push(finding('Security', 'warn', 'Content Security Policy', 'No Content-Security-Policy header was sent.', 'csp'));
  } else if (/unsafe-inline/i.test(csp) && /unsafe-eval/i.test(csp)) {
    findings.push(finding('Security', 'warn', 'Content Security Policy', 'The policy allows both unsafe-inline and unsafe-eval.', 'csp'));
  } else {
    findings.push(finding('Security', 'pass', 'Content Security Policy', 'A Content-Security-Policy header is present.', 'csp'));
  }

  if (hasFrameProtection(headers)) {
    findings.push(finding('Security', 'pass', 'Clickjacking protection', 'A frame policy keeps other sites from embedding this page.', 'frames'));
  } else {
    findings.push(finding('Security', 'fail', 'Clickjacking protection', 'Add X-Frame-Options or a Content-Security-Policy frame-ancestors directive.', 'frames'));
  }

  const nosniff = String(headers['x-content-type-options'] || '').toLowerCase();
  if (nosniff.includes('nosniff')) {
    findings.push(finding('Security', 'pass', 'Content type sniffing', 'X-Content-Type-Options is nosniff.', 'nosniff'));
  } else if (nosniff) {
    findings.push(finding('Security', 'warn', 'Content type sniffing', 'X-Content-Type-Options is present, but it is not nosniff.', 'nosniff'));
  } else {
    findings.push(finding('Security', 'warn', 'Content type sniffing', 'No X-Content-Type-Options: nosniff header was sent.', 'nosniff'));
  }

  const referrer = String(headers['referrer-policy'] || '').toLowerCase().split(',')[0].trim();
  if (STRONG_REFERRER.has(referrer)) {
    findings.push(finding('Security', 'pass', 'Referrer policy', `Referrer-Policy is ${referrer}.`, 'referrer'));
  } else if (!referrer) {
    findings.push(finding('Security', 'warn', 'Referrer policy', 'No Referrer-Policy header was sent.', 'referrer'));
  } else {
    findings.push(finding('Security', 'warn', 'Referrer policy', `Referrer-Policy is ${referrer}.`, 'referrer'));
  }

  const powered = headers['x-powered-by'] || '';
  if (powered) {
    findings.push(finding('Security', 'warn', 'Technology disclosure', `X-Powered-By discloses ${powered}.`, 'powered-by'));
  } else {
    findings.push(finding('Security', 'pass', 'Technology disclosure', 'No X-Powered-By header was sent.', 'powered-by'));
  }

  const server = headers.server || '';
  if (server && /\d+\.\d+/.test(server)) {
    findings.push(finding('Security', 'warn', 'Server version', `The Server header includes a version: ${server}.`, 'server'));
  } else if (server) {
    findings.push(finding('Security', 'pass', 'Server header', `The Server header does not include a version (${server}).`, 'server'));
  } else {
    findings.push(finding('Security', 'pass', 'Server header', 'No Server header was sent.', 'server'));
  }

  findings.push(...analyzeCookies(cookies, https));

  const allowOrigin = String(headers['access-control-allow-origin'] || '').trim();
  const allowCredentials = /true/i.test(headers['access-control-allow-credentials'] || '');
  if (allowOrigin === '*' && allowCredentials) {
    findings.push(finding('Security', 'fail', 'CORS', 'The response allows any origin and also allows credentials.', 'cors'));
  } else if (allowOrigin === '*') {
    findings.push(finding('Security', 'note', 'CORS', 'Any website may read this response in a browser. That is normal for a public page and unsafe if the response contains private data.', 'cors'));
  }

  if (https && html) {
    const mixed = [];
    for (const match of html.matchAll(/\b(?:src|href|action)\s*=\s*["']http:\/\/[^"']+/gi)) {
      if (/http:\/\/www\.w3\.org\//i.test(match[0])) continue;
      mixed.push(match[0]);
      if (mixed.length >= 3) break;
    }
    if (mixed.length) {
      findings.push(finding('Security', 'warn', 'Mixed content', `Found ${mixed.length} http:// resource link${mixed.length === 1 ? '' : 's'} on an HTTPS page. Example: ${mixed[0]}`, 'mixed'));
    }
  }

  return findings;
}

function analyzeCookies(cookies, https) {
  if (!cookies.length) {
    return [finding('Security', 'note', 'Cookies', 'This response did not set a cookie. Cookies created later by JavaScript are not visible here.', 'cookies')];
  }
  const issues = [];
  let secureMissing = false;
  for (const raw of cookies) {
    const name = clip(String(raw).split('=')[0].trim() || 'cookie', 40);
    const missing = [];
    if (!/;\s*httponly\b/i.test(raw)) missing.push('HttpOnly');
    if (https && !/;\s*secure\b/i.test(raw)) {
      missing.push('Secure');
      secureMissing = true;
    }
    if (!/;\s*samesite\s*=/i.test(raw)) missing.push('SameSite');
    if (/;\s*samesite\s*=\s*none\b/i.test(raw) && !/;\s*secure\b/i.test(raw)) {
      if (!missing.includes('Secure')) missing.push('Secure');
      secureMissing = true;
    }
    if (missing.length) issues.push(`${name} is missing ${missing.join(', ')}`);
  }
  if (!issues.length) {
    return [finding('Security', 'pass', 'Cookie flags', `${cookies.length} cookie${cookies.length === 1 ? '' : 's'} include the expected flags. Values were not stored.`, 'cookies')];
  }
  return [finding(
    'Security',
    secureMissing ? 'fail' : 'warn',
    'Cookie flags',
    `${issues.join(' ')} Values were not stored.`,
    'cookies',
  )];
}

function metaContent(html, name) {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    if ((attr(tag, 'name') || '').toLowerCase() !== name) continue;
    return attr(tag, 'content') || '';
  }
  return null;
}

export function analyzeQuality(html, contentType) {
  if (!isHtml(html, contentType)) {
    return [finding('Quality', 'note', 'Not an HTML page', contentType ? `Content-Type is ${contentType}.` : 'The response did not look like HTML.', 'not-html')];
  }
  const source = stripEmbedded(html);
  const findings = [];
  const title = cleanText((source.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '');
  if (!title) {
    findings.push(finding('Quality', 'fail', 'Title', 'The page has no title.', 'title'));
  } else if (title.length < 8 || title.length > 70) {
    findings.push(finding('Quality', 'warn', 'Title', `The title is ${title.length} characters: “${title}”. Aim for roughly 8 to 70.`, 'title'));
  } else {
    findings.push(finding('Quality', 'pass', 'Title', `The title is ${title.length} characters.`, 'title'));
  }

  const description = metaContent(source, 'description');
  if (description == null || !description) {
    findings.push(finding('Quality', 'warn', 'Meta description', 'The page has no meta description.', 'description'));
  } else if (description.length < 40 || description.length > 170) {
    findings.push(finding('Quality', 'warn', 'Meta description', `The description is ${description.length} characters. Aim for roughly 40 to 170.`, 'description'));
  } else {
    findings.push(finding('Quality', 'pass', 'Meta description', `The description is ${description.length} characters.`, 'description'));
  }

  const viewport = (source.match(/<meta\b[^>]*>/gi) || []).some((tag) => (attr(tag, 'name') || '').toLowerCase() === 'viewport');
  findings.push(viewport
    ? finding('Quality', 'pass', 'Viewport', 'A viewport meta tag is present.', 'viewport')
    : finding('Quality', 'warn', 'Viewport', 'No viewport meta tag was found, so phones may show a desktop layout.', 'viewport'));

  const canonical = (source.match(/<link\b[^>]*>/gi) || []).some((tag) => /\bcanonical\b/i.test(attr(tag, 'rel') || ''));
  findings.push(canonical
    ? finding('Quality', 'pass', 'Canonical link', 'A canonical link is present.', 'canonical')
    : finding('Quality', 'warn', 'Canonical link', 'No canonical link was found.', 'canonical'));

  const htmlTag = /<html\b[^>]*>/i.exec(source)?.[0] || '';
  const lang = attr(htmlTag, 'lang');
  findings.push(lang
    ? finding('Quality', 'pass', 'Page language', `The html element lang is ${lang}.`, 'lang')
    : finding('Quality', 'warn', 'Page language', 'The html element has no lang attribute.', 'lang'));

  const levels = [...source.matchAll(/<h([1-6])\b/gi)].map((match) => Number(match[1]));
  const h1Count = levels.filter((level) => level === 1).length;
  if (h1Count === 1) findings.push(finding('Quality', 'pass', 'H1 heading', 'The page has one H1.', 'h1'));
  else if (h1Count === 0) findings.push(finding('Quality', 'warn', 'H1 heading', 'The page has no H1.', 'h1'));
  else findings.push(finding('Quality', 'warn', 'H1 heading', `The page has ${h1Count} H1 headings.`, 'h1'));

  let previous = 0;
  let skipped = false;
  for (const level of levels) {
    if (previous && level > previous + 1) skipped = true;
    previous = level;
  }
  if (!levels.length) {
    findings.push(finding('Quality', 'warn', 'Headings', 'The page has no headings.', 'headings'));
  } else if (skipped) {
    findings.push(finding('Quality', 'warn', 'Heading order', 'A heading skips a level, which makes the outline harder to follow.', 'headings'));
  } else {
    findings.push(finding('Quality', 'pass', 'Heading order', 'Headings do not skip a level.', 'headings'));
  }

  const images = [...source.matchAll(/<img\b[^>]*>/gi)];
  const missingAlt = images.filter((match) => attr(match[0], 'alt') == null);
  if (!images.length) {
    findings.push(finding('Quality', 'note', 'Image text', 'The page has no images.', 'alt'));
  } else if (!missingAlt.length) {
    findings.push(finding('Quality', 'pass', 'Image text', `${images.length} image${images.length === 1 ? '' : 's'} include an alt attribute.`, 'alt'));
  } else {
    findings.push(finding('Quality', 'warn', 'Image text', `${missingAlt.length} of ${images.length} image${images.length === 1 ? '' : 's'} ${missingAlt.length === 1 ? 'has' : 'have'} no alt attribute. Use an empty alt when the image is decorative.`, 'alt'));
  }

  const buttons = [...source.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/gi)].slice(0, 40);
  const emptyButtons = buttons.filter((match) => {
    if (cleanText(match[2] || '')) return false;
    return attr(match[1], 'aria-label') == null
      && attr(match[1], 'aria-labelledby') == null
      && attr(match[1], 'title') == null;
  });
  if (buttons.length && emptyButtons.length) {
    findings.push(finding('Quality', 'warn', 'Button names', `${emptyButtons.length} button${emptyButtons.length === 1 ? '' : 's'} ${emptyButtons.length === 1 ? 'has' : 'have'} no accessible name.`, 'buttons'));
  } else if (buttons.length) {
    findings.push(finding('Quality', 'pass', 'Button names', 'Buttons on the page have an accessible name.', 'buttons'));
  }

  const fields = [
    ...source.matchAll(/<(input|textarea|select)\b([^>]*)>/gi),
  ].slice(0, 40);
  let considered = 0;
  let unlabeled = 0;
  for (const match of fields) {
    const kind = match[1].toLowerCase();
    const attrs = match[2] || '';
    if (kind === 'input') {
      const type = (attr(attrs, 'type') || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'image', 'reset'].includes(type)) continue;
    }
    considered += 1;
    if (attr(attrs, 'aria-label') != null || attr(attrs, 'aria-labelledby') != null || attr(attrs, 'title') != null) continue;
    const id = attr(attrs, 'id');
    if (id) {
      const label = new RegExp(`<label\\b[^>]*\\bfor\\s*=\\s*['"]${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`, 'i');
      if (label.test(source)) continue;
    }
    unlabeled += 1;
  }
  if (considered && unlabeled) {
    findings.push(finding('Quality', 'warn', 'Form labels', `${unlabeled} of ${considered} field${considered === 1 ? '' : 's'} ${unlabeled === 1 ? 'has' : 'have'} no label. Fields wrapped in a label without a for attribute are not detected.`, 'labels'));
  } else if (considered) {
    findings.push(finding('Quality', 'pass', 'Form labels', `${considered} field${considered === 1 ? '' : 's'} have a label.`, 'labels'));
  }

  return findings;
}

export function analyzePerformance({ headerMs, totalMs, bytes, truncated, encoding, status }) {
  if (status >= 400) {
    return [finding('Performance', 'note', 'Timing belongs to an error response', `Headers arrived in ${Math.round(headerMs)} ms. The body analyzed was ${formatBytes(bytes)}.`, 'timing')];
  }
  const findings = [];
  const headerStatus = headerMs < 800 ? 'pass' : headerMs < 1800 ? 'warn' : 'fail';
  findings.push(finding('Performance', headerStatus, 'Time to final headers', `${Math.round(headerMs)} ms, including redirects. Distance from this computer affects the number.`, 'ttfb'));
  const totalStatus = headerMs >= 1800 ? 'note' : totalMs < 2500 ? 'pass' : 'warn';
  findings.push(finding('Performance', totalStatus, 'Document download', `${Math.round(totalMs)} ms total and ${formatBytes(bytes)}${truncated ? ', stopped at 1 MB' : ''}.`, 'download'));
  if (encoding) {
    findings.push(finding('Performance', 'pass', 'Compression', `Content-Encoding is ${encoding}.`, 'compression'));
  } else if (bytes > 2000) {
    findings.push(finding('Performance', 'warn', 'Compression', 'No Content-Encoding header on a response large enough to compress.', 'compression'));
  } else {
    findings.push(finding('Performance', 'note', 'Compression', 'No Content-Encoding header. The response is small enough that this may be fine.', 'compression'));
  }
  if (bytes > 500000) {
    findings.push(finding('Performance', 'warn', 'Document size', `The HTML analyzed was ${formatBytes(bytes)}.`, 'size'));
  }
  return findings;
}

export function analyzeExposure(results) {
  const findings = [];
  const quiet = [];
  for (const item of results || []) {
    if (!item.sensitive) {
      const detail = item.error
        ? item.error
        : item.status === 200
          ? 'robots.txt is publicly available.'
          : `The robots.txt request finished with HTTP ${item.status}.`;
      findings.push(finding('Exposure', 'note', 'robots.txt', detail, 'robots'));
      continue;
    }
    if (item.error) {
      findings.push(finding('Exposure', 'warn', item.path, item.error, item.path));
      continue;
    }
    if (item.status >= 200 && item.status < 300) {
      if (item.kind === 'html') {
        findings.push(finding('Exposure', 'warn', `${item.path} returned HTML`, 'HTTP 200 looked like a normal HTML page, which often means the site shows its fallback page for unknown addresses. Confirm it is not the real file. The body was not saved.', item.path));
      } else {
        findings.push(finding('Exposure', 'fail', `${item.path} looks publicly reachable`, 'HTTP 200 did not look like HTML. Treat the path as public until you confirm otherwise. The body was not saved.', item.path));
      }
      continue;
    }
    if ([401, 403, 404, 410].includes(item.status)) {
      quiet.push(`${item.path} (${item.status})`);
      continue;
    }
    if (item.status >= 300 && item.status < 400) {
      findings.push(finding('Exposure', 'warn', `${item.path} redirects`, `HTTP ${item.status}. Confirm the redirect does not reveal the file.`, item.path));
      continue;
    }
    findings.push(finding('Exposure', 'warn', item.path, `Unexpected HTTP ${item.status}.`, item.path));
  }
  if (quiet.length) {
    findings.unshift(finding('Exposure', 'pass', 'Sensitive paths were not publicly readable', quiet.join(', '), 'exposure-ok'));
  }
  return findings;
}

export function extractLinks(html, baseUrl) {
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const links = [];
  const seen = new Set();
  const source = stripEmbedded(html);
  for (const match of source.matchAll(/<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi)) {
    const href = String(match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (!href || href.startsWith('#') || /^(?:mailto:|tel:|javascript:)/i.test(href)) continue;
    let url;
    try {
      url = new URL(href, base);
    } catch {
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
    if (url.host !== base.host) continue;
    url.hash = '';
    if (seen.has(url.href) || url.href === base.href) continue;
    seen.add(url.href);
    links.push(url.href);
    if (links.length >= 12) break;
  }
  return links;
}

export function analyzeLinks(results) {
  if (!results?.length) {
    return [finding('Links', 'note', 'Same-site links', 'No same-site links were found on the page.', 'links-none')];
  }
  const findings = [];
  const good = [];
  for (const item of results) {
    if (item.error) {
      findings.push(finding('Links', 'warn', item.url, item.error, item.url));
      continue;
    }
    if (item.status >= 200 && item.status < 400) {
      good.push(item.url);
      continue;
    }
    findings.push(finding('Links', 'fail', item.url, `HTTP ${item.status}.`, item.url));
  }
  if (good.length) {
    findings.unshift(finding('Links', 'pass', 'Same-site links responded', `${good.length} link${good.length === 1 ? '' : 's'} returned a usable response.`, 'links-ok'));
  }
  return findings;
}

export function summarize(findings, ran = { security: true, exposure: true }) {
  const counts = { pass: 0, warn: 0, fail: 0, note: 0 };
  let deducted = 0;
  for (const item of findings) {
    if (counts[item.status] != null) counts[item.status] += 1;
    deducted += PENALTY[item.group]?.[item.status] || 0;
  }
  const score = Math.max(0, Math.min(100, 100 - deducted));
  const grade = score >= 90 ? 'Solid' : score >= 75 ? 'Fair' : score >= 50 ? 'Uneven' : 'Needs work';
  let lead;
  if (counts.fail === 0 && counts.warn === 0) lead = 'These checks did not find a problem.';
  else if (counts.fail === 0) lead = `${counts.warn} warning${counts.warn === 1 ? '' : 's'} to review.`;
  else lead = `${counts.fail} failure${counts.fail === 1 ? '' : 's'} and ${counts.warn} warning${counts.warn === 1 ? '' : 's'}. Start with the failures.`;
  if (ran.security === false) lead += ' Security headers were not checked.';
  if (ran.exposure === false) lead += ' Public file checks were not run.';
  return {
    score,
    grade,
    counts,
    lead,
    partial: ran.security === false || ran.exposure === false,
  };
}
