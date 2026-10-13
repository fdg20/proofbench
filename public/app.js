const CHECK_KEYS = ['security', 'exposure', 'quality', 'performance', 'links'];
const GROUP_ORDER = ['Delivery', 'Security', 'Exposure', 'Quality', 'Performance', 'Links'];
const RANK = { fail: 0, warn: 1, note: 2, pass: 3 };
const PILL = { fail: 'Fail', warn: 'Warn', note: 'Note', pass: 'Pass' };
const STORAGE = 'proofbench-target';

const form = document.getElementById('audit-form');
const urlInput = document.getElementById('url');
const authBox = document.getElementById('authorized');
const formError = document.getElementById('form-error');
const runAuditBtn = document.getElementById('run-audit');
const runLoadBtn = document.getElementById('run-load');
const useSample = document.getElementById('use-sample');
const concurrency = document.getElementById('concurrency');
const duration = document.getElementById('duration');
const concurrencyOut = document.getElementById('concurrency-out');
const durationOut = document.getElementById('duration-out');
const capsNote = document.getElementById('caps-note');
const results = document.getElementById('results');

let lastAudit = null;
let lastLoad = null;
let latest = 'audit';

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'hidden') node.hidden = true;
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function countPhrase(count, singular, plural) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function formatBytes(bytes) {
  const size = Number(bytes) || 0;
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(1)} MB`;
}

function gradeSlug(grade) {
  return String(grade || '').toLowerCase().replace(/\s+/g, '-');
}

function shortUrl(href) {
  try {
    const url = new URL(href);
    return `${url.host}${url.pathname === '/' ? '' : url.pathname}`;
  } catch {
    return href;
  }
}

function safeHost(href) {
  try {
    return new URL(href).host.replace(/[^\w.-]+/g, '_') || 'report';
  } catch {
    return 'report';
  }
}

function showError(message) {
  formError.hidden = false;
  formError.textContent = message;
}

function clearError() {
  formError.hidden = true;
  formError.textContent = '';
}

function setStatus(text) {
  const current = document.getElementById('run-status');
  if (!text) {
    current?.remove();
    return;
  }
  if (current) {
    current.textContent = text;
    return;
  }
  results.prepend(el('p', { id: 'run-status', class: 'run-status' }, [text]));
}

function setBusy(mode) {
  const busy = Boolean(mode);
  runAuditBtn.disabled = busy;
  runLoadBtn.disabled = busy;
  useSample.disabled = busy;
  runAuditBtn.textContent = mode === 'audit' ? 'Checking…' : 'Run checks';
  runLoadBtn.textContent = mode === 'load' ? 'Running…' : 'Run load smoke test';
  results.setAttribute('aria-busy', busy ? 'true' : 'false');
}

function syncOutputs() {
  concurrencyOut.textContent = concurrency.value;
  durationOut.textContent = duration.value;
}

function clampSlider(input) {
  const max = Number(input.max);
  const min = Number(input.min);
  let value = Number(input.value);
  if (value > max) value = max;
  if (value < min) value = min;
  input.value = String(value);
}

function readUrl() {
  const value = urlInput.value.trim();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Enter a full URL, including https://');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Use an http or https URL.');
  }
  return parsed.href;
}

function readChecks() {
  const checks = {};
  for (const key of CHECK_KEYS) checks[key] = document.getElementById(`check-${key}`).checked;
  if (!Object.values(checks).some(Boolean)) throw new Error('Choose at least one check.');
  return checks;
}

function payload() {
  const url = readUrl();
  if (!authBox.checked) throw new Error('Confirm you are allowed to test this site.');
  return {
    url,
    authorized: true,
    checks: readChecks(),
  };
}

function persist() {
  const checks = {};
  for (const key of CHECK_KEYS) checks[key] = document.getElementById(`check-${key}`).checked;
  localStorage.setItem(STORAGE, JSON.stringify({
    url: urlInput.value.trim(),
    checks,
    concurrency: Number(concurrency.value),
    duration: Number(duration.value),
  }));
}

function restore() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE) || 'null');
    if (!saved) return;
    if (typeof saved.url === 'string') urlInput.value = saved.url;
    if (saved.checks) {
      for (const key of CHECK_KEYS) {
        const box = document.getElementById(`check-${key}`);
        if (box && typeof saved.checks[key] === 'boolean') box.checked = saved.checks[key];
      }
    }
    if (typeof saved.concurrency === 'number') concurrency.value = String(saved.concurrency);
    if (typeof saved.duration === 'number') duration.value = String(saved.duration);
  } catch {
    /* ignore a damaged saved target */
  }
}

async function loadHealth() {
  try {
    const response = await fetch('/api/health', { cache: 'no-store' });
    const data = await response.json();
    const limits = data.limits || {};
    if (limits.maxConcurrency) concurrency.max = String(limits.maxConcurrency);
    if (limits.minDurationSec) duration.min = String(limits.minDurationSec);
    if (limits.maxDurationSec) duration.max = String(limits.maxDurationSec);
    clampSlider(concurrency);
    clampSlider(duration);
    syncOutputs();
    if (limits.maxConcurrency && limits.maxRequests) {
      capsNote.textContent = `Up to ${limits.maxConcurrency} requests at a time, for ${limits.minDurationSec} to ${limits.maxDurationSec} seconds, and ${limits.maxRequests} requests total.`;
    }
  } catch {
    capsNote.textContent = 'Load limits appear when the server is running.';
  }
}

async function postJson(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      cache: 'no-store',
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error('Proofbench could not be reached. Keep this server running.');
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'The check failed.');
  return data;
}

function tally(items) {
  const counts = { fail: 0, warn: 0, note: 0, pass: 0 };
  for (const item of items) if (counts[item.status] != null) counts[item.status] += 1;
  return counts;
}

function tallyText(items) {
  const counts = tally(items);
  if (!counts.fail && !counts.warn && !counts.note) return `${counts.pass} passed`;
  const parts = [];
  if (counts.fail) parts.push(`${counts.fail} failure${counts.fail === 1 ? '' : 's'}`);
  if (counts.warn) parts.push(`${counts.warn} warning${counts.warn === 1 ? '' : 's'}`);
  if (counts.note) parts.push(`${counts.note} note${counts.note === 1 ? '' : 's'}`);
  if (counts.pass) parts.push(`${counts.pass} passed`);
  return parts.join(' · ');
}

function findingList(items) {
  const list = el('ul', { class: 'findings' });
  for (const item of items) {
    list.append(el('li', { class: 'finding' }, [
      el('span', { class: `pill ${item.status}` }, [PILL[item.status] || item.status]),
      el('div', {}, [
        el('p', { class: 'finding-title' }, [item.title]),
        el('p', { class: 'finding-detail' }, [item.detail]),
      ]),
    ]));
  }
  return list;
}

function scoreRing(summary) {
  const slug = gradeSlug(summary.grade);
  const wrap = el('div', {
    class: 'score',
    role: 'img',
    'aria-label': `Score ${summary.score} out of 100, ${summary.grade}`,
  });
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  svg.setAttribute('class', 'ring');
  svg.setAttribute('aria-hidden', 'true');
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  for (const [className, offset] of [
    ['ring-track', 0],
    ['ring-value', circumference * (1 - summary.score / 100)],
  ]) {
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '60');
    circle.setAttribute('cy', '60');
    circle.setAttribute('r', String(radius));
    circle.setAttribute('class', className === 'ring-value' ? `ring-value grade-${slug}` : className);
    if (className === 'ring-value') {
      circle.setAttribute('transform', 'rotate(-90 60 60)');
      circle.setAttribute('stroke-dasharray', circumference.toFixed(2));
      circle.setAttribute('stroke-dashoffset', offset.toFixed(2));
    }
    svg.append(circle);
  }
  wrap.append(svg, el('div', { class: 'score-num' }, [
    el('strong', {}, [String(summary.score)]),
    el('span', {}, ['Score']),
  ]));
  return wrap;
}

function renderAudit(audit) {
  const summary = audit.summary || { score: 0, grade: 'Needs work', counts: {}, lead: 'No summary was returned.' };
  const counts = summary.counts || {};
  const slug = gradeSlug(summary.grade);
  const eyebrow = summary.partial ? `${summary.grade} · partial` : summary.grade;
  const copy = el('div', { class: 'hero-copy' }, [
    el('p', { class: `eyebrow grade-${slug}` }, [eyebrow]),
    el('h2', {}, [summary.lead || 'Checks finished.']),
    el('p', { class: 'final-url' }, [
      el('a', { href: audit.finalUrl, target: '_blank', rel: 'noopener noreferrer' }, [audit.finalUrl || '']),
    ]),
    el('p', { class: 'meta-line' }, [[
      `HTTP ${audit.meta?.status ?? '—'}`,
      audit.meta?.truncated ? `${formatBytes(audit.meta?.bytes)} analyzed` : formatBytes(audit.meta?.bytes),
      `${audit.meta?.headerMs ?? '—'} ms to headers`,
      `${audit.meta?.totalMs ?? '—'} ms total`,
    ].join(' · ')]),
    el('p', { class: 'counts' }, [[
      countPhrase(counts.fail || 0, 'failure', 'failures'),
      countPhrase(counts.warn || 0, 'warning', 'warnings'),
      `${counts.pass || 0} passed`,
      countPhrase(counts.note || 0, 'note', 'notes'),
    ].join(' · ')]),
  ]);

  if (Array.isArray(audit.chain) && audit.chain.length > 1) {
    const chain = el('ol', { class: 'chain' });
    for (const hop of audit.chain) chain.append(el('li', {}, [`${hop.status} ${shortUrl(hop.url)}`]));
    copy.append(chain);
  }

  const save = el('button', { type: 'button', class: 'secondary slim' }, ['Save report']);
  save.addEventListener('click', downloadReport);
  const print = el('button', { type: 'button', class: 'secondary slim' }, ['Print']);
  print.addEventListener('click', () => window.print());
  copy.append(el('div', { class: 'hero-actions' }, [save, print]));

  const nodes = [el('section', { class: 'hero' }, [scoreRing(summary), copy])];
  const grouped = new Map(GROUP_ORDER.map((name) => [name, []]));
  for (const item of audit.findings || []) {
    if (!grouped.has(item.group)) grouped.set(item.group, []);
    grouped.get(item.group).push(item);
  }
  for (const [name, items] of grouped) {
    if (!items.length) continue;
    const sorted = [...items].sort((a, b) => (RANK[a.status] ?? 9) - (RANK[b.status] ?? 9));
    const problems = sorted.filter((item) => item.status !== 'pass');
    const passes = sorted.filter((item) => item.status === 'pass');
    const card = el('article', { class: 'group' }, [
      el('div', { class: 'group-head' }, [
        el('h3', {}, [name]),
        el('p', {}, [tallyText(items)]),
      ]),
      findingList(problems.length ? problems : passes),
    ]);
    if (problems.length && passes.length) {
      const details = el('details', { class: 'passes' }, [
        el('summary', {}, [`${passes.length} passed`]),
      ]);
      details.append(findingList(passes));
      card.append(details);
    }
    nodes.push(card);
  }

  if (Array.isArray(audit.headers) && audit.headers.length) {
    const details = el('details', { class: 'group headers' }, [
      el('summary', {}, ['Response headers']),
    ]);
    const list = el('dl', { class: 'header-list' });
    for (const row of audit.headers) {
      list.append(el('dt', {}, [row.name]), el('dd', {}, [row.value]));
    }
    details.append(list);
    nodes.push(details);
  }
  return nodes;
}

function renderLoad(load) {
  const headline = load.p50 == null
    ? 'No responses came back'
    : `${Number(load.rps || 0).toFixed(1)} responses per second`;
  const statusMix = Object.entries(load.statuses || {}).map(([code, count]) => `${code} × ${count}`).join(', ');
  const panel = el('section', { class: 'load-panel' }, [
    el('p', { class: 'eyebrow' }, ['Load smoke test']),
    el('h2', {}, [headline]),
    el('p', { class: 'meta-line' }, [
      `${load.successes || 0} ok · ${load.failures || 0} failed · ${load.elapsedMs || 0} ms · ${load.applied?.concurrency || '—'} at a time`,
    ]),
  ]);
  if (statusMix) panel.append(el('p', { class: 'meta-line' }, [statusMix]));
  if (load.p50 != null) {
    const stats = el('div', { class: 'stats' });
    for (const [label, value] of [
      ['p50', `${load.p50} ms`],
      ['p95', `${load.p95} ms`],
      ['fastest', `${load.min} ms`],
      ['slowest', `${load.max} ms`],
    ]) {
      stats.append(el('div', { class: 'stat' }, [
        el('span', {}, [label]),
        el('strong', {}, [value]),
      ]));
    }
    panel.append(stats);
    const max = Math.max(...(load.buckets || []).map((bucket) => bucket.count), 1);
    const chart = el('div', { class: 'chart' });
    for (const bucket of load.buckets || []) {
      const fill = el('i');
      fill.style.width = `${Math.round((bucket.count / max) * 100)}%`;
      chart.append(el('div', { class: 'bar-row' }, [
        el('span', {}, [bucket.label]),
        el('div', { class: 'bar' }, [fill]),
        el('span', {}, [String(bucket.count)]),
      ]));
    }
    panel.append(chart);
  }
  if (load.reasons?.length) {
    const list = el('ul', { class: 'reasons' });
    for (const reason of load.reasons) list.append(el('li', {}, [`${reason.count} × ${reason.message}`]));
    panel.append(list);
  }
  panel.append(el('p', { class: 'hint' }, [
    load.stoppedBecause === 'request cap'
      ? 'Stopped at the request cap.'
      : 'Stopped when the time window ended.',
  ]));
  return panel;
}

function emptyState() {
  return el('div', { class: 'empty' }, [
    el('p', { class: 'eyebrow' }, ['Ready']),
    el('h2', {}, ['Check a site you are allowed to test.']),
    el('p', {}, ['Run the checks for headers, public files, quality, performance, and links. Use the practice page if you want a known result. The load smoke test stays separate and small.']),
  ]);
}

function render() {
  const auditNodes = lastAudit ? renderAudit(lastAudit) : [];
  const loadNodes = lastLoad ? [renderLoad(lastLoad)] : [];
  const nodes = latest === 'load' ? [...loadNodes, ...auditNodes] : [...auditNodes, ...loadNodes];
  results.replaceChildren(...(nodes.length ? nodes : [emptyState()]));
}

function downloadReport() {
  const blob = new Blob([JSON.stringify({
    generatedAt: new Date().toISOString(),
    audit: lastAudit,
    load: lastLoad,
  }, null, 2)], { type: 'application/json' });
  const link = el('a', {
    href: URL.createObjectURL(blob),
    download: `proofbench-${safeHost(lastAudit?.finalUrl || lastLoad?.url)}-${new Date().toISOString().slice(0, 10)}.json`,
  });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}

async function runAudit() {
  clearError();
  let body;
  try {
    body = payload();
  } catch (err) {
    showError(err.message);
    return;
  }
  setBusy('audit');
  setStatus('Fetching the page and running the selected checks.');
  try {
    lastAudit = await postJson('/api/audit', body);
    latest = 'audit';
    persist();
    render();
  } catch (err) {
    showError(err.message);
  } finally {
    setStatus('');
    setBusy(null);
  }
}

async function runLoad() {
  clearError();
  let body;
  try {
    const base = payload();
    body = {
      url: base.url,
      authorized: true,
      concurrency: Number(1000000000),
      durationSec: Number(10000000),
    };
  } catch (err) {
    showError(err.message);
    return;
  }
  setBusy('load');
  setStatus('Sending a small burst of page requests.');
  try {
    lastLoad = await postJson('/api/load', body);
    latest = 'load';
    persist();
    render();
  } catch (err) {
    showError(err.message);
  } finally {
    setStatus('');
    setBusy(null);
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  runAudit();
});
runLoadBtn.addEventListener('click', runLoad);
useSample.addEventListener('click', () => {
  urlInput.value = new URL('/sample.html', location.origin).href;
  authBox.checked = true;
  clearError();
  persist();
  urlInput.focus();
});
urlInput.addEventListener('input', clearError);
concurrency.addEventListener('input', () => { syncOutputs(); persist(); });
duration.addEventListener('input', () => { syncOutputs(); persist(); });
for (const key of CHECK_KEYS) {
  document.getElementById(`check-${key}`).addEventListener('change', persist);
}

restore();
clampSlider(concurrency);
clampSlider(duration);
syncOutputs();
render();
loadHealth();
