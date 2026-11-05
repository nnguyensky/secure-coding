// Where the data comes from, and everything derived from it.
//
// Two modes, one bundle:
//   live      served by hooks/serve.js: the token arrives in the URL fragment
//             and every read goes through the local API.
//   snapshot  written by `report.js --dashboard`: the data is embedded in the
//             page, which then works offline as a single file.

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEV_WEIGHT = { critical: 10, high: 5, medium: 2, low: 1 };
export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
export const STATUSES = ['open', 'fixed', 'suppressed', 'baselined'];

export function readEmbedded() {
  const el = document.getElementById('sc-snapshot');
  const text = el && el.textContent.trim();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

// The token travels in the fragment (never sent to a server, never in a
// Referer). Take it, then clear it from the address bar so it is not left
// in screenshots or copied links. sessionStorage keeps it for a reload of
// this tab only; the server's port, and so this origin, changes every run.
export function takeToken() {
  const m = window.location.hash.match(/token=([A-Za-z0-9_-]+)/);
  if (m) {
    try { sessionStorage.setItem('sc-token', m[1]); } catch { /* storage blocked */ }
    window.history.replaceState(null, '', window.location.pathname);
    return m[1];
  }
  try { return sessionStorage.getItem('sc-token'); } catch { return null; }
}

export async function fetchSnapshot(token) {
  const r = await fetch('/api/snapshot', { headers: { 'x-sc-token': token }, cache: 'no-store' });
  if (!r.ok) throw new Error(r.status === 401 ? 'The dashboard link has expired — open the new one printed by serve.js.' : `Server answered ${r.status}`);
  return r.json();
}

export async function requestScan(token) {
  const r = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'x-sc-token': token, 'content-type': 'application/json' },
    body: '{}',
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `Scan failed (${r.status})`);
  return body;
}

export function stats(findings) {
  const open = findings.filter(f => f.status === 'open');
  const bySev = Object.fromEntries(SEVERITIES.map(s => [s, open.filter(f => f.severity === s).length]));
  const weighted = open.reduce((n, f) => n + (SEV_WEIGHT[f.severity] || 1), 0);
  // 100 with nothing open; each critical costs roughly what five lows do.
  const score = Math.round(100 * Math.exp(-weighted / 60));
  const label = score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 50 ? 'Fair' : 'At risk';
  const count = s => findings.filter(f => f.status === s).length;
  return {
    open: open.length, fixed: count('fixed'), suppressed: count('suppressed'), baselined: count('baselined'),
    bySev, score, label, files: new Set(open.map(f => f.file)).size,
  };
}

export function sections(findings) {
  const map = new Map();
  for (const f of findings) {
    if (f.status !== 'open') continue;
    const key = f.section || '00';
    const s = map.get(key) || { key, name: f.sectionName || 'Other', open: 0, worst: 'low', bySev: { critical: 0, high: 0, medium: 0, low: 0 } };
    s.open++;
    s.bySev[f.severity] = (s.bySev[f.severity] || 0) + 1;
    if (SEV_RANK[f.severity] < SEV_RANK[s.worst]) s.worst = f.severity;
    map.set(key, s);
  }
  return [...map.values()].sort((a, b) => b.open - a.open || SEV_RANK[a.worst] - SEV_RANK[b.worst]);
}

// Per day: found, fixed, and open at the end of the day (last 30 days).
export function trend(findings) {
  const day = s => (s || '').slice(0, 10);
  const days = new Set();
  for (const f of findings) {
    if (f.status !== 'open' && f.status !== 'fixed') continue;
    if (day(f.firstSeen)) days.add(day(f.firstSeen));
    if (day(f.resolvedAt)) days.add(day(f.resolvedAt));
  }
  return [...days].sort().slice(-30).map(d => {
    let found = 0, fixed = 0, open = 0;
    for (const f of findings) {
      if (f.status !== 'open' && f.status !== 'fixed') continue;
      const a = day(f.firstSeen), r = day(f.resolvedAt);
      if (a === d) found++;
      if (r === d) fixed++;
      if (a && a <= d && (!r || r > d)) open++;
    }
    return { day: d, found, fixed, open };
  });
}

export function relTime(iso) {
  if (!iso) return '—';
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (Number.isNaN(s)) return iso;
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}
