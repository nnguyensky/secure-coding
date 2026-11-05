import { useDeferredValue, useMemo, useState } from 'react';
import { SEVERITIES, SEV_RANK, STATUSES } from './data.js';

const STATUS_LABEL = { open: 'Open', fixed: 'Fixed', suppressed: 'Suppressed', baselined: 'Baselined' };

export default function Explorer({ findings, section, onSection, onOpen, sectionNames }) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('open');
  const [sevs, setSevs] = useState(() => new Set(SEVERITIES));
  const q = useDeferredValue(query.trim().toLowerCase());

  const counts = useMemo(() => Object.fromEntries(STATUSES.map(s => [s, findings.filter(f => f.status === s).length])), [findings]);

  const groups = useMemo(() => {
    const rows = findings.filter(f =>
      (status === 'all' || f.status === status)
      && sevs.has(f.severity)
      && (!section || f.section === section)
      && (!q || `${f.id} ${f.file} ${f.note} ${f.sectionName}`.toLowerCase().includes(q)));
    const byFile = new Map();
    for (const f of rows) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    return [...byFile.entries()]
      .map(([file, list]) => ({ file, list: list.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.line - b.line) }))
      .sort((a, b) => SEV_RANK[a.list[0].severity] - SEV_RANK[b.list[0].severity] || b.list.length - a.list.length);
  }, [findings, status, sevs, section, q]);

  const total = groups.reduce((n, g) => n + g.list.length, 0);
  const toggleSev = s => setSevs(prev => {
    const next = new Set(prev);
    if (next.has(s) && next.size > 1) next.delete(s); else next.add(s);
    return next;
  });

  return (
    <section className="card explorer" aria-labelledby="explorer-h">
      <header className="explorer-head">
        <h2 id="explorer-h">Findings</h2>
        <div className="search">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
          <input type="search" placeholder="Search rule, file or code…" value={query} onChange={e => setQuery(e.target.value)} aria-label="Search findings" />
        </div>
      </header>

      <div className="filters">
        <div className="segmented" role="tablist" aria-label="Status">
          {[...STATUSES, 'all'].map(s => (
            <button key={s} type="button" role="tab" aria-selected={status === s} className={status === s ? 'on' : ''} onClick={() => setStatus(s)}>
              {s === 'all' ? 'All' : STATUS_LABEL[s]} <span className="n">{s === 'all' ? findings.length : counts[s]}</span>
            </button>
          ))}
        </div>
        <div className="sev-toggles" aria-label="Severity">
          {SEVERITIES.map(s => (
            <button key={s} type="button" aria-pressed={sevs.has(s)} className={`sev-toggle sev-${s}${sevs.has(s) ? ' on' : ''}`} onClick={() => toggleSev(s)}>{s}</button>
          ))}
        </div>
        {section && (
          <button type="button" className="chip chip-filter" onClick={() => onSection(null)} aria-label="Clear section filter">
            {sectionNames[section] || section} <span aria-hidden="true">×</span>
          </button>
        )}
      </div>

      <div className="results-meta muted small" aria-live="polite">{total} finding{total === 1 ? '' : 's'} in {groups.length} file{groups.length === 1 ? '' : 's'}</div>

      {groups.length === 0 ? (
        <div className="empty">
          <div className="empty-icon" aria-hidden="true">✓</div>
          <p>{status === 'open' && !q && !section ? 'Nothing open. Clean.' : 'No findings match these filters.'}</p>
        </div>
      ) : (
        <ul className="file-groups">
          {groups.map((g, gi) => (
            <li key={g.file} className="file-group" style={{ '--i': Math.min(gi, 12) }}>
              <details open={gi < 6}>
                <summary>
                  <span className="file-name" title={g.file}>{g.file || '(unknown file)'}</span>
                  <span className="file-sevs">{SEVERITIES.map(s => {
                    const n = g.list.filter(f => f.severity === s).length;
                    return n ? <span key={s} className={`mini sev-${s}`}>{n}</span> : null;
                  })}</span>
                </summary>
                <ul className="rows">
                  {g.list.map((f, i) => (
                    <li key={`${f.id}@${f.line}@${i}`}>
                      <button type="button" className="row" onClick={() => onOpen(f)}>
                        <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                        <span className="row-id">{f.id}</span>
                        <span className="row-line">:{f.line || '?'}</span>
                        <span className="row-note">{f.note.replace(/^Line \d+:\s*/, '')}</span>
                        {f.status !== 'open' && <span className={`status-pill st-${f.status}`}>{STATUS_LABEL[f.status] || f.status}</span>}
                      </button>
                    </li>
                  ))}
                </ul>
              </details>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
