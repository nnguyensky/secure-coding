import { useEffect, useRef } from 'react';

// Details of one finding, with its remediation block, in a side panel that
// swings in from the edge. Esc or the backdrop closes it; focus moves in and
// goes back to where it came from.
export default function Drawer({ finding, fix, onClose }) {
  const panel = useRef(null);
  useEffect(() => {
    if (!finding) return undefined;
    const prev = document.activeElement;
    panel.current?.focus();
    const onKey = e => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); prev?.focus?.(); };
  }, [finding, onClose]);

  if (!finding) return null;
  const f = finding;
  const snippet = f.note.replace(/^Line \d+:\s*/, '');
  return (
    <div className="drawer-layer" role="presentation">
      <button type="button" className="drawer-backdrop" aria-label="Close details" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-h" tabIndex={-1} ref={panel}>
        <header className="drawer-head">
          <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
          <h3 id="drawer-h">{f.id}</h3>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">×</button>
        </header>
        <div className="drawer-body">
          <div className="loc"><span className="muted">at</span> <code>{f.file}{f.line ? `:${f.line}` : ''}</code></div>
          {snippet && <pre className="code code-hit"><code>{snippet}</code></pre>}
          {f.status === 'suppressed' && <p className="note-box">Suppressed inline — reason: <em>{f.reason || 'none given'}</em></p>}
          {f.status === 'baselined' && <p className="note-box">In the baseline: it existed before the scanner was adopted and does not block. It still needs fixing.</p>}

          {fix ? (
            <>
              {fix.summary && <p className="lead">{fix.summary}</p>}
              <div className="flip-pair">
                {fix.wrong && <div className="flip wrong"><div className="flip-label">Wrong</div><pre className="code"><code>{fix.wrong}</code></pre></div>}
                {fix.right && <div className="flip right"><div className="flip-label">Right</div><pre className="code"><code>{fix.right}</code></pre></div>}
              </div>
              {fix.watch && <p className="watch"><strong>Watch:</strong> {fix.watch}</p>}
              <dl className="meta">
                {fix.cwe && <><dt>CWE</dt><dd><a href={`https://cwe.mitre.org/data/definitions/${fix.cwe}.html`} target="_blank" rel="noreferrer noopener">CWE-{fix.cwe}</a></dd></>}
                {fix.category && <><dt>OWASP Top 10</dt><dd>{fix.category}</dd></>}
                <dt>Section</dt><dd>{f.sectionName}</dd>
                <dt>First seen</dt><dd>{f.firstSeen ? new Date(f.firstSeen).toLocaleString() : '—'}</dd>
                {f.resolvedAt && <><dt>Fixed</dt><dd>{new Date(f.resolvedAt).toLocaleString()}</dd></>}
              </dl>
            </>
          ) : <p className="muted">No remediation block for this rule.</p>}
          <p className="muted small">Ask your agent: <code>fix the {f.id} finding in {f.file}</code> — or run <code>node hooks/fix.js --dry-run</code>.</p>
        </div>
      </aside>
    </div>
  );
}
