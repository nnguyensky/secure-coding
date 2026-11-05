export default function Deps({ audit }) {
  const list = audit.findings || [];
  return (
    <section className="card deps" aria-labelledby="deps-h">
      <h2 id="deps-h">Dependencies</h2>
      {list.length === 0 ? (
        <p className="muted small">
          {audit.ts ? 'No known advisories in the last audit.' : 'No audit yet — run node hooks/audit.js.'}
          {audit.skipped?.length ? ` Not audited: ${audit.skipped.map(s => s.ecosystem).join(', ')}.` : ''}
        </p>
      ) : (
        <ul className="dep-list">
          {list.slice(0, 40).map((d, i) => (
            <li key={`${d.ecosystem}:${d.package}:${i}`} className="dep">
              <span className={`sev-badge sev-${d.severity || 'high'}`}>{d.severity || 'high'}</span>
              <span className="dep-name"><b>{d.package}</b> <span className="muted">{d.installed}</span></span>
              <span className="dep-eco">{d.ecosystem}</span>
              <span className="dep-title muted">{d.title}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
