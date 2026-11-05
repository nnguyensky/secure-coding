import { useCallback, useEffect, useMemo, useState, useTransition } from 'react';
import { SEVERITIES, readEmbedded, takeToken, fetchSnapshot, requestScan, stats, sections, trend, relTime } from './data.js';
import { TiltCard } from './effects.jsx';
import Posture from './Posture.jsx';
import Skyline from './Skyline.jsx';
import Trend from './Trend.jsx';
import Explorer from './Explorer.jsx';
import Drawer from './Drawer.jsx';
import Deps from './Deps.jsx';

const SEV_COPY = {
  critical: 'Exploitable as written',
  high: 'Serious, fix this change',
  medium: 'Weakens a defence',
  low: 'Hygiene',
};

function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('sc-theme') || 'auto'; } catch { return 'auto'; }
  });
  useEffect(() => {
    const el = document.documentElement;
    if (theme === 'auto') el.removeAttribute('data-theme'); else el.setAttribute('data-theme', theme);
    try { localStorage.setItem('sc-theme', theme); } catch { /* storage blocked */ }
  }, [theme]);
  return [theme, () => setTheme(t => (t === 'auto' ? 'light' : t === 'light' ? 'dark' : 'auto'))];
}

export default function App() {
  const embedded = useMemo(readEmbedded, []);
  const [token] = useState(() => (embedded ? null : takeToken()));
  const [snap, setSnap] = useState(embedded);
  const [error, setError] = useState(null);
  const [section, setSection] = useState(null);
  const [selected, setSelected] = useState(null);
  const [scanning, startScan] = useTransition();
  const [theme, cycleTheme] = useTheme();
  const live = !embedded && Boolean(token);

  const load = useCallback(async () => {
    if (!live) return;
    try { setSnap(await fetchSnapshot(token)); setError(null); } catch (e) { setError(e.message); }
  }, [live, token]);

  // Live: read now, then every 5 s while the tab is visible, so a scan run
  // by the hook or a commit shows up without touching the page.
  useEffect(() => {
    if (!live) return undefined;
    load();
    const id = setInterval(() => { if (document.visibilityState === 'visible') load(); }, 5000);
    return () => clearInterval(id);
  }, [live, load]);

  const rescan = () => startScan(async () => {
    try { await requestScan(token); await load(); } catch (e) { setError(e.message); }
  });

  const findings = snap?.findings || [];
  const s = useMemo(() => stats(findings), [findings]);
  const secs = useMemo(() => sections(findings), [findings]);
  const series = useMemo(() => trend(findings), [findings]);
  const sectionNames = useMemo(() => Object.fromEntries(findings.map(f => [f.section, f.sectionName])), [findings]);
  const fixFor = selected && snap?.fixes ? snap.fixes[selected.id] : null;

  if (!snap) {
    return (
      <main className="boot">
        <title>secure-coding</title>
        <div className="boot-cube" aria-hidden="true"><span /><span /><span /><span /><span /><span /></div>
        {error ? <p className="error">{error}</p> : live ? <p className="muted">Loading findings…</p> : (
          <div className="boot-help">
            <h1>secure-coding dashboard</h1>
            <p className="muted">Open it with <code>node hooks/serve.js</code> for live results, or <code>node hooks/report.js --dashboard</code> for a single offline file.</p>
          </div>
        )}
      </main>
    );
  }

  return (
    <>
      <title>{s.open ? `(${s.open}) secure-coding — ${snap.project}` : `secure-coding — ${snap.project}`}</title>
      <div className="bg-orbs" aria-hidden="true"><span /><span /><span /></div>
      <header className="topbar">
        <div className="brand">
          <div className="logo" aria-hidden="true"><span /><span /><span /></div>
          <div>
            <div className="brand-name">secure-coding</div>
            <div className="brand-sub">{snap.project} · v{snap.tool?.version}</div>
          </div>
        </div>
        <div className="top-actions">
          <span className={`live-pill${live ? ' on' : ''}`}>
            <i aria-hidden="true" />{live ? 'Live' : 'Snapshot'} · {relTime(live ? (snap.server?.lastScan?.at || snap.generatedAt) : snap.generatedAt)}
          </span>
          <button type="button" className="btn ghost" onClick={cycleTheme} aria-label={`Theme: ${theme}`} title={`Theme: ${theme}`}>
            {theme === 'light' ? (
              <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
            ) : theme === 'dark' ? (
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>
            ) : (
              <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" /></svg>
            )}
          </button>
          {live && (
            <button type="button" className="btn primary" onClick={rescan} disabled={scanning || snap.server?.scanning}>
              {scanning || snap.server?.scanning ? <><span className="spinner" aria-hidden="true" />Scanning…</> : 'Rescan project'}
            </button>
          )}
        </div>
      </header>

      {error && <div className="toast" role="alert">{error}<button type="button" onClick={() => setError(null)} aria-label="Dismiss">×</button></div>}

      <main className="layout">
        <section className="hero">
          <Posture s={s} />
          <div className="kpis">
            {SEVERITIES.map((sev, i) => (
              <TiltCard key={sev} className={`card kpi sev-${sev}`} style={{ '--i': i }}>
                <div className="kpi-top"><span className={`dot sev-${sev}`} />{sev}</div>
                <div className="kpi-n">{s.bySev[sev]}</div>
                <div className="kpi-sub muted">{SEV_COPY[sev]}</div>
                <div className="kpi-depth" aria-hidden="true">{s.bySev[sev]}</div>
              </TiltCard>
            ))}
            <TiltCard className="card kpi kpi-wide" style={{ '--i': 4 }}>
              <div className="kpi-split">
                <div><div className="kpi-n small ok-text">{s.fixed}</div><div className="muted small">fixed</div></div>
                <div><div className="kpi-n small">{s.suppressed}</div><div className="muted small">suppressed</div></div>
                <div><div className="kpi-n small">{s.baselined}</div><div className="muted small">baselined</div></div>
                <div><div className="kpi-n small">{snap.audit?.findings?.length || 0}</div><div className="muted small">dep advisories</div></div>
              </div>
            </TiltCard>
          </div>
        </section>

        <section className="grid-2">
          <div className="card skyline-card">
            <div className="card-head">
              <h2>Risk skyline</h2>
              <span className="muted small">open findings by section · drag to turn · click a tower to filter</span>
            </div>
            <Skyline data={secs} active={section} onPick={setSection} />
          </div>
          <div className="stack">
            <div className="card">
              <div className="card-head"><h2>Over time</h2></div>
              <Trend series={series} />
            </div>
            <Deps audit={snap.audit || {}} />
          </div>
        </section>

        <Explorer findings={findings} section={section} onSection={setSection} onOpen={setSelected} sectionNames={sectionNames} />

        <footer className="foot muted small">
          secure-coding v{snap.tool?.version} · {findings.length} records · generated {new Date(snap.generatedAt).toLocaleString()}
          {live ? ' · local only, token-protected' : ' · offline snapshot'}
        </footer>
      </main>

      <Drawer finding={selected} fix={fixFor} onClose={() => setSelected(null)} />
    </>
  );
}
