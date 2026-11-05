import { useEffect, useRef, useState } from 'react';
import { useReducedMotion } from './effects.jsx';

const TILE = 46;      // footprint of one tower, px
const GAP = 22;
const MAX_H = 170;    // tallest tower, px

// Open findings by OWASP section as a small 3D city: one tower per section,
// height = open findings, colour = worst severity in it. Drag to turn it;
// the arrow keys do the same when it has focus.
export default function Skyline({ data, active, onPick }) {
  const reduced = useReducedMotion();
  const [spin, setSpin] = useState(-38);
  const [tilt, setTilt] = useState(58);
  const drag = useRef(null);
  const touched = useRef(false);

  useEffect(() => {
    if (reduced) return undefined;
    let raf;
    const tick = () => {
      if (!touched.current && !drag.current) setSpin(s => s + 0.06);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [reduced]);

  const towers = data.slice(0, 16);
  const cols = Math.max(2, Math.ceil(Math.sqrt(towers.length)));
  const rows = Math.max(1, Math.ceil(towers.length / cols));
  const max = Math.max(1, ...towers.map(t => t.open));
  const w = cols * TILE + (cols - 1) * GAP;
  const h = rows * TILE + (rows - 1) * GAP;

  const down = e => { drag.current = { x: e.clientX, y: e.clientY, spin, tilt }; touched.current = true; e.currentTarget.setPointerCapture(e.pointerId); };
  const move = e => {
    if (!drag.current) return;
    setSpin(drag.current.spin + (e.clientX - drag.current.x) * 0.4);
    setTilt(Math.min(75, Math.max(35, drag.current.tilt - (e.clientY - drag.current.y) * 0.25)));
  };
  const up = () => { drag.current = null; };
  const key = e => {
    const k = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -5], ArrowDown: [0, 5] }[e.key];
    if (!k) return;
    e.preventDefault();
    touched.current = true;
    setSpin(s => s + k[0]);
    setTilt(t => Math.min(75, Math.max(35, t + k[1])));
  };

  if (towers.length === 0) {
    return <div className="skyline-empty"><div className="flat-grid" aria-hidden="true" /><p>Nothing standing — no open findings.</p></div>;
  }

  return (
    <div className="skyline-wrap">
      <div
        className="skyline"
        role="img"
        tabIndex={0}
        aria-label={`3D chart of open findings by section. ${towers.map(t => `${t.name}: ${t.open}`).join('; ')}`}
        onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} onKeyDown={key}
      >
        <div className="plane" style={{ width: w, height: h, transform: `rotateX(${tilt}deg) rotateZ(${spin}deg)` }}>
          <div className="plane-grid" />
          {towers.map((t, i) => {
            const x = (i % cols) * (TILE + GAP);
            const y = Math.floor(i / cols) * (TILE + GAP);
            const height = Math.max(10, (t.open / max) * MAX_H);
            const dim = active && active !== t.key;
            return (
              <button
                key={t.key}
                type="button"
                className={`tower sev-${t.worst}${dim ? ' dim' : ''}${active === t.key ? ' on' : ''}`}
                style={{ left: x, top: y, width: TILE, height: TILE, '--h': `${height}px`, '--d': `${i * 45}ms` }}
                onClick={() => onPick(active === t.key ? null : t.key)}
                title={`${t.name}: ${t.open} open`}
                aria-label={`${t.name}: ${t.open} open, worst ${t.worst}`}
                tabIndex={-1}
              >
                <span className="face top"><b>{t.open}</b></span>
                <span className="face front" />
                <span className="face back" />
                <span className="face left" />
                <span className="face right" />
              </button>
            );
          })}
        </div>
      </div>
      <ul className="skyline-legend">
        {towers.map(t => (
          <li key={t.key}>
            <button type="button" className={`legend-item${active === t.key ? ' on' : ''}`} onClick={() => onPick(active === t.key ? null : t.key)}>
              <i className={`dot sev-${t.worst}`} />
              <span className="legend-name">{t.name}</span>
              <span className="legend-n">{t.open}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
