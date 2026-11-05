// Open findings over time, with what was found and fixed each day.
export default function Trend({ series }) {
  if (series.length < 2) {
    return <p className="muted small">The trend appears after scans on two different days.</p>;
  }
  const W = 640, H = 170, P = 8;
  const max = Math.max(1, ...series.map(p => Math.max(p.open, p.found, p.fixed)));
  const step = (W - P * 2) / (series.length - 1);
  const x = i => P + i * step;
  const y = v => H - P - (v / max) * (H - P * 2 - 14);
  const line = series.map((p, i) => `${x(i)},${y(p.open)}`).join(' ');
  const area = `${x(0)},${H - P} ${line} ${x(series.length - 1)},${H - P}`;
  const bw = Math.max(2, Math.min(10, step / 4));
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Open findings per day">
        <defs>
          <linearGradient id="tr-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0.35" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {series.map((p, i) => (
          <g key={p.day}>
            <rect x={x(i) - bw - 1} y={y(p.found)} width={bw} height={H - P - y(p.found)} className="bar-found"><title>{`${p.day}: ${p.found} found`}</title></rect>
            <rect x={x(i) + 1} y={y(p.fixed)} width={bw} height={H - P - y(p.fixed)} className="bar-fixed"><title>{`${p.day}: ${p.fixed} fixed`}</title></rect>
          </g>
        ))}
        <polygon points={area} fill="url(#tr-fill)" />
        <polyline points={line} className="line-open" />
        {series.map((p, i) => <circle key={p.day} cx={x(i)} cy={y(p.open)} r="3.5" className="pt-open"><title>{`${p.day}: ${p.open} open`}</title></circle>)}
      </svg>
      <figcaption className="legend-row">
        <span><i className="dot accent" />Open</span>
        <span><i className="dot sev-critical" />Found</span>
        <span><i className="dot ok" />Fixed</span>
        <span className="muted">{series[0].day} → {series[series.length - 1].day}</span>
      </figcaption>
    </figure>
  );
}
