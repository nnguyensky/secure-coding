import { TiltCard } from './effects.jsx';

// The overall score as a 3D gyroscope: three rings turning on different axes
// around the number. The colour follows the score.
export default function Posture({ s }) {
  const tone = s.score >= 90 ? 'good' : s.score >= 75 ? 'ok' : s.score >= 50 ? 'warn' : 'bad';
  return (
    <TiltCard className={`card posture tone-${tone}`} max={6}>
      <div className="posture-stage" aria-hidden="true">
        <div className="gyro">
          <span className="ring r1" />
          <span className="ring r2" />
          <span className="ring r3" />
          <span className="core" />
        </div>
      </div>
      <div className="posture-text">
        <div className="eyebrow">Security posture</div>
        <div className="score" aria-label={`Score ${s.score} out of 100`}>{s.score}<small>/100</small></div>
        <div className={`chip chip-${tone}`}>{s.label}</div>
        <p className="muted">
          {s.open === 0
            ? 'No open findings. Keep it that way: the hook checks every file as it is written.'
            : `${s.open} open finding${s.open === 1 ? '' : 's'} across ${s.files} file${s.files === 1 ? '' : 's'}. Critical issues weigh most.`}
        </p>
      </div>
    </TiltCard>
  );
}
