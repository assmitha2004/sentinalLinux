import { levelText } from '../utils/format.js';

const BANDS = ['Excellent', 'Good', 'Moderate', 'High risk', 'Critical'];

/** Risk score (0 = no exposure, 100 = critical) placed on the configured band scale. */
export default function RiskGauge({ score, level, caption }) {
  if (score == null) {
    return <div className="gauge"><div><div className="gauge-score muted">—</div><div className="gauge-level muted">No scan yet</div></div><p className="gauge-caption">Scores appear after the agent completes its first security scan.</p></div>;
  }
  const band = Math.min(4, Math.floor(Math.max(0, score - 1) / 20));
  return (
    <div className="gauge">
      <div>
        <div className="gauge-score" style={{ color: ['var(--good)', 'var(--sev-low)', 'var(--sev-medium)', 'var(--sev-high)', 'var(--sev-critical)'][band] }}>{score}</div>
        <div className="gauge-level">{levelText(level)}</div>
      </div>
      <div>
        <div className="band" aria-label={`Risk score ${score} of 100, ${levelText(level)}`}>
          <div className="band-pointer" style={{ left: `${score}%` }}>{score}</div>
          <div className="band-track">{BANDS.map((b) => <span key={b} />)}</div>
          <div className="band-labels">{BANDS.map((b, i) => <span key={b} className={i === band ? 'on' : ''}>{b}</span>)}</div>
        </div>
        {caption && <p className="gauge-caption" style={{ marginTop: 10 }}>{caption}</p>}
      </div>
    </div>
  );
}
