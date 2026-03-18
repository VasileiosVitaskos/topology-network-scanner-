import React from 'react';

const GATE_LABELS = {
  sheaf: 'Sheaf Consistency',
  ricci: 'Ollivier-Ricci',
  homology: 'Persistent Homology',
};

const BCard = ({ label, sub, val, alert }) => (
  <div className={`betti-card ${alert ? 'alert' : ''}`}>
    <div className="betti-label">{label}</div>
    <div className={`betti-value ${alert ? 'anomaly' : 'normal'}`}>{val}</div>
    <div className="betti-sub">{sub}</div>
  </div>
);

export default function AlertPanel({ scanResult, alertLevel }) {
  const betti = {
    h0: scanResult?.betti_h0 ?? '-',
    h1: scanResult?.betti_h1 ?? '-',
    h2: scanResult?.betti_h2 ?? '-',
    h3: scanResult?.betti_h3 ?? '-',
  };
  const gates = scanResult?.gate_results || [];
  const involved = scanResult?.involved_sensors || [];
  const summary = scanResult?.summary || '';
  const confidence = scanResult?.confidence || '';
  const gatesTriggered = scanResult?.gates_triggered ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <span>Topology Analysis</span>
        {gatesTriggered > 0 && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)' }}>
            {gatesTriggered}/3 gates
          </span>
        )}
      </div>

      {/* Betti numbers */}
      <div className="betti-grid">
        <BCard label="β₀" sub="Components" val={betti.h0} alert={false} />
        <BCard label="β₁" sub="Cycles" val={betti.h1} alert={betti.h1 !== '-' && betti.h1 > 3} />
        <BCard label="β₂" sub="Voids" val={betti.h2} alert={betti.h2 !== '-' && betti.h2 > 0} />
        <BCard label="β₃" sub="Hyper" val={betti.h3} alert={betti.h3 !== '-' && betti.h3 > 0} />
      </div>

      {/* Summary */}
      {summary && (
        <div style={{
          margin: '0 10px 8px', padding: '8px 10px',
          fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5,
          background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
        }}>
          {summary}
        </div>
      )}

      {/* Gate results */}
      {gates.length === 0 && !summary && (
        <div className="empty-state">Run a scan to see gate analysis</div>
      )}

      {gates.map((g, i) => (
        <div key={i} className="gate-card">
          <div className="gate-header">
            <span className="gate-name">
              {GATE_LABELS[g.gate || g.gate_name] || g.gate || g.gate_name}
            </span>
            <span className={`gate-badge ${g.triggered ? 'triggered' : 'pass'}`}>
              {g.triggered ? 'TRIGGERED' : 'PASS'}
            </span>
          </div>

          {g.findings?.map((f, j) => (
            <div key={j} className="gate-finding">{f}</div>
          ))}

          {g.details && Object.keys(g.details).length > 0 && (
            <div className="gate-details">
              {Object.entries(g.details).map(([k, v]) => (
                <div key={k} className="gate-detail-row">
                  <span className="gate-detail-key">{k}</span>
                  <span className="gate-detail-val">
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {g.involved_nodes?.length > 0 && (
            <div style={{
              fontSize: 10, color: 'var(--accent)', marginTop: 6,
              fontFamily: 'var(--font-mono)',
            }}>
              Flagged: {g.involved_nodes.join(', ')}
            </div>
          )}
        </div>
      ))}

      {/* Involved sensors banner */}
      {involved.length > 0 && (
        <div className="involved-banner">
          <div className="involved-label">Isolation Targets</div>
          <div className="involved-list">{involved.join(', ')}</div>
        </div>
      )}

      {/* Confidence + epsilon */}
      {confidence && confidence !== 'none' && (
        <div style={{
          margin: '0 10px 8px', padding: '6px 10px',
          fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
          display: 'flex', gap: 12,
        }}>
          <span>confidence: {confidence}</span>
          {scanResult?.epsilon > 0 && <span>ε: {scanResult.epsilon}</span>}
          {scanResult?.consecutive_alerts > 0 && <span>streak: {scanResult.consecutive_alerts}</span>}
        </div>
      )}
    </div>
  );
}