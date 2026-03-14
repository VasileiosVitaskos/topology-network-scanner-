import React from 'react';

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">Topology Analysis</div>

      <div className="betti-grid">
        <BCard label="β₀" sub="Components" val={betti.h0} alert={false} />
        <BCard label="β₁" sub="Cycles" val={betti.h1} alert={betti.h1 > 3} />
        <BCard label="β₂" sub="Voids" val={betti.h2} alert={betti.h2 > 0} />
        <BCard label="β₃" sub="Hyper" val={betti.h3} alert={betti.h3 > 0} />
      </div>

      {gates.length === 0 && (
        <div className="empty-state">Run a scan to see gate analysis</div>
      )}

      {gates.map((g, i) => (
        <div key={i} className="gate-card">
          <div className="gate-header">
            <span className="gate-name">Gate {i + 1}: {g.gate || g.gate_name}</span>
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
            <div style={{ fontSize: '11px', color: '#f87171', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
              Flagged: {g.involved_nodes.join(', ')}
            </div>
          )}
        </div>
      ))}

      {involved.length > 0 && (
        <div className="involved-banner">
          <div className="involved-label">Threat Isolation Targets</div>
          <div className="involved-list">{involved.join(', ')}</div>
        </div>
      )}
    </div>
  );
}
