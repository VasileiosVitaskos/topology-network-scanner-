import React, { useState } from 'react';

export default function ScanResultPanel({ result }) {
  const [showGates, setShowGates] = useState(false);

  if (!result) return null;

  const findings = result.findings || [];
  const health = result.network_health || {};
  const recommendations = result.recommendations || [];
  const gateResults = result.gate_results || [];
  const isDeep = result.scan_type === 'deep';
  const status = (result.status || 'CLEAN').toLowerCase();

  return (
    <div>
      {/* ── Health Bar ── */}
      {health.total_events > 0 && (
        <div className="health-bar">
          <div className="health-stat">
            <div className="health-value">{health.total_events || 0}</div>
            <div className="health-label">Events</div>
          </div>
          <div className="health-stat">
            <div className="health-value" style={{ color: health.denied_events > 5 ? '#ff1744' : undefined }}>
              {health.denied_events || 0}
            </div>
            <div className="health-label">Denied</div>
          </div>
          <div className="health-stat">
            <div className="health-value" style={{ color: health.cross_segment_events > 0 ? '#ffab00' : undefined }}>
              {health.cross_segment_events || 0}
            </div>
            <div className="health-label">Cross-seg</div>
          </div>
          <div className="health-stat">
            <div className="health-value">{health.active_hosts || 0}</div>
            <div className="health-label">Hosts</div>
          </div>
          <div className="health-stat">
            <div className="health-value">{(health.protocols_seen || []).length}</div>
            <div className="health-label">Protocols</div>
          </div>
        </div>
      )}

      {/* ── AI Summary ── */}
      {result.summary && (
        <div className="result-summary">
          <strong style={{ color: statusColor(status), marginRight: 8 }}>
            {statusIcon(status)}
          </strong>
          {result.summary}
        </div>
      )}

      {/* ── Findings ── */}
      {findings.length > 0 && (
        <div className="findings-list">
          {findings.map((f, i) => (
            <div key={i} className={`finding-card ${f.severity || 'info'}`}>
              <div className="finding-title">
                {severityIcon(f.severity)} {f.title}
              </div>
              <div className="finding-detail">{f.detail}</div>
              {f.involved_ips && f.involved_ips.length > 0 && (
                <div className="finding-ips">
                  {f.involved_ips.map((ip, j) => (
                    <span key={j} className="ip-tag">{ip}</span>
                  ))}
                </div>
              )}
              {f.evidence && (
                <div style={{ fontSize: 10, color: '#5f6368', marginTop: 4, fontStyle: 'italic' }}>
                  {f.evidence}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Deep Scan: Gate Results (collapsible) ── */}
      {isDeep && gateResults.length > 0 && (
        <div className="gates-section">
          <div
            className="gates-title"
            onClick={() => setShowGates(!showGates)}
            style={{ cursor: 'pointer' }}
          >
            ◈ Topological Analysis (3-Gate Engine)
            <span style={{ fontSize: 10, color: '#80868b', fontWeight: 400 }}>
              {showGates ? '▼' : '▶'} {gateResults.filter(g => g.triggered).length}/3 gates triggered
            </span>
          </div>

          {showGates && gateResults.map((g, i) => (
            <div key={i} className="gate-card">
              <div className="gate-header">
                <span className="gate-name">
                  Gate {i + 1}: {gateLabel(g.gate || g.gate_name)}
                </span>
                <span className={`gate-badge ${g.triggered ? 'triggered' : 'pass'}`}>
                  {g.triggered ? '⚠ TRIGGERED' : '✓ PASS'}
                </span>
              </div>

              <div className="gate-findings">
                {(g.findings || []).map((f, j) => (
                  <div key={j} style={{ marginBottom: 2 }}>• {f}</div>
                ))}
              </div>

              {g.involved_nodes && g.involved_nodes.length > 0 && (
                <div className="finding-ips" style={{ marginTop: 6 }}>
                  {g.involved_nodes.map((n, j) => (
                    <span key={j} className="ip-tag">{n}</span>
                  ))}
                </div>
              )}

              {g.details && Object.keys(g.details).length > 0 && (
                <div className="gate-details">
                  {Object.entries(g.details).map(([k, v]) => (
                    <div key={k} className="gate-detail-row">
                      <span>{k}</span>
                      <span className="gate-detail-val">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}

          {/* Betti summary for deep scan */}
          {showGates && (result.betti_h0 !== undefined) && (
            <div style={{
              display: 'flex', gap: 12, padding: '8px 0', fontSize: 11, color: '#80868b'
            }}>
              <span>β₀={result.betti_h0}</span>
              <span>β₁={result.betti_h1}</span>
              <span style={{ color: result.betti_h2 > 0 ? '#ff1744' : undefined }}>
                β₂={result.betti_h2}
              </span>
              <span style={{ color: result.betti_h3 > 0 ? '#ff1744' : undefined }}>
                β₃={result.betti_h3}
              </span>
              <span>ε={result.epsilon || 0}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Recommendations ── */}
      {recommendations.length > 0 && (
        <div className="recommendations">
          {recommendations.map((r, i) => (
            <div key={i} className="rec-item">{r}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function statusColor(s) {
  if (s.includes('critical') || s.includes('high')) return '#ff1744';
  if (s.includes('suspicious') || s.includes('mid')) return '#ffab00';
  return '#00e676';
}

function statusIcon(s) {
  if (s.includes('critical') || s.includes('high')) return '🔴';
  if (s.includes('suspicious') || s.includes('mid')) return '🟡';
  return '🟢';
}

function severityIcon(s) {
  if (s === 'critical') return '🔴';
  if (s === 'warning') return '🟡';
  return '🔵';
}

function gateLabel(name) {
  if (name === 'sheaf') return 'Sheaf Laplacian';
  if (name === 'ricci') return 'Ollivier-Ricci';
  if (name === 'homology') return 'Persistent Homology';
  return name;
}
