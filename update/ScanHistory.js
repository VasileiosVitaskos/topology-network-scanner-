import React from 'react';

const statusColors = { CLEAN: '#22c55e', MID_ALERT: '#f59e0b', HIGH_ALERT: '#ef4444', UNKNOWN: '#71717a' };

export default function ScanHistory({ scans, onSelect, onExport, selectedId }) {
  return (
    <>
      <div className="panel-header">
        <span>Scan History</span>
        <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}>{scans.length}</span>
      </div>
      <div className="history-list">
        {scans.length === 0 && <div className="empty-state">No scans yet</div>}
        {scans.map(s => (
          <div
            key={s.id}
            className={`history-item ${selectedId === s.id ? 'selected' : ''}`}
            onClick={() => onSelect(s)}
          >
            <div className="status-dot" style={{ backgroundColor: statusColors[s.status] || '#71717a' }} />
            <div className="history-info">
              <div className="history-top">
                <span className="history-id">#{s.id}</span>
                <span className="history-status" style={{ color: statusColors[s.status] }}>{s.status}</span>
              </div>
              <div className="history-bottom">
                <span className="history-time">{new Date(s.timestamp * 1000).toLocaleTimeString()}</span>
                <span className="history-betti">H₂={s.betti_h2}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="history-footer">
        <button className="export-btn" onClick={onExport}>Export CSV</button>
      </div>
    </>
  );
}
