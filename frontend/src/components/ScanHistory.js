import React from 'react';

export default function ScanHistory({ scans, onSelect, onExport, selectedId }) {
  return (
    <>
      <div className="panel-header">
        <span>History</span>
        <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}>{scans.length}</span>
      </div>
      <div className="history-list">
        {scans.length === 0 && <div className="empty-state">No scans yet</div>}
        {scans.map(s => {
          const isAlert = s.status && s.status !== 'CLEAN';
          return (
            <div
              key={s.id}
              className={`history-item ${selectedId === s.id ? 'selected' : ''}`}
              onClick={() => onSelect(s)}
            >
              <div
                className={`status-dot ${isAlert ? 'alert' : ''}`}
                style={isAlert ? { background: 'var(--accent)' } : undefined}
              />
              <div className="history-info">
                <div className="history-top">
                  <span className="history-id">#{s.id}</span>
                  <span
                    className="history-status"
                    style={isAlert ? { color: 'var(--accent)' } : undefined}
                  >
                    {s.status}
                  </span>
                </div>
                <div className="history-bottom">
                  <span className="history-time">
                    {new Date(s.timestamp * 1000).toLocaleTimeString()}
                  </span>
                  <span className="history-betti">
                    {s.gates_triggered > 0 ? `${s.gates_triggered}/3` : ''}
                    {s.betti_h2 > 0 ? ` β₂=${s.betti_h2}` : ''}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="history-footer">
        <button className="export-btn" onClick={onExport}>Export CSV</button>
      </div>
    </>
  );
}