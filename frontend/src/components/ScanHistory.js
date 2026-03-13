import React from 'react';

export default function ScanHistory({ scans, onSelect, onExport, selectedId }) {
  return (
    <>
      <div className="panel-header">
        <span>Scan History</span>
        <span className="count">{scans.length} scans</span>
      </div>

      <div className="history-list">
        {scans.length === 0 && (
          <div className="history-empty">
            No scans yet.<br />
            Run a Quick Scan or Deep Scan to begin.
          </div>
        )}

        {scans.map(s => {
          const status = (s.status || 'CLEAN').toLowerCase();
          const summary = s.summary || s.pattern || 'Scan completed';
          const scanType = s.scan_type || 'quick';
          const time = s.timestamp
            ? new Date(s.timestamp * 1000).toLocaleTimeString()
            : '';

          return (
            <div
              key={s.id || s.scan_id}
              className={`history-item ${(selectedId === s.id || selectedId === s.scan_id) ? 'selected' : ''}`}
              onClick={() => onSelect(s)}
            >
              <div className={`history-dot ${status}`} />
              <div className="history-info">
                <div className="history-status" style={{ color: statusColor(status) }}>
                  {(s.status || 'CLEAN').replace('_', ' ')}
                </div>
                <div className="history-summary">{summary}</div>
                <div className="history-meta">
                  <span className={`history-type ${scanType}`}>
                    {scanType}
                  </span>
                  <span>{time}</span>
                  {s.logs_analyzed > 0 && (
                    <span>{s.logs_analyzed} events</span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="history-footer">
        <button className="btn btn-ghost" onClick={onExport} style={{ width: '100%', justifyContent: 'center' }}>
          ↓ Export CSV
        </button>
      </div>
    </>
  );
}

function statusColor(status) {
  if (status.includes('critical') || status.includes('high')) return '#ff1744';
  if (status.includes('suspicious') || status.includes('mid')) return '#ffab00';
  return '#00e676';
}
