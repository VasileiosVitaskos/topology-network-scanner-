import React, { useState } from 'react';

export default function TopologyManager({ pendingNodes, onConfirm, onDeny }) {
  const [expanded, setExpanded] = useState(null);
  const [label, setLabel] = useState('');
  const [segment, setSegment] = useState('unknown');
  const [nodeType, setNodeType] = useState('sensor');

  const segments = ['plc', 'scada', 'workstation', 'dmz', 'unknown'];
  const types = ['sensor', 'plc', 'hmi', 'switch', 'firewall', 'workstation'];

  const toggle = (id) => {
    if (expanded === id) {
      setExpanded(null);
    } else {
      setExpanded(id);
      setLabel(id);
      setSegment('unknown');
      setNodeType('sensor');
    }
  };

  if (pendingNodes.length === 0) return null;

  return (
    <div className="topology-section">
      <div className="panel-header">
        <span>Topology</span>
        <span className="count" style={{ color: '#ffab00' }}>
          {pendingNodes.length} pending
        </span>
      </div>

      {pendingNodes.map(n => (
        <div key={n.node_id} className="pending-node">
          <div className="pending-header" onClick={() => toggle(n.node_id)}>
            <div className="pending-indicator">⚠</div>
            <div className="pending-info">
              <div className="pending-id">{n.node_id}</div>
              <div className="pending-time">
                {new Date(n.first_seen * 1000).toLocaleTimeString()}
              </div>
            </div>
            <button
              className="btn-deny"
              onClick={(e) => { e.stopPropagation(); onDeny(n.node_id); }}
              title="Deny"
            >
              ✕
            </button>
          </div>

          {expanded === n.node_id && (
            <div className="pending-expand">
              <div className="field-row">
                <label>Label</label>
                <input
                  className="field-input"
                  value={label}
                  onChange={e => setLabel(e.target.value)}
                  placeholder="e.g. PLC-Stage3"
                />
              </div>
              <div className="field-row">
                <label>Segment</label>
                <select className="field-input" value={segment} onChange={e => setSegment(e.target.value)}>
                  {segments.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="field-row">
                <label>Type</label>
                <select className="field-input" value={nodeType} onChange={e => setNodeType(e.target.value)}>
                  {types.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <button
                className="btn-confirm"
                onClick={() => { onConfirm(n.node_id, label, segment, nodeType); setExpanded(null); }}
              >
                ✓ Confirm Node
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
