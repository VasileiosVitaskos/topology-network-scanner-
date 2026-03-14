import React, { useState } from 'react';

export default function TopologyManager({ pendingNodes, onConfirm, onDeny }) {
  const [exp, setExp] = useState(null);
  const [label, setLabel] = useState('');
  const [seg, setSeg] = useState('unknown');
  const [typ, setTyp] = useState('sensor');

  const segments = ['plc', 'scada', 'workstation', 'dmz', 'unknown'];
  const types = ['sensor', 'plc', 'hmi', 'switch', 'firewall', 'workstation'];

  const toggle = (id) => {
    if (exp === id) { setExp(null); } else { setExp(id); setLabel(id); setSeg('unknown'); setTyp('sensor'); }
  };

  return (
    <div className="topology-manager">
      <div className="panel-header">
        <span>Topology</span>
        {pendingNodes.length > 0 && <span className="pending-count">{pendingNodes.length} pending</span>}
      </div>
      {pendingNodes.length === 0 && <div className="empty-state">Network topology stable</div>}
      <div className="pending-list">
        {pendingNodes.map(n => (
          <div key={n.node_id} className="pending-node">
            <div className="pending-header" onClick={() => toggle(n.node_id)}>
              <div className="pending-indicator">!</div>
              <div className="pending-info">
                <div className="pending-id">{n.node_id}</div>
                <div className="pending-time">Detected {new Date(n.first_seen * 1000).toLocaleTimeString()}</div>
              </div>
              <button className="btn-deny" onClick={e => { e.stopPropagation(); onDeny(n.node_id); }}>×</button>
            </div>
            {exp === n.node_id && (
              <div className="pending-expand">
                <div className="field-row">
                  <label>Label</label>
                  <input type="text" value={label} onChange={e => setLabel(e.target.value)} className="field-input" placeholder="e.g. PLC-Stage3" />
                </div>
                <div className="field-row">
                  <label>Segment</label>
                  <select value={seg} onChange={e => setSeg(e.target.value)} className="field-input">
                    {segments.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="field-row">
                  <label>Type</label>
                  <select value={typ} onChange={e => setTyp(e.target.value)} className="field-input">
                    {types.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <button className="btn-confirm" onClick={() => { onConfirm(n.node_id, label, seg, typ); setExp(null); }}>
                  Confirm Node
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
