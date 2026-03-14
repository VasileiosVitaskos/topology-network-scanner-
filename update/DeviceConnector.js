import React, { useState } from 'react';
import api from '../services/api';

const DEVICE_TYPES = [
  { value: 'cisco_ios', label: 'Cisco IOS' },
  { value: 'cisco_xe', label: 'Cisco IOS-XE' },
  { value: 'cisco_asa', label: 'Cisco ASA' },
  { value: 'juniper', label: 'Juniper JunOS' },
  { value: 'paloalto_panos', label: 'Palo Alto' },
];

export default function DeviceConnector({ onClose }) {
  const [host, setHost] = useState('');
  const [user, setUser] = useState('');
  const [pwd, setPwd] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [port, setPort] = useState('22');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleConnect = async () => {
    if (!host || !user) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.connectLive(host, user, pwd, deviceType);
      setResult(res);
    } catch (e) {
      setResult({ error: 'Connection failed. Check that the backend is running and the device is reachable.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">Connect Network Device</span>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body">
          <div className="field-row">
            <label>Host</label>
            <input className="field-input" placeholder="192.168.1.1" value={host} onChange={e => setHost(e.target.value)} />
          </div>
          <div className="field-row">
            <label>Port</label>
            <input className="field-input" placeholder="22" value={port} onChange={e => setPort(e.target.value)} style={{ maxWidth: 80 }} />
          </div>
          <div className="field-row">
            <label>Username</label>
            <input className="field-input" placeholder="admin" value={user} onChange={e => setUser(e.target.value)} />
          </div>
          <div className="field-row">
            <label>Password</label>
            <input className="field-input" type="password" placeholder="••••••••" value={pwd} onChange={e => setPwd(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && handleConnect()} />
          </div>
          <div className="field-row">
            <label>Device</label>
            <select className="field-input" value={deviceType} onChange={e => setDeviceType(e.target.value)}>
              {DEVICE_TYPES.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
            </select>
          </div>

          <button className="scan-btn" onClick={handleConnect} disabled={loading || !host} style={{ width: '100%', marginTop: 8 }}>
            {loading ? 'Connecting via SSH...' : 'Connect'}
          </button>

          {result && (
            <div className={`result-box ${result.error ? 'error' : 'success'}`}>
              {result.error
                ? result.error
                : `Connected — ${result.routes_found || 0} routes, ${result.logs_parsed || 0} logs collected`
              }
            </div>
          )}

          <div style={{ marginTop: 14, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
            Read-only commands only: show log, show arp, show ip route, show interfaces.
            No configuration changes are made to the device.
          </div>
        </div>
      </div>
    </div>
  );
}
