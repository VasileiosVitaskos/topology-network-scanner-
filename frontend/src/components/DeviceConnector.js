import React, { useState } from 'react';
import api from '../services/api';

export default function DeviceConnector({ onClose }) {
  const [host, setHost] = useState('');
  const [user, setUser] = useState('');
  const [pwd, setPwd] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleConnect = async () => {
    if (!host || !user) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.connectLive(host, user, pwd, deviceType);
      setResult({ success: true, ...res });
    } catch (e) {
      setResult({ success: false, error: e.message || 'Connection failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span>Live Device Connection (SSH)</span>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="field-row">
            <label style={{ width: 80, color: '#00e5ff' }}>IP/Host</label>
            <input
              className="field-input"
              placeholder="192.168.1.1"
              value={host}
              onChange={e => setHost(e.target.value)}
            />
          </div>
          <div className="field-row">
            <label style={{ width: 80, color: '#00e5ff' }}>Username</label>
            <input
              className="field-input"
              placeholder="admin"
              value={user}
              onChange={e => setUser(e.target.value)}
            />
          </div>
          <div className="field-row">
            <label style={{ width: 80, color: '#00e5ff' }}>Password</label>
            <input
              className="field-input"
              type="password"
              placeholder="••••••••"
              value={pwd}
              onChange={e => setPwd(e.target.value)}
            />
          </div>
          <div className="field-row">
            <label style={{ width: 80, color: '#00e5ff' }}>Device</label>
            <select
              className="field-input"
              value={deviceType}
              onChange={e => setDeviceType(e.target.value)}
            >
              <option value="cisco_ios">Cisco IOS</option>
              <option value="cisco_xe">Cisco IOS-XE</option>
              <option value="cisco_asa">Cisco ASA</option>
              <option value="juniper">Juniper</option>
              <option value="paloalto_panos">Palo Alto</option>
            </select>
          </div>

          <button
            className="btn btn-scan-quick"
            onClick={handleConnect}
            disabled={loading || !host || !user}
            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
          >
            {loading ? 'Negotiating SSH Keys...' : 'Connect to Device'}
          </button>

          {result && (
            <div className={`modal-result ${result.success ? 'success' : 'error'}`}>
              {result.success
                ? `✓ Connected to ${host} — ${result.devices_found || 0} devices, ${result.logs_parsed || 0} logs, ${result.routes_found || 0} routes`
                : `✕ ${result.error}`
              }
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
