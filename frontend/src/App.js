import React, { useState, useCallback, useEffect } from 'react';
import ScanHistory from './components/ScanHistory';
import NetworkGraph from './components/NetworkGraph';
import AlertPanel from './components/AlertPanel';
import TopologyManager from './components/TopologyManager';
import DatasetSelector from './components/DatasetSelector';
import ChatAssistant from './components/ChatAssistant';
import DeviceConnector from './components/DeviceConnector';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export default function App() {
  const [dataset, setDataset] = useState('hai');
  const [scanType, setScanType] = useState('deep');
  const [scanResult, setScanResult] = useState(null);
  const [alertLevel, setAlertLevel] = useState('CLEAN');
  const [loading, setLoading] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [pendingNodes, setPendingNodes] = useState([]);
  const [showConnector, setShowConnector] = useState(false);

  useEffect(() => {
    fetchHistory();
    fetchPendingNodes();
  }, []);

  const fetchHistory = async () => {
    try {
      const r = await fetch(`${API_URL}/history/?limit=50`);
      const d = await r.json();
      setScanHistory(d.scans || []);
    } catch (e) {
      console.error('Failed to fetch history:', e);
    }
  };

  const fetchPendingNodes = async () => {
    try {
      const r = await fetch(`${API_URL}/topology/nodes/pending`);
      const d = await r.json();
      setPendingNodes(d.pending || []);
    } catch (e) {
      console.error('Failed to fetch pending nodes:', e);
    }
  };

  const runScan = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API_URL}/scan/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dataset, scan_type: scanType }),
      });
      const d = await r.json();
      setScanResult(d);
      setAlertLevel(d.status || 'UNKNOWN');
      fetchHistory();
      fetchPendingNodes();
    } catch (e) {
      console.error('Scan failed:', e);
    } finally {
      setLoading(false);
    }
  }, [dataset, scanType]);

  const selectScan = useCallback((scan) => {
    setScanResult(scan);
    setAlertLevel(scan.status || 'UNKNOWN');
  }, []);

  const exportCSV = useCallback(async () => {
    try {
      const r = await fetch(`${API_URL}/history/export`);
      const b = await r.blob();
      const u = window.URL.createObjectURL(b);
      const a = document.createElement('a');
      a.href = u;
      a.download = 'scan_history.csv';
      a.click();
      window.URL.revokeObjectURL(u);
    } catch (e) {
      console.error('Export failed:', e);
    }
  }, []);

  const confirmNode = useCallback(async (nodeId, label, segment, nodeType) => {
    try {
      await fetch(`${API_URL}/topology/nodes/${nodeId}/confirm`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, segment, node_type: nodeType }),
      });
      fetchPendingNodes();
    } catch (e) {
      console.error('Confirm failed:', e);
    }
  }, []);

  const denyNode = useCallback(async (nodeId) => {
    try {
      await fetch(`${API_URL}/topology/nodes/${nodeId}/deny`, { method: 'PUT' });
      fetchPendingNodes();
    } catch (e) {
      console.error('Deny failed:', e);
    }
  }, []);

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <h1 className="logo">
            <span className="logo-icon">T</span>
            Topo Scanner
          </h1>
          <span className="subtitle">OT Security</span>
        </div>
        <div className="header-right">
          <button className="btn btn-success" onClick={() => setShowConnector(true)}>
            + Device
          </button>
          <DatasetSelector value={dataset} onChange={setDataset} />
          <div className="scan-type-toggle">
            <button
              className={`scan-type-btn ${scanType === 'quick' ? 'active' : ''}`}
              onClick={() => setScanType('quick')}
            >
              Quick
            </button>
            <button
              className={`scan-type-btn ${scanType === 'deep' ? 'active' : ''}`}
              onClick={() => setScanType('deep')}
            >
              Deep
            </button>
          </div>
          <button className="scan-btn" onClick={runScan} disabled={loading}>
            {loading ? 'Scanning...' : 'Run Scan'}
          </button>
          <div className={`status-badge status-${alertLevel.toLowerCase()}`}>
            {alertLevel.replace('_', ' ')}
          </div>
          {pendingNodes.length > 0 && (
            <div className="pending-badge">{pendingNodes.length} new</div>
          )}
        </div>
      </header>

      <main className="dashboard">
        <section className="panel">
          <ScanHistory
            scans={scanHistory}
            onSelect={selectScan}
            onExport={exportCSV}
            selectedId={scanResult?.scan_id || scanResult?.id}
          />
        </section>
        <section className="panel" style={{ borderRight: '1px solid var(--border)' }}>
          <NetworkGraph scanResult={scanResult} dataset={dataset} />
        </section>
        <section className="panel" style={{ borderRight: 'none', overflowY: 'auto' }}>
          <AlertPanel scanResult={scanResult} alertLevel={alertLevel} />
          <TopologyManager
            pendingNodes={pendingNodes}
            onConfirm={confirmNode}
            onDeny={denyNode}
          />
          <ChatAssistant />
        </section>
      </main>

      {showConnector && (
        <DeviceConnector onClose={() => setShowConnector(false)} />
      )}
    </div>
  );
}