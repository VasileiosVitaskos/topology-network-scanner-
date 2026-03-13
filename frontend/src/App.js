import React, { useState, useCallback, useEffect, useRef } from 'react';
import ScanHistory from './components/ScanHistory';
import NetworkGraph from './components/NetworkGraph';
import ScanResultPanel from './components/ScanResultPanel';
import ChatAssistant from './components/ChatAssistant';
import TopologyManager from './components/TopologyManager';
import DeviceConnector from './components/DeviceConnector';
import api from './services/api';
import './App.css';

export default function App() {
  const [dataset, setDataset] = useState('live');
  const [scanResult, setScanResult] = useState(null);
  const [alertLevel, setAlertLevel] = useState('CLEAN');
  const [loading, setLoading] = useState(false);
  const [scanType, setScanType] = useState(null); // which button is loading
  const [scanHistory, setScanHistory] = useState([]);
  const [pendingNodes, setPendingNodes] = useState([]);
  const [showConnector, setShowConnector] = useState(false);
  const chatRef = useRef(null);

  useEffect(() => {
    fetchHistory();
    fetchPending();
  }, []);

  const fetchHistory = async () => {
    try {
      const d = await api.getHistory(50);
      setScanHistory(d.scans || []);
    } catch (e) { console.error(e); }
  };

  const fetchPending = async () => {
    try {
      const d = await api.getPendingNodes();
      setPendingNodes(d.pending || []);
    } catch (e) { console.error(e); }
  };

  const runScan = useCallback(async (type) => {
    setLoading(true);
    setScanType(type);
    try {
      const d = await api.runScan(dataset, type);
      setScanResult(d);
      setAlertLevel(d.status || 'CLEAN');
      fetchHistory();
      fetchPending();
    } catch (e) {
      console.error('Scan failed:', e);
    } finally {
      setLoading(false);
      setScanType(null);
    }
  }, [dataset]);

  const selectScan = useCallback((scan) => {
    // Parse JSON fields if they're strings
    const parsed = { ...scan };
    ['findings', 'network_health', 'recommendations', 'gate_results', 'involved_sensors'].forEach(f => {
      if (typeof parsed[f] === 'string') {
        try { parsed[f] = JSON.parse(parsed[f]); } catch {}
      }
    });
    setScanResult(parsed);
    setAlertLevel(parsed.status || 'CLEAN');
  }, []);

  const exportCSV = useCallback(async () => {
    try {
      const blob = await api.exportCSV();
      const u = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = u; a.download = 'scan_history.csv'; a.click();
    } catch (e) { console.error(e); }
  }, []);

  const confirmNode = useCallback(async (nodeId, label, segment, nodeType) => {
    try {
      await api.confirmNode(nodeId, label, segment, nodeType);
      fetchPending();
    } catch (e) { console.error(e); }
  }, []);

  const denyNode = useCallback(async (nodeId) => {
    try {
      await api.denyNode(nodeId);
      fetchPending();
    } catch (e) { console.error(e); }
  }, []);

  return (
    <div className="app">
      {/* ── HEADER ── */}
      <header className="header">
        <div className="header-left">
          <h1 className="logo">
            <span className="logo-icon">⬡</span>
            Topo Scanner
          </h1>
          <span className="subtitle">OT Network Security</span>
        </div>
        <div className="header-right">
          <button className="btn btn-device" onClick={() => setShowConnector(true)}>
            ＋ Device
          </button>

          <select
            className="dataset-select"
            value={dataset}
            onChange={e => setDataset(e.target.value)}
          >
            <option value="live">Live Simulation</option>
            <option value="hai">HAI Dataset</option>
            <option value="swat">SWaT A10</option>
            <option value="batadal">BATADAL</option>
          </select>

          <button
            className="btn btn-scan-quick"
            onClick={() => runScan('quick')}
            disabled={loading}
          >
            {scanType === 'quick' ? '⟳ Analyzing...' : '▶ Quick Scan'}
          </button>

          <button
            className="btn btn-scan-deep"
            onClick={() => runScan('deep')}
            disabled={loading}
          >
            {scanType === 'deep' ? '⟳ Computing...' : '◈ Deep Scan'}
          </button>

          <div className={`status-badge status-${alertLevel.toLowerCase()}`}>
            {alertLevel.replace('_', ' ')}
          </div>

          {pendingNodes.length > 0 && (
            <span style={{ fontSize: 11, color: '#ffab00' }}>
              ⚠ {pendingNodes.length} new
            </span>
          )}
        </div>
      </header>

      {/* ── DASHBOARD ── */}
      <main className="dashboard">
        {/* LEFT: Scan History */}
        <section className="panel">
          <ScanHistory
            scans={scanHistory}
            onSelect={selectScan}
            onExport={exportCSV}
            selectedId={scanResult?.scan_id || scanResult?.id}
          />
        </section>

        {/* CENTER: Network Graph + Results */}
        <section className="center-panel">
          <div className="graph-container">
            <NetworkGraph
              scanResult={scanResult}
              dataset={dataset}
            />
            {loading && (
              <div className="scanning-overlay">
                <div className="scan-spinner" />
                <div className="scanning-text">
                  {scanType === 'deep'
                    ? 'Running topological analysis — Sheaf · Ricci · Homology'
                    : 'AI analyzing network logs...'}
                </div>
              </div>
            )}
          </div>

          {scanResult && (
            <div className="scan-result-panel">
              <ScanResultPanel result={scanResult} />
            </div>
          )}
        </section>

        {/* RIGHT: Chat + Topology */}
        <section className="panel right-panel">
          <ChatAssistant ref={chatRef} scanResult={scanResult} />
          <TopologyManager
            pendingNodes={pendingNodes}
            onConfirm={confirmNode}
            onDeny={denyNode}
          />
        </section>
      </main>

      {/* MODAL */}
      {showConnector && (
        <DeviceConnector onClose={() => setShowConnector(false)} />
      )}
    </div>
  );
}
