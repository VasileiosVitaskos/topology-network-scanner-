const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

class ApiService {
  async _fetch(url, options = {}) {
    const res = await fetch(`${API_URL}${url}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res;
  }

  // ── Scan ──
  async runScan(dataset = 'live', scanType = 'quick', options = {}) {
    const res = await this._fetch('/scan/', {
      method: 'POST',
      body: JSON.stringify({ dataset, scan_type: scanType, ...options }),
    });
    return res.json();
  }

  async getScanStatus() {
    return (await this._fetch('/scan/status')).json();
  }

  // ── Chat ──
  async chat(message, sessionId = 'default') {
    const res = await this._fetch('/chat/', {
      method: 'POST',
      body: JSON.stringify({ message, session_id: sessionId }),
    });
    return res.json();
  }

  // ── Backwards compat ──
  async askAssistant(prompt) {
    const res = await this._fetch('/assistant/', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    });
    return res.json();
  }

  // ── History ──
  async getHistory(limit = 50, offset = 0, status = null) {
    const p = new URLSearchParams({ limit, offset });
    if (status) p.append('status', status);
    return (await this._fetch(`/history/?${p}`)).json();
  }

  async getScan(id) {
    return (await this._fetch(`/history/${id}`)).json();
  }

  async getStats() {
    return (await this._fetch('/history/stats')).json();
  }

  async exportCSV() {
    return (await fetch(`${API_URL}/history/export`)).blob();
  }

  // ── Logs ──
  async getLogs(dataset = 'live', limit = 100) {
    const p = new URLSearchParams({ dataset, limit });
    return (await this._fetch(`/logs/?${p}`)).json();
  }

  // ── Topology ──
  async getNodes() {
    return (await this._fetch('/topology/nodes')).json();
  }

  async getPendingNodes() {
    return (await this._fetch('/topology/nodes/pending')).json();
  }

  async addNode(id, label, segment, nodeType) {
    return (await this._fetch('/topology/nodes', {
      method: 'POST',
      body: JSON.stringify({ node_id: id, label, segment, node_type: nodeType }),
    })).json();
  }

  async confirmNode(id, label, segment, nodeType) {
    return (await this._fetch(`/topology/nodes/${id}/confirm`, {
      method: 'PUT',
      body: JSON.stringify({ label, segment, node_type: nodeType }),
    })).json();
  }

  async denyNode(id) {
    return (await this._fetch(`/topology/nodes/${id}/deny`, { method: 'PUT' })).json();
  }

  // ── SSH Live Connect ──
  async connectLive(host, username, password, deviceType = 'cisco_ios') {
    return (await this._fetch('/topology/connect_live', {
      method: 'POST',
      body: JSON.stringify({ host, username, password, device_type: deviceType }),
    })).json();
  }

  // ── Health ──
  async getHealth() {
    return (await this._fetch('/health')).json();
  }
}

const api = new ApiService();
export default api;
