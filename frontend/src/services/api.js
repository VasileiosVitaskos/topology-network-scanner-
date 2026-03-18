const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

class ApiService {
  async runScan(dataset = 'hai', scanType = 'deep', options = {}) {
    const r = await fetch(`${API_URL}/scan/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset, scan_type: scanType, ...options }),
    });
    return r.json();
  }

  async getScanStatus() {
    return (await fetch(`${API_URL}/scan/status`)).json();
  }

  async getHistory(limit = 50, offset = 0, status = null) {
    const p = new URLSearchParams({ limit, offset });
    if (status) p.append('status', status);
    return (await fetch(`${API_URL}/history/?${p}`)).json();
  }

  async getScan(id) {
    return (await fetch(`${API_URL}/history/${id}`)).json();
  }

  async getStats() {
    return (await fetch(`${API_URL}/history/stats`)).json();
  }

  async exportCSV() {
    return (await fetch(`${API_URL}/history/export`)).blob();
  }

  async getNodes(includeRemoved = false) {
    return (await fetch(`${API_URL}/topology/nodes?include_removed=${includeRemoved}`)).json();
  }

  async getPendingNodes() {
    return (await fetch(`${API_URL}/topology/nodes/pending`)).json();
  }

  async addNode(id, label, segment, nodeType) {
    return (await fetch(`${API_URL}/topology/nodes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: id, label, segment, node_type: nodeType }),
    })).json();
  }

  async confirmNode(id, label, segment, nodeType) {
    return (await fetch(`${API_URL}/topology/nodes/${id}/confirm`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, segment, node_type: nodeType }),
    })).json();
  }

  async denyNode(id) {
    return (await fetch(`${API_URL}/topology/nodes/${id}/deny`, { method: 'PUT' })).json();
  }

  async getHealth() {
    return (await fetch(`${API_URL}/health`)).json();
  }

  async askAssistant(prompt) {
    return (await fetch(`${API_URL}/assistant/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    })).json();
  }

  async connectLive(host, username, password, deviceType = 'cisco_ios', port = 22) {
    return (await fetch(`${API_URL}/topology/connect_live`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, username, password, device_type: deviceType, port }),
    })).json();
  }
}

const apiServiceInstance = new ApiService();
export default apiServiceInstance;