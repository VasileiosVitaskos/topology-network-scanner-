const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

class ApiService {
  async runScan(dataset = 'swat', options = {}) {
    const r = await fetch(`${API_URL}/scan/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset, ...options })
    });
    return r.json();
  }

  async getScanStatus() { return (await fetch(`${API_URL}/scan/status`)).json(); }

  async getHistory(limit = 50, offset = 0, status = null) {
    const p = new URLSearchParams({ limit, offset });
    if (status) p.append('status', status);
    return (await fetch(`${API_URL}/history/?${p}`)).json();
  }

  async getScan(id) { return (await fetch(`${API_URL}/history/${id}`)).json(); }
  async getStats() { return (await fetch(`${API_URL}/history/stats`)).json(); }
  async exportCSV() { return (await fetch(`${API_URL}/history/export`)).blob(); }
  async getNodes(incl = false) { return (await fetch(`${API_URL}/topology/nodes?include_removed=${incl}`)).json(); }
  async getPendingNodes() { return (await fetch(`${API_URL}/topology/nodes/pending`)).json(); }

  async addNode(id, label, seg, typ) {
    return (await fetch(`${API_URL}/topology/nodes`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: id, label, segment: seg, node_type: typ })
    })).json();
  }

  async confirmNode(id, label, seg, typ) {
    return (await fetch(`${API_URL}/topology/nodes/${id}/confirm`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, segment: seg, node_type: typ })
    })).json();
  }

  async denyNode(id) { return (await fetch(`${API_URL}/topology/nodes/${id}/deny`, { method: 'PUT' })).json(); }

  async getLogs(ds = 'swat', since = 0, limit = 100) {
    const p = new URLSearchParams({ dataset: ds, since, limit });
    return (await fetch(`${API_URL}/logs/?${p}`)).json();
  }

  async getHealth() { return (await fetch(`${API_URL}/health`)).json(); }

  async askAssistant(prompt) {
    return (await fetch(`${API_URL}/assistant/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    })).json();
  }

  async connectLive(host, username, password, device_type = 'cisco_ios') {
    return (await fetch(`${API_URL}/topology/connect_live`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, username, password, device_type })
    })).json();
  }
}

const apiServiceInstance = new ApiService();
export default apiServiceInstance;
