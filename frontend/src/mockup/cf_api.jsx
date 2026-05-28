// cf_api.jsx — tiny client for the CyberFusion FastAPI backend.
// Exposed as window.CFApi so the (globals-style) mockup pages can call it.

const _api = (window.CF_API || "");

const CFApi = {
  async refreshData() {
    const r = await fetch(`${_api}/api/data`);
    if (!r.ok) throw new Error(`/api/data ${r.status}`);
    window.CFData = await r.json();
    return window.CFData;
  },
  async runPipeline(quick = true) {
    const r = await fetch(`${_api}/api/pipeline/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ quick, no_scan: false }),
    });
    if (!r.ok) throw new Error(`pipeline ${r.status}`);
    return r.json();
  },
  async uploadPreview(file, forcedType = "auto") {
    const fd = new FormData();
    fd.append("file", file); fd.append("forced_type", forcedType);
    const r = await fetch(`${_api}/api/upload/preview`, { method: "POST", body: fd });
    return r.json();
  },
  async uploadCommit(file, forcedType = "auto") {
    const fd = new FormData();
    fd.append("file", file); fd.append("forced_type", forcedType);
    const r = await fetch(`${_api}/api/upload/commit`, { method: "POST", body: fd });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `upload ${r.status}`); }
    return r.json();
  },
  async listUploads() { return (await fetch(`${_api}/api/uploads`)).json(); },
  async clearUploads() { return (await fetch(`${_api}/api/uploads`, { method: "DELETE" })).json(); },
  async supportedTypes() { return (await fetch(`${_api}/api/supported-types`)).json(); },
  async sourceTypes() { return (await fetch(`${_api}/api/source-types`)).json(); },
  async sources() { return (await fetch(`${_api}/api/sources`)).json(); },
  async addSource(body) {
    const r = await fetch(`${_api}/api/sources`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `add ${r.status}`); }
    return r.json();
  },
  async updateSource(id, body) {
    return (await fetch(`${_api}/api/sources/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
  },
  async deleteSource(id) { return (await fetch(`${_api}/api/sources/${id}`, { method: "DELETE" })).json(); },
  async setSecret(id, field, value) {
    return (await fetch(`${_api}/api/sources/${id}/secret`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ field, value }) })).json();
  },
  async testSource(id) { return (await fetch(`${_api}/api/sources/${id}/test`, { method: "POST" })).json(); },
  async workspace() { return (await fetch(`${_api}/api/workspace`)).json(); },
  async downloadReport() {
    const r = await fetch(`${_api}/api/report/pdf`, { method: "POST" });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `report ${r.status}`); }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "cyberfusion_report.pdf";
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    return true;
  },
  async briefingStatus() { return (await fetch(`${_api}/api/briefing/status`)).json(); },
  async generateBriefing() {
    const r = await fetch(`${_api}/api/briefing/generate`, { method: "POST" });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `briefing ${r.status}`); }
    return r.json();
  },
  async patchWorkspace(body) {
    const r = await fetch(`${_api}/api/workspace`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return r.json();
  },
  async onboard(body) {
    const r = await fetch(`${_api}/api/onboard`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return r.json();
  },
  async setFindingStatus(ruleId, status) {
    const r = await fetch(`${_api}/api/findings/${encodeURIComponent(ruleId)}/status`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `status ${r.status}`); }
    return r.json();
  },
  async notifySlack() {
    const r = await fetch(`${_api}/api/notify/slack`, { method: "POST" });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `slack ${r.status}`); }
    return r.json();
  },
  async briefingHistory() {
    const r = await fetch(`${_api}/api/briefing/history`);
    if (!r.ok) throw new Error(`history ${r.status}`);
    return r.json();
  },
  async getBriefing(filename) {
    const r = await fetch(`${_api}/api/briefing/history/${encodeURIComponent(filename)}`);
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `briefing ${r.status}`); }
    return r.json();
  },
  async fetchSource(id) {
    const r = await fetch(`${_api}/api/sources/${id}/fetch`, { method: "POST" });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `fetch ${r.status}`); }
    return r.json();
  },
};

window.CFApi = CFApi;
