// frontend/src/main.jsx
// Entry point: fetch live dashboard data from the FastAPI backend, set
// window.CFData (so the ported mockup code reads it unchanged), then render.
import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import { App } from "./CyberFusionApp.jsx";
import "./index.css";

// In dev, Vite proxies /api → http://localhost:8000 (see vite.config.js).
const API = "";

function Root() {
  const [state, setState] = useState({ loading: true, error: null, ready: false });

  const load = async () => {
    setState({ loading: true, error: null, ready: false });
    try {
      const res = await fetch(`${API}/api/data`);
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      const data = await res.json();
      window.CFData = data;            // the mockup reads this global
      window.CF_API = API;             // pages use this for uploads / actions
      setState({ loading: false, error: null, ready: true });
    } catch (e) {
      setState({ loading: false, error: e.message, ready: false });
    }
  };

  useEffect(() => { load(); }, []);

  if (state.loading) {
    return (
      <div style={{ display: "grid", placeItems: "center", height: "100vh",
                    fontFamily: "Manrope, system-ui, sans-serif", color: "#475569" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#0FB5A8" }}>CyberFusion</div>
          <div style={{ marginTop: 8, fontSize: 14 }}>Loading live intelligence…</div>
        </div>
      </div>
    );
  }
  if (state.error) {
    return (
      <div style={{ display: "grid", placeItems: "center", height: "100vh",
                    fontFamily: "Manrope, system-ui, sans-serif" }}>
        <div style={{ maxWidth: 460, textAlign: "center" }}>
          <div style={{ fontSize: 22, fontWeight: 800, color: "#E24B4A" }}>Cannot reach the API</div>
          <p style={{ color: "#475569", fontSize: 14, lineHeight: 1.6, marginTop: 10 }}>
            {state.error}. Make sure the backend is running:
          </p>
          <pre style={{ background: "#0a1226", color: "#7CF5E6", padding: "10px 14px",
                        borderRadius: 8, fontSize: 12, textAlign: "left", overflowX: "auto" }}>
uvicorn api.main:app --port 8000</pre>
          <button onClick={load} style={{ marginTop: 14, background: "#0FB5A8", color: "#fff",
                    border: 0, borderRadius: 8, padding: "9px 18px", fontWeight: 700, cursor: "pointer" }}>
            Retry
          </button>
        </div>
      </div>
    );
  }
  return <App />;
}

ReactDOM.createRoot(document.getElementById("root")).render(<Root />);
