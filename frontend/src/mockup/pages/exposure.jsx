// Exposure & Breach page
const ExposurePage = () => {
  const d = window.CFData;
  const [tab, setTab] = useState("ports");

  return (
    <div className="page" data-screen-label="Exposure and Breach">
      <div className="page-head">
        <div>
          <h1 className="page-title">Exposure &amp; Attack Surface</h1>
          <div className="page-sub">Authorized scan results, breach signals, and IP reputation enrichment. <span className="mono">Lab-scoped only.</span></div>
        </div>
      </div>

      <div className="alert warn" style={{ marginBottom: 14 }}>
        <Icon name="info" size={15} style={{ marginTop: 1 }} />
        <div><span className="alert-strong">Ethics note.</span> All TCP scans target localhost or authorized lab Docker containers. Breach signals are HIBP API data or clearly-labeled synthetic.</div>
      </div>

      <div className="tabs">
        <button className={"tab" + (tab === "ports" ? " active" : "")} onClick={() => setTab("ports")}>
          <Icon name="network" size={13} /> Open Ports <span className="tab-count">{d.ports.length} hosts</span>
        </button>
        <button className={"tab" + (tab === "breach" ? " active" : "")} onClick={() => setTab("breach")}>
          <Icon name="file" size={13} /> Breach Signals <span className="tab-count">{d.breaches.length}</span>
        </button>
        <button className={"tab" + (tab === "ip" ? " active" : "")} onClick={() => setTab("ip")}>
          <Icon name="radar" size={13} /> IP Reputation <span className="tab-count">{d.ipRep.length}</span>
        </button>
      </div>

      {tab === "ports" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {d.ports.map(h => (
            <Card key={h.hostname} title={
              <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                <Icon name="server" size={15} style={{ color: "var(--text-3)" }} /> {h.hostname}
              </span>
            } sub={<span><span className="mono">{h.ip}</span> · {h.openCount} open port(s) · scanned {h.scannedAt}</span>} padded={false}>
              <table className="data">
                <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Note</th></tr></thead>
                <tbody>
                  {h.ports.map(p => (
                    <tr key={p.port}>
                      <td className="mono" style={{ fontWeight: 600 }}>{p.port}</td>
                      <td className="mono" style={{ color: "var(--text-2)" }}>{p.service}</td>
                      <td><Badge severity={p.risk} size="sm" /></td>
                      <td style={{ color: "var(--text-2)" }}>{p.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          ))}
        </div>
      )}

      {tab === "breach" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {d.breaches.map(b => (
            <Card key={b.name}>
              <div className="row-gap" style={{ marginBottom: 8 }}>
                <Badge severity={b.severity} size="sm" />
                {b.synthetic && <span className="chip">SYNTHETIC</span>}
                <span style={{ fontSize: 12, color: "var(--text-3)" }}>· {b.date}</span>
                <span className="spacer" />
                <span className="mono" style={{ fontWeight: 600 }}>{b.pwnCount.toLocaleString()} accounts</span>
              </div>
              <h3 style={{ margin: "0 0 6px", fontSize: 16 }}>{b.name}</h3>
              <div style={{ fontSize: 12.5, color: "var(--text-3)", marginBottom: 8 }}>Domain: <span className="mono">{b.domain}</span></div>
              <p style={{ margin: 0, color: "var(--text-2)", lineHeight: 1.55, fontSize: 13.5 }}>{b.description}</p>
              <div style={{ marginTop: 10 }}>
                <div className="section-h" style={{ marginBottom: 6 }}>Data exposed</div>
                <div className="row-gap">
                  {b.classes.map(c => <span key={c} className="chip">{c}</span>)}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {tab === "ip" && (
        <Card padded={false}>
          <table className="data">
            <thead>
              <tr><th>IP Address</th><th>Classification</th><th>Open ports</th><th>CVEs</th><th>Note</th></tr>
            </thead>
            <tbody>
              {d.ipRep.map(r => {
                const cls = r.classification;
                const color = cls === "MALICIOUS" ? "crit" : cls === "BENIGN" ? "low" : "unknown";
                return (
                  <tr key={r.ip}>
                    <td className="mono" style={{ fontWeight: 600 }}>{r.ip}</td>
                    <td><Badge severity={color === "crit" ? "CRITICAL" : color === "low" ? "LOW" : ""} size="sm">{cls}</Badge></td>
                    <td className="mono" style={{ color: "var(--text-2)" }}>{r.ports.join(", ") || "—"}</td>
                    <td className="mono" style={{ color: "var(--text-2)" }}>{r.vulns.join(", ") || "—"}</td>
                    <td style={{ color: "var(--text-2)" }}>{r.note}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
};

window.ExposurePage = ExposurePage;
