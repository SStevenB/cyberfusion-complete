// Threat Feed page
const ThreatFeed = () => {
  const d = window.CFData;
  const [tab, setTab] = useState("cve");
  const [search, setSearch] = useState("");
  const [kevOnly, setKevOnly] = useState(false);

  const filteredCves = d.cves.filter(c =>
    (!search || c.id.toLowerCase().includes(search.toLowerCase()) || c.description.toLowerCase().includes(search.toLowerCase()))
    && (!kevOnly || c.kev)
  );

  return (
    <div className="page" data-screen-label="Threat Feed">
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intelligence Feed</h1>
          <div className="page-sub">Curated CVEs, CISA KEV catalog entries, and security journalism · refreshed every 60 minutes.</div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={async (e) => {
            const b = e.currentTarget; const o = b.textContent;
            b.disabled = true; b.textContent = "Refreshing…";
            try { await window.CFApi.runPipeline(true); await window.CFApi.refreshData(); location.reload(); }
            catch (err) { b.textContent = "Refresh failed"; setTimeout(() => { b.disabled = false; b.textContent = o; }, 2000); }
          }}><Icon name="refresh" size={14}/>Refresh feeds</button>
        </div>
      </div>

      <div className="tabs">
        <button className={"tab" + (tab === "cve" ? " active" : "")} onClick={() => setTab("cve")}>
          <Icon name="bug" size={13} /> Recent CVEs <span className="tab-count">{d.cves.length}</span>
        </button>
        <button className={"tab" + (tab === "kev" ? " active" : "")} onClick={() => setTab("kev")}>
          <Icon name="flame" size={13} /> CISA KEV <span className="tab-count">{d.kev.length}</span>
        </button>
        <button className={"tab" + (tab === "news" ? " active" : "")} onClick={() => setTab("news")}>
          <Icon name="feed" size={13} /> Security News <span className="tab-count">{d.news.length}</span>
        </button>
      </div>

      {tab === "cve" && (
        <>
          <div className="row-gap" style={{ marginBottom: 14 }}>
            <input className="search" placeholder="Search CVEs by ID or description…" value={search} onChange={e => setSearch(e.target.value)} style={{ width: 320 }} />
            <button className={"chip" + (kevOnly ? " active" : "")} onClick={() => setKevOnly(!kevOnly)} style={{ cursor: "pointer" }}>
              <Icon name="flame" size={11} /> KEV only
            </button>
            <span className="spacer" />
            <span style={{ fontSize: 12, color: "var(--text-3)" }}>{filteredCves.length} of {d.cves.length}</span>
          </div>
          <Card padded={false}>
            <table className="data">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Vendor · Product</th>
                  <th>Description</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {filteredCves.map(c => (
                  <tr key={c.id}>
                    <td><span className="mono" style={{ fontWeight: 600 }}>{c.id}</span>{c.kev && <span style={{ marginLeft: 6 }}><Icon name="flame" size={11} style={{ color: "var(--kev)" }} /></span>}</td>
                    <td><Badge severity={c.severity} size="sm" /></td>
                    <td><span className="mono" style={{ fontWeight: 600 }}>{c.score.toFixed(1)}</span></td>
                    <td style={{ color: "var(--text-2)" }}>{c.vendor} · {c.product}</td>
                    <td style={{ maxWidth: 380, color: "var(--text-2)" }}>{c.description}</td>
                    <td style={{ whiteSpace: "nowrap", color: "var(--text-3)" }}>{c.published}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {tab === "kev" && (
        <>
          <div className="alert info" style={{ marginBottom: 14 }}>
            <Icon name="info" size={15} style={{ marginTop: 1 }} />
            <div><span className="alert-strong">CISA Known Exploited Vulnerabilities</span> — {d.kev.length} vulnerabilities confirmed as actively exploited. Federal agencies must remediate these on deadline.</div>
          </div>
          <Card padded={false}>
            <table className="data">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Vendor</th>
                  <th>Product</th>
                  <th>Vulnerability</th>
                  <th>Date added</th>
                  <th>Due date</th>
                  <th>Ransomware</th>
                </tr>
              </thead>
              <tbody>
                {d.kev.map(v => (
                  <tr key={v.cveID}>
                    <td><span className="mono" style={{ fontWeight: 600 }}>{v.cveID}</span></td>
                    <td>{v.vendorProject}</td>
                    <td style={{ color: "var(--text-2)" }}>{v.product}</td>
                    <td style={{ color: "var(--text-2)" }}>{v.vulnerabilityName}</td>
                    <td className="mono" style={{ color: "var(--text-3)", fontSize: 12 }}>{v.dateAdded}</td>
                    <td className="mono" style={{ color: "var(--text-3)", fontSize: 12 }}>{v.dueDate}</td>
                    <td>{v.ransomware === "Known" ? <Badge severity="HIGH" size="sm">Known</Badge> : <span style={{ color: "var(--text-4)", fontSize: 12 }}>Unknown</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {tab === "news" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {d.news.map((n, i) => (
            <Card key={i}>
              <div className="row-gap" style={{ marginBottom: 6 }}>
                {n.priority && <Badge severity="HIGH" size="sm">Priority</Badge>}
                <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 600 }}>{n.source}</span>
                <span style={{ fontSize: 12, color: "var(--text-4)" }}>· {n.published}</span>
              </div>
              <h3 style={{ margin: "0 0 8px", fontSize: 16, letterSpacing: "-0.01em" }}>{n.title}</h3>
              <p style={{ margin: 0, color: "var(--text-2)", lineHeight: 1.55, fontSize: 13.5 }}>{n.summary}</p>
              <div className="row-gap" style={{ marginTop: 10 }}>
                {n.keywords.map(k => <span key={k} className="chip">{k}</span>)}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

window.ThreatFeed = ThreatFeed;
