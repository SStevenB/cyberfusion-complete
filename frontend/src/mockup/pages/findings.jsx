// Correlated Findings page
const FindingsPage = ({ onOpenFinding }) => {
  const d = window.CFData;
  const [sevFilter, setSevFilter] = useState({ CRITICAL: true, HIGH: true, MEDIUM: true, LOW: true });
  const [statusFilter, setStatusFilter] = useState("all");
  const [expanded, setExpanded] = useState(new Set([d.findings[0]?.rule_id]));

  const filtered = d.findings.filter(f => sevFilter[f.risk_label] && (statusFilter === "all" || f.status === statusFilter));

  const toggle = (id) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id); else next.add(id);
    setExpanded(next);
  };

  return (
    <div className="page" data-screen-label="Correlated Findings">
      <div className="page-head">
        <div>
          <h1 className="page-title">Correlated Intelligence Findings</h1>
          <div className="page-sub">Multi-source signal correlation with MITRE ATT&amp;CK mapping, status tracking, and PDF export.</div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={async (e) => {
            const b = e.currentTarget; const o = b.textContent;
            b.disabled = true; b.textContent = "Generating…";
            try { await window.CFApi.downloadReport(); b.textContent = o; }
            catch (err) { b.textContent = "No findings yet"; }
            finally { setTimeout(() => { b.disabled = false; b.textContent = o; }, 1500); }
          }}><Icon name="download" size={14} />Export PDF report</button>
          <button className="btn btn-primary" onClick={async (e) => {
            const b = e.currentTarget; const o = b.textContent;
            b.disabled = true; b.textContent = "Sending…";
            try {
              const r = await window.CFApi.notifySlack();
              b.textContent = r.sent ? "Sent to Slack ✓" : "Slack not configured";
              if (!r.sent) alert(r.message);
            } catch (err) { b.textContent = "Send failed"; }
            finally { setTimeout(() => { b.disabled = false; b.textContent = o; }, 2200); }
          }}><Icon name="external" size={14} />Send to Slack</button>
        </div>
      </div>

      {/* Score chart */}
      <Card title="Risk Score by Finding" sub="Open and acknowledged findings · click any to expand"
        action={<div className="row-gap">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
            <button key={s}
              className={"chip" + (sevFilter[s] ? " active" : "")}
              style={{ cursor: "pointer" }}
              onClick={() => setSevFilter({ ...sevFilter, [s]: !sevFilter[s] })}>
              <span className="sw" style={{ width: 7, height: 7, borderRadius: 50, background: `var(--${sevClass(s)})` }} />
              {s.toLowerCase()}
            </button>
          ))}
        </div>}>
        <FindingScoreBars findings={filtered} />
      </Card>

      <div style={{ height: 16 }} />

      {/* Status filter row */}
      <div className="row-gap" style={{ marginBottom: 14 }}>
        <Icon name="filter" size={14} style={{ color: "var(--text-3)" }} />
        <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 600, textTransform: "uppercase", letterSpacing: ".06em", marginRight: 6 }}>Status</span>
        {["all", "open", "acknowledged", "resolved", "false_positive"].map(s => (
          <button key={s} className={"chip" + (statusFilter === s ? " active" : "")} style={{ cursor: "pointer" }} onClick={() => setStatusFilter(s)}>
            {s === "all" ? "All" : s === "false_positive" ? "False positive" : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        <span className="spacer" />
        <span style={{ fontSize: 12, color: "var(--text-3)" }}>{filtered.length} of {d.findings.length} findings</span>
      </div>

      {/* Findings list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {filtered.map(f => {
          const open = expanded.has(f.rule_id);
          return (
            <div key={f.rule_id} className="card">
              <div className="card-head" style={{ cursor: "pointer" }} onClick={() => toggle(f.rule_id)}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, flex: 1 }}>
                  <div className={"list-rail " + sevClass(f.risk_label)} style={{ height: 32 }} />
                  <div>
                    <div className="row-gap" style={{ marginBottom: 4 }}>
                      <span className="mono" style={{ fontSize: 11.5, color: "var(--text-4)" }}>{f.rule_id}</span>
                      <Badge severity={f.risk_label} size="sm" />
                      {f.kev_confirmed_cves && f.kev_confirmed_cves.length > 0 && <KevBadge />}
                      <span className={"status-pill " + (f.status === "open" ? "open" : f.status === "acknowledged" ? "ack" : f.status === "resolved" ? "resolved" : "fp")}>
                        <span className="ind" />{f.status.replace("_", " ")}
                      </span>
                    </div>
                    <h3 className="card-title" style={{ fontSize: 15 }}>{f.rule_name}</h3>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                  <div style={{ textAlign: "right" }}>
                    <div className="mono" style={{ fontSize: 18, fontWeight: 700 }}>{f.risk_score}<span style={{ color: "var(--text-4)", fontWeight: 400 }}>/100</span></div>
                    <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 2 }}>{f.ageDays}d ago</div>
                  </div>
                  <Icon name={open ? "chevronDown" : "chevron"} size={16} style={{ color: "var(--text-3)" }} />
                </div>
              </div>
              {open && (
                <div className="card-body" style={{ paddingTop: 18 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 24 }}>
                    <div>
                      <div className="section-h">Description</div>
                      <p style={{ margin: "0 0 14px", color: "var(--text-2)", lineHeight: 1.6 }}>{f.description}</p>

                      {f.mitre_technique && (
                        <>
                          <div className="section-h">MITRE ATT&amp;CK</div>
                          <div className="row-gap" style={{ marginBottom: 16 }}>
                            <span className="mitre-tag"><Icon name="map" size={11} />{f.mitre_tactic}</span>
                            <span className="mitre-tag">{f.mitre_technique}</span>
                          </div>
                        </>
                      )}

                      {[
                        { field: "matched_exposure", label: "Exposure / breach signals", icon: "eye" },
                        { field: "matched_cves", label: "Related CVEs", icon: "bug" },
                        { field: "kev_confirmed_cves", label: "KEV-confirmed", icon: "flame" },
                        { field: "affected_emails", label: "Affected email addresses", icon: "file" },
                      ].map(({ field, label, icon }) => {
                        const items = f[field] || [];
                        if (!items.length) return null;
                        return (
                          <div key={field} style={{ marginBottom: 14 }}>
                            <div className="section-h" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                              <Icon name={icon} size={11} /> {label} <span style={{ color: "var(--text-4)" }}>({items.length})</span>
                            </div>
                            <div className="evidence-list">
                              {items.slice(0, 5).map((e, i) => <div key={i} className="evidence-item">{e}</div>)}
                              {items.length > 5 && <div style={{ fontSize: 12, color: "var(--text-3)", padding: "4px 11px" }}>+ {items.length - 5} more</div>}
                            </div>
                          </div>
                        );
                      })}

                      <div className="section-h">Recommended mitigation</div>
                      <ol style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)", lineHeight: 1.65, fontSize: 13.5 }}>
                        {parseRec(f.recommendation).map((s, i) => <li key={i} style={{ marginBottom: 5 }}>{s}</li>)}
                      </ol>
                    </div>

                    <div>
                      <div className="section-h">Score breakdown</div>
                      <div className="score-rows">
                        {f.score_breakdown.map((row, i) => (
                          <div className="score-row" key={i}>
                            <span className="lbl">{row.label}</span>
                            <span className="val">{row.value}</span>
                          </div>
                        ))}
                        <div className="score-row total">
                          <span className="lbl">Final score</span>
                          <span className="val">{f.risk_score} / 100</span>
                        </div>
                      </div>

                      <div className="section-h" style={{ marginTop: 18 }}>Affected assets</div>
                      <div className="evidence-list">
                        {f.affected_assets.map((a, i) => <div key={i} className="evidence-item">{a}</div>)}
                      </div>
                      <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 6 }}>
                        {{1: "Tier 1 — Crown Jewel (×1.5 multiplier)", 2: "Tier 2 — Core (×1.2 multiplier)", 3: "Tier 3 — Standard (×1.0)"}[f.asset_tier]}
                      </div>

                      <div className="divider" />
                      <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }} onClick={(e) => { e.stopPropagation(); onOpenFinding(f.rule_id); }}>
                        Open full detail page <Icon name="external" size={13} />
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

window.FindingsPage = FindingsPage;
