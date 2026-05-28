// Finding Detail page
const FindingDetail = ({ ruleId, onBack }) => {
  const d = window.CFData;
  const f = d.findings.find(x => x.rule_id === ruleId);
  const [status, setStatusState] = useState(f ? f.status : "open");
  const [saving, setSaving] = useState(null);

  const changeStatus = async (newStatus) => {
    setSaving(newStatus);
    try {
      await window.CFApi.setFindingStatus(ruleId, newStatus);
      setStatusState(newStatus);
      // keep the in-memory copy in sync so other pages reflect it without a full reload
      if (f) f.status = newStatus;
    } catch (e) {
      alert("Could not update status: " + String(e));
    }
    setSaving(null);
  };

  if (!f) {
    return (
      <div className="page">
        <button className="btn" onClick={onBack}><Icon name="chevron" size={13} style={{ transform: "rotate(180deg)" }} /> Back</button>
        <div style={{ padding: 40, textAlign: "center", color: "var(--text-3)" }}>Finding {ruleId} not found.</div>
      </div>
    );
  }

  const docs = {
    "CORR-003": {
      purpose: "Surfaces breach or exposure signals containing VPN-related credentials. This is treated as the highest-impact initial-access vector because a single valid credential bypasses every perimeter control.",
      detection_logic: "The correlator flattens all breach/exposure signals from configured sources, filters for items tagged as `vpn` or `remote_access`, and joins them against the asset inventory's VPN-tagged hosts. A match fires this rule with confidence HIGH; the rule's base weight is 25.",
      why_it_matters: "VPN credentials yield trusted network access. Once inside, an attacker bypasses NAT, perimeter firewalls, and many DLP/EDR controls. Real-world ransomware operators consistently rank exposed VPN access as the #1 initial-access vector.",
      false_positives: "Stale exposure signals from a deprecated VPN appliance can persist after migration. Re-run the asset reconciliation step monthly to clear.",
      data_sources: ["hibp", "kev", "assets"],
    },
    "CORR-008": {
      purpose: "Compound risk detector. Fires when the same organization or asset accumulates multiple independent breach/exposure signals across different sources within a short window.",
      detection_logic: "Counts independent (source, signal_type) tuples per organization. ≥4 distinct signals within 14 days triggers the rule. Confidence is set MEDIUM unless any constituent signal is itself HIGH-confidence.",
      why_it_matters: "Multiple independent signals against the same org indicates sustained attacker interest or persistent exposure. Compound risk is more dangerous than the sum of its parts.",
      data_sources: ["hibp", "rss", "shodan"],
    },
    "CORR-005": {
      purpose: "Identifies corporate email addresses appearing in third-party breach data. These addresses are the launch pad for spear-phishing, credential stuffing, and social engineering campaigns.",
      detection_logic: "Filters HIBP/breach results for items where `data_classes` contains email addresses, then matches each address's domain against configured corporate domains.",
      why_it_matters: "Targeted phishing against a known list of corporate identities has a dramatically higher success rate than untargeted campaigns. Mitigation focuses on user awareness and MFA enforcement.",
      data_sources: ["hibp", "assets"],
    },
  }[ruleId] || {};

  return (
    <div className="page" data-screen-label="Finding Detail">
      <button className="btn btn-ghost" onClick={onBack} style={{ marginBottom: 12 }}>
        <Icon name="chevron" size={13} style={{ transform: "rotate(180deg)" }} /> Back to Correlated Findings
      </button>

      <div className="detail-hero">
        <div className="detail-hero-id">FINDING · {f.rule_id}</div>
        <h1 className="detail-hero-title">{f.rule_name}</h1>
        <div className="row-gap">
          <Badge severity={f.risk_label} solid>{f.risk_label}</Badge>
          <span style={{ background: "rgba(255,255,255,0.1)", color: "#fff", padding: "3px 10px", borderRadius: 999, fontSize: 12, fontWeight: 600 }}>Risk Score · {f.risk_score}/100</span>
          {f.kev_confirmed_cves && f.kev_confirmed_cves.length > 0 && (
            <span style={{ background: "rgba(123,47,190,0.25)", color: "#e8d4ff", padding: "3px 10px", borderRadius: 999, fontSize: 12, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 5 }}>
              <Icon name="flame" size={11} /> Actively exploited (KEV)
            </span>
          )}
          <span style={{ marginLeft: "auto", fontSize: 12, color: "rgba(255,255,255,0.7)" }}>Detected · {f.detectedAt}</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Card title="🎯 Objective">
            <p style={{ margin: 0, lineHeight: 1.65, color: "var(--text-2)", fontSize: 14 }}>{docs.purpose || f.description}</p>
          </Card>

          {f.mitre_technique && (
            <Card title="🗺️ MITRE ATT&CK Mapping">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                <div>
                  <div className="section-h">Tactic</div>
                  <span className="mitre-tag" style={{ fontSize: 13, padding: "5px 12px" }}>{f.mitre_tactic}</span>
                </div>
                <div>
                  <div className="section-h">Technique</div>
                  <span className="mitre-tag" style={{ fontSize: 13, padding: "5px 12px" }}>{f.mitre_technique}</span>
                </div>
              </div>
              <div style={{ marginTop: 14, fontSize: 12, color: "var(--text-3)" }}>
                Reference: <a href="https://attack.mitre.org/" target="_blank" style={{ color: "var(--accent-dark)" }}>attack.mitre.org</a>
              </div>
            </Card>
          )}

          <Card title="🧾 Evidence Summary" sub="Every signal contributing to this finding">
            {[
              { field: "matched_exposure", label: "Exposure / breach signals", icon: "eye" },
              { field: "matched_cves", label: "Related CVEs", icon: "bug" },
              { field: "kev_confirmed_cves", label: "Actively exploited (KEV)", icon: "flame" },
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
                    {items.map((e, i) => <div key={i} className="evidence-item">{e}</div>)}
                  </div>
                </div>
              );
            })}
          </Card>

          <Card title="⚙️ Detection Methodology" sub={`Source: analysis/correlator.py → rule ${f.rule_id}`}>
            <p style={{ margin: 0, lineHeight: 1.65, color: "var(--text-2)" }}>{docs.detection_logic || "Detection logic documentation pending."}</p>
          </Card>

          {docs.why_it_matters && (
            <Card title="💡 Why This Matters">
              <p style={{ margin: 0, lineHeight: 1.65, color: "var(--text-2)" }}>{docs.why_it_matters}</p>
            </Card>
          )}

          <Card title="🛠️ Recommended Mitigation">
            <ol style={{ margin: 0, paddingLeft: 20, lineHeight: 1.7, color: "var(--text-2)" }}>
              {parseRec(f.recommendation).map((s, i) => (
                <li key={i} style={{ marginBottom: 6 }}>{s}</li>
              ))}
            </ol>
            <div className="divider" />
            <div className="row-gap">
              <button className={"btn " + (status === "resolved" ? "btn-accent" : "")}
                disabled={saving} onClick={() => changeStatus("resolved")}>
                <Icon name="check" size={13}/>{status === "resolved" ? "Resolved ✓" : "Mark resolved"}
              </button>
              <button className={"btn " + (status === "acknowledged" ? "btn-accent" : "")}
                disabled={saving} onClick={() => changeStatus("acknowledged")}>
                <Icon name="bell" size={13}/>{status === "acknowledged" ? "Acknowledged ✓" : "Acknowledge"}
              </button>
              <button className="btn btn-ghost" disabled={saving}
                onClick={() => changeStatus("false_positive")}>
                {status === "false_positive" ? "Marked false positive ✓" : "Mark as false positive"}
              </button>
              {status !== "open" && (
                <button className="btn btn-ghost" disabled={saving}
                  onClick={() => changeStatus("open")} style={{ marginLeft: "auto" }}>
                  Reopen
                </button>
              )}
            </div>
          </Card>

          {docs.false_positives && (
            <Card title="⚠️ Known False-Positive Conditions">
              <p style={{ margin: 0, lineHeight: 1.65, color: "var(--text-2)" }}>{docs.false_positives}</p>
            </Card>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Card title="📊 Score Breakdown" sub="Every point documented">
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
            <div style={{ marginTop: 14, fontSize: 11.5, color: "var(--text-3)", lineHeight: 1.5 }}>
              <strong>Confidence:</strong> {f.confidence}<br/>
              Driven by source reliability and the number of independent signals supporting the correlation.
            </div>
          </Card>

          <Card title="🖥️ Affected Assets">
            <div className="evidence-list">
              {f.affected_assets.map((a, i) => <div key={i} className="evidence-item">{a}</div>)}
            </div>
            <div style={{ marginTop: 10, fontSize: 11.5, color: "var(--text-3)" }}>
              {{1: "Tier 1 — Crown Jewel (×1.5)", 2: "Tier 2 — Core Infra (×1.2)", 3: "Tier 3 — Standard (×1.0)"}[f.asset_tier]}
            </div>
          </Card>

          {docs.data_sources && docs.data_sources.length > 0 && (
            <Card title="📡 Data Provenance" sub="Every signal traceable to its source">
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {docs.data_sources.map(k => {
                  const src = d.dataSources.find(s => s.key === k);
                  if (!src) return null;
                  return (
                    <div key={k} style={{ padding: "10px 12px", border: "1px solid var(--border)", borderRadius: 8, background: "var(--surface-2)" }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{src.name}</div>
                      <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 3 }}>
                        {src.type} · {src.license} · refresh {src.refresh}
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          <Card title="📋 Finding Status">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {["open", "acknowledged", "resolved", "false_positive"].map(st => (
                <label key={st} style={{ display: "flex", alignItems: "center", gap: 9, padding: "8px 10px", border: "1px solid var(--border)", borderRadius: 7, cursor: saving ? "wait" : "pointer", background: status === st ? "var(--accent-soft)" : "var(--surface)" }}>
                  <input type="radio" name="status" checked={status === st} disabled={saving}
                    onChange={() => changeStatus(st)} />
                  <span className={"status-pill " + (st === "open" ? "open" : st === "acknowledged" ? "ack" : st === "resolved" ? "resolved" : "fp")}>
                    <span className="ind" />{st.replace("_", " ")}
                  </span>
                </label>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

window.FindingDetail = FindingDetail;
