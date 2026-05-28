// Methodology + Architecture pages
const MethodologyPage = () => {
  const d = window.CFData;
  return (
    <div className="page" data-screen-label="Methodology">
      <div className="page-head">
        <div>
          <h1 className="page-title">Methodology &amp; Transparency</h1>
          <div className="page-sub">Every score, every signal, every data source — fully documented.</div>
        </div>
      </div>

      <Card title="About This Demo" sub="What is real vs. illustrative">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
          <div>
            <div className="section-h" style={{ color: "var(--low)" }}>Real pipeline output</div>
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, color: "var(--text-2)", fontSize: 13 }}>
              <li>Correlated findings, risk scores, and full score breakdowns</li>
              <li>CVEs from the NIST NVD API and entries from the CISA KEV catalog</li>
              <li>Security news from public RSS feeds</li>
              <li>TCP port scans of local lab Docker containers only</li>
              <li>Correlation rules and data-source provenance</li>
            </ul>
          </div>
          <div>
            <div className="section-h" style={{ color: "var(--high)" }}>Illustrative / synthetic</div>
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, color: "var(--text-2)", fontSize: 13 }}>
              <li><strong>30-day trend</strong> and <strong>peer benchmark</strong> — shaped to the current run; no external peer dataset</li>
              <li><strong>MTTR</strong> and <strong>briefing history</strong> — sample values showing format</li>
              <li><strong>Breach &amp; exposure records</strong> — clearly-labeled synthetic, generated locally</li>
              <li><strong>Distribution channels</strong> (Slack / email / ticketing) — roadmap, not wired</li>
            </ul>
          </div>
        </div>
        <div className="divider" />
        <div style={{ fontSize: 12.5, color: "var(--text-3)", lineHeight: 1.6 }}>
          This is a static portfolio build. Data was generated from a real local pipeline run and frozen into the page.
          All scanning is lab/localhost only — CyberFusion never targets external infrastructure.
          Anything not produced by the pipeline is tagged <span className="illus-tag">illustrative</span> in the UI.
        </div>
      </Card>

      <div style={{ height: 16 }} />

      <div className="alert info" style={{ marginBottom: 16 }}>
        <Icon name="info" size={15} style={{ marginTop: 1 }} />
        <div>
          <span className="alert-strong">Auditability is the design principle.</span> Every correlation rule is open code, every data source publicly verifiable, and every risk score carries its breakdown.
        </div>
      </div>

      {/* Pipeline overview */}
      <Card title="Pipeline Overview" sub="Collect → Normalize → Correlate → Score → Visualize">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
          {[
            { step: "Collect", desc: "5 public APIs + lab scan", icon: "feed" },
            { step: "Normalize", desc: "Unified schema across sources", icon: "list" },
            { step: "Correlate", desc: "8 detection rules", icon: "link" },
            { step: "Score", desc: "Weighted explainable formula", icon: "flask" },
            { step: "Visualize", desc: "Dashboard · PDF report · briefing", icon: "eye" },
          ].map((s, i) => (
            <div key={i} style={{ padding: "14px 14px", border: "1px solid var(--border)", borderRadius: 10, background: "var(--surface-2)", position: "relative" }}>
              <div style={{ width: 28, height: 28, borderRadius: 7, background: "var(--accent-soft)", color: "var(--accent-dark)", display: "grid", placeItems: "center" }}>
                <Icon name={s.icon} size={14} />
              </div>
              <div style={{ fontWeight: 700, fontSize: 13, marginTop: 10 }}>{i + 1}. {s.step}</div>
              <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 3, lineHeight: 1.4 }}>{s.desc}</div>
              {i < 4 && <div style={{ position: "absolute", right: -8, top: "50%", transform: "translateY(-50%)", color: "var(--text-4)", zIndex: 1 }}><Icon name="chevron" size={14}/></div>}
            </div>
          ))}
        </div>
      </Card>

      <div style={{ height: 16 }} />

      {/* Risk scoring */}
      <Card title="Risk Scoring Formula" sub="Capped at 100. Mapped to label thresholds: ≥65 CRITICAL · ≥45 HIGH · ≥25 MEDIUM · &lt;25 LOW.">
        <div style={{ background: "var(--navy-900)", color: "#c5cbdb", padding: 18, borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, lineHeight: 1.65, marginBottom: 14 }}>
          Score = (base_severity + confidence_bonus + rule_weight_bonus + evidence_bonus)<br/>
          {"        "}× asset_criticality_multiplier&nbsp;&nbsp;[1.0 – 1.5×]<br/>
          {"        "}+ kev_bonus&nbsp;&nbsp;[+20 if actively exploited]
        </div>
        <table className="data" style={{ border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
          <thead><tr><th>Factor</th><th>Range</th><th>Drives</th></tr></thead>
          <tbody>
            <tr><td>Base severity</td><td className="mono">5–40</td><td style={{ color: "var(--text-2)" }}>CRITICAL / HIGH / MEDIUM / LOW from the rule</td></tr>
            <tr><td>Confidence bonus</td><td className="mono">0–10</td><td style={{ color: "var(--text-2)" }}>How certain the correlation rule is</td></tr>
            <tr><td>Rule importance</td><td className="mono">0–25</td><td style={{ color: "var(--text-2)" }}>Some rules are inherently higher priority</td></tr>
            <tr><td>Evidence count</td><td className="mono">0–12</td><td style={{ color: "var(--text-2)" }}>More corroborating signals → higher score</td></tr>
            <tr><td>Asset multiplier</td><td className="mono">1.0–1.5×</td><td style={{ color: "var(--text-2)" }}>Tier-1 assets (VPN, DC) amplify the score</td></tr>
            <tr><td>KEV bonus</td><td className="mono">+20</td><td style={{ color: "var(--text-2)" }}>Active CISA exploitation overrides everything</td></tr>
          </tbody>
        </table>
      </Card>

      <div style={{ height: 16 }} />

      {/* Rule catalog */}
      <Card title="Correlation Rule Catalog" sub={`${d.ruleCatalog.length} rules covering the highest-impact signal combinations`} padded={false}>
        <table className="data">
          <thead><tr><th>Rule</th><th>Name</th><th>Purpose</th><th>Weight</th></tr></thead>
          <tbody>
            {d.ruleCatalog.map(r => (
              <tr key={r.id}>
                <td><span className="mono" style={{ fontWeight: 600 }}>{r.id}</span></td>
                <td style={{ fontWeight: 600 }}>{r.name}</td>
                <td style={{ color: "var(--text-2)", maxWidth: 500 }}>{r.purpose}</td>
                <td className="mono" style={{ fontWeight: 700 }}>{r.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <div style={{ height: 16 }} />

      {/* Data sources */}
      <Card title="Data Sources" sub="All sources are public APIs or internal lab data" padded={false}>
        <table className="data">
          <thead><tr><th>Source</th><th>Type</th><th>License</th><th>Refresh</th><th>Description</th></tr></thead>
          <tbody>
            {d.dataSources.map(s => (
              <tr key={s.key}>
                <td style={{ fontWeight: 600 }}>{s.name}</td>
                <td><span className="chip">{s.type}</span></td>
                <td style={{ color: "var(--text-2)" }}>{s.license}</td>
                <td className="mono" style={{ color: "var(--text-3)", fontSize: 12 }}>{s.refresh}</td>
                <td style={{ color: "var(--text-2)", maxWidth: 380 }}>{s.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
};

const ArchitecturePage = () => {
  const d = window.CFData;
  return (
    <div className="page" data-screen-label="Architecture">
      <div className="page-head">
        <div>
          <h1 className="page-title">System Architecture</h1>
          <div className="page-sub">How CyberFusion works — for demos, interviews, and portfolio reviewers.</div>
        </div>
      </div>

      <Card title="Module Status" sub="Live health of each pipeline component" padded={false}>
        <table className="data">
          <thead><tr><th>Module</th><th>Purpose</th><th>Records</th><th>Last run</th><th>Status</th></tr></thead>
          <tbody>
            {d.pipelineModules.map(m => (
              <tr key={m.name}>
                <td className="mono" style={{ fontWeight: 600 }}>{m.name}.py</td>
                <td style={{ color: "var(--text-2)" }}>{m.description}</td>
                <td className="mono">{m.records}</td>
                <td className="mono" style={{ color: "var(--text-3)", fontSize: 12 }}>{m.lastRun}</td>
                <td>
                  {m.health === "ok" && <span className="status-pill resolved"><span className="ind"/>Healthy</span>}
                  {m.health === "synthetic" && <span className="status-pill ack"><span className="ind"/>Synthetic data</span>}
                  {m.health === "error" && <span className="status-pill open"><span className="ind"/>Error</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <div style={{ height: 16 }} />

      <div className="grid-2">
        <Card title="Ethics &amp; Safety" sub="Hard boundaries baked into the pipeline">
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, color: "var(--text-2)" }}>
            <li>All TCP scans target localhost + Docker lab only — never external infrastructure.</li>
            <li>Breach data: HaveIBeenPwned public API per ToS, or clearly-labeled synthetic.</li>
            <li>No credentials stored or displayed at any point.</li>
            <li>AI briefing uses only your own local intelligence data as context.</li>
          </ul>
        </Card>
        <Card title="How CyberFusion Differs" sub="Compared to opaque commercial platforms">
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, color: "var(--text-2)" }}>
            <li>Every correlation rule is open Python — readable, modifiable, testable.</li>
            <li>Every data source is publicly verifiable — no proprietary feeds, no vendor lock-in.</li>
            <li>Every risk score has a published breakdown — no opaque ML models.</li>
            <li>Every finding lists its data provenance — you see exactly where each signal came from.</li>
          </ul>
        </Card>
      </div>

      <div style={{ height: 16 }} />

      <Card title="Cron Scheduler" sub="Hourly auto-runs keep the dashboard fresh">
        <div style={{ background: "var(--navy-900)", color: "#c5cbdb", padding: 18, borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 12.5, lineHeight: 1.6 }}>
          <span style={{ color: "var(--accent)" }}>$</span> crontab -e<br/>
          <span style={{ color: "var(--text-4)" }}># Add this line:</span><br/>
          0 * * * * cd ~/cyberfusion-complete &amp;&amp; source venv/bin/activate \<br/>
          {"        "}&amp;&amp; python run_pipeline.py --quick &gt;&gt; data/pipeline.log 2&gt;&amp;1
        </div>
      </Card>
    </div>
  );
};

Object.assign(window, { MethodologyPage, ArchitecturePage });
