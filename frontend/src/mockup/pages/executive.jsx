// Executive View page
const ExecutiveView = ({ onOpenFinding, onNav }) => {
  const d = window.CFData;
  const { riskScore, summary, delta, findings, trend } = d;

  const scoreColor = riskScore.current >= 65 ? "var(--crit)" : riskScore.current >= 45 ? "var(--high)" : riskScore.current >= 25 ? "var(--med)" : "var(--low)";
  const scoreColorResolved = resolveCSSVar(scoreColor);

  return (
    <div className="page" data-screen-label="Executive View">
      <div className="page-head">
        <div>
          <h1 className="page-title">Executive Security Summary</h1>
          <div className="page-sub">{d.org.name} · <span className="mono">{d.org.scope}</span> · {d.org.environment}</div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={async (e) => {
            const b = e.currentTarget; const o = b.textContent;
            b.disabled = true; b.textContent = "Generating…";
            try { await window.CFApi.downloadReport(); b.textContent = o; }
            catch (err) { b.textContent = "No findings yet"; }
            finally { setTimeout(() => { b.disabled = false; b.textContent = o; }, 1500); }
          }}><Icon name="download" size={14} />Export PDF</button>
          <button className="btn btn-accent" onClick={() => onNav("briefing")}><Icon name="sparkles" size={14} />Generate briefing</button>
        </div>
      </div>

      {/* ── Hero: risk score + KPIs ─────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 16, marginBottom: 16 }}>
        <Card title="Aggregate Risk Score" sub="Weighted across all findings · updated every pipeline run">
          <div className="score-big">
            <ScoreRing value={riskScore.current} color={scoreColorResolved} />
            <div>
              <div className="row-gap" style={{ marginBottom: 10 }}>
                <Badge severity={riskScore.label === "ELEVATED" ? "HIGH" : "MEDIUM"} solid>{riskScore.label}</Badge>
                <span className="kpi-delta up" style={{ fontSize: 13, display: "inline-flex", alignItems: "center", gap: 3 }}>
                  <Icon name="arrowUp" size={12} /> {riskScore.current - riskScore.previous} pts
                </span>
                <span style={{ fontSize: 12, color: "var(--text-3)" }}>vs. previous run</span>
              </div>
              <div className="score-band">
                <span className={"seg" + (riskScore.current > 0 ? " active low" : "")} />
                <span className={"seg" + (riskScore.current >= 25 ? " active med" : "")} />
                <span className={"seg" + (riskScore.current >= 45 ? " active high" : "")} />
                <span className={"seg" + (riskScore.current >= 65 ? " active crit" : "")} />
              </div>
              <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 8 }}>
                Low · Medium · High · Critical (0–100 scale)
              </div>
              <div style={{ marginTop: 18, paddingTop: 14, borderTop: "1px solid var(--border)" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, fontSize: 13 }}>
                  <div>
                    <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 2 }}>Peer median <span className="illus-tag">illustrative</span></div>
                    <div style={{ fontWeight: 600 }}>{riskScore.benchmark} <span style={{ color: "var(--text-3)", fontWeight: 400, fontSize: 12 }}>· FinSrv segment</span></div>
                  </div>
                  <div>
                    <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 2 }}>Posture vs. peer <span className="illus-tag">illustrative</span></div>
                    <div style={{ fontWeight: 600, color: "var(--crit)" }}>+{riskScore.current - riskScore.benchmark} pts above median</div>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-4)", marginTop: 8 }}>Peer benchmarking is illustrative — no external peer dataset is included in this demo.</div>
              </div>
            </div>
          </div>
        </Card>

        <Card title="30-Day Trend" sub={<span>Daily severity distribution <span className="illus-tag">illustrative</span></span>}>
          <TrendBars trend={trend} />
          <div className="divider" />
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 12.5 }}>
            <div>
              <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em" }}>Resolved (7d)</div>
              <div style={{ fontWeight: 700, fontSize: 17, marginTop: 2, color: "var(--low)" }}>{delta.resolved}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em" }}>New (7d)</div>
              <div style={{ fontWeight: 700, fontSize: 17, marginTop: 2 }}>{delta.new}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em" }}>Escalated (7d)</div>
              <div style={{ fontWeight: 700, fontSize: 17, marginTop: 2 }}>{delta.escalated}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em" }}>MTTR <span className="illus-tag">illus.</span></div>
              <div style={{ fontWeight: 700, fontSize: 17, marginTop: 2 }}>4.2<span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-3)" }}> days</span></div>
            </div>
          </div>
        </Card>
      </div>

      {/* ── KPIs ─────────────────────────────────────────────────── */}
      <div className="kpi-grid">
        <div className="kpi">
          <div className="kpi-label">Total findings</div>
          <div className="kpi-value">{summary.total}</div>
          <div className="kpi-meta">correlated findings this run</div>
        </div>
        <div className="kpi">
          <div className="kpi-label"><span className="kpi-dot" style={{background:"var(--crit)"}}/>Critical</div>
          <div className="kpi-value" style={{ color: "var(--crit)" }}>{summary.critical}</div>
          <div className="kpi-meta">highest-severity findings</div>
        </div>
        <div className="kpi">
          <div className="kpi-label"><span className="kpi-dot" style={{background:"var(--high)"}}/>High</div>
          <div className="kpi-value" style={{ color: "var(--high)" }}>{summary.high}</div>
          <div className="kpi-meta">high-severity findings</div>
        </div>
        <div className="kpi">
          <div className="kpi-label"><span className="kpi-dot" style={{background:"var(--med)"}}/>Medium</div>
          <div className="kpi-value" style={{ color: "var(--med)" }}>{summary.medium}</div>
          <div className="kpi-meta">medium-severity findings</div>
        </div>
        <div className="kpi">
          <div className="kpi-label"><span className="kpi-dot" style={{background:"var(--kev)"}}/>KEV-confirmed</div>
          <div className="kpi-value" style={{ color: "var(--kev)" }}>{[...new Set(findings.flatMap(f => f.kev_confirmed_cves || []))].length}</div>
          <div className="kpi-meta">actively exploited (CISA KEV)</div>
        </div>
      </div>

      {/* ── Delta alerts ─────────────────────────────────────────── */}
      {delta.resolved > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="alert info">
            <Icon name="check" size={16} style={{ marginTop: 1, color: "var(--low)" }} />
            <div>
              <div className="alert-strong">{delta.resolved} findings resolved since the last pipeline run.</div>
              <div style={{ fontSize: 12, marginTop: 2, color: "var(--text-3)" }}>
                Resolved: {delta.resolvedIds.map(id => <code key={id} className="mono" style={{ marginRight: 8 }}>{id}</code>)}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Distribution + Top findings ──────────────────────────── */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <Card title="Highest-Risk Findings" sub="Click for full evidence, methodology, and mitigation"
          action={<button className="btn btn-sm btn-ghost" onClick={() => onNav("findings")}>View all <Icon name="chevron" size={12}/></button>}
          padded={false}>
          <div className="list">
            {findings.map(f => (
              <div className="list-row" key={f.rule_id} onClick={() => onOpenFinding(f.rule_id)}>
                <div className={"list-rail " + sevClass(f.risk_label)} />
                <div>
                  <div className="list-title">{f.rule_name}</div>
                  <div className="list-meta">
                    <Badge severity={f.risk_label} size="sm" />
                    <span className="mono" style={{ fontSize: 11.5, color: "var(--text-4)" }}>{f.rule_id}</span>
                    <span>·</span>
                    <span>{f.mitre_technique}</span>
                    {f.kev_confirmed_cves && f.kev_confirmed_cves.length > 0 && (<><span>·</span><KevBadge /></>)}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  <div className="list-score">{f.risk_score} / 100</div>
                  <Icon name="chevron" size={14} style={{ color: "var(--text-4)" }} />
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Risk Distribution" sub="Across all open findings">
          <SeverityDonut summary={summary} />
          <div className="divider" />
          <DistBar data={[
            { label: "Critical", value: summary.critical, color: resolveCSSVar("var(--crit)") },
            { label: "High",     value: summary.high,     color: resolveCSSVar("var(--high)") },
            { label: "Medium",   value: summary.medium,   color: resolveCSSVar("var(--med)") },
            { label: "Low",      value: summary.low || 0, color: resolveCSSVar("var(--low)") },
          ]} />
        </Card>
      </div>

      {/* ── Top recommendations ──────────────────────────────────── */}
      <div className="grid-2">
        <Card title="Top Recommended Actions" sub="From critical and high findings"
          action={<button className="btn btn-sm btn-ghost" onClick={() => onNav("briefing")}>Open briefing <Icon name="external" size={12}/></button>}>
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {findings.filter(f => f.risk_label === "CRITICAL" || f.risk_label === "HIGH").slice(0, 2).map((f, i) => (
              <div key={f.rule_id} style={{ borderLeft: `3px solid var(--${sevClass(f.risk_label)})`, paddingLeft: 14 }}>
                <div className="row-gap" style={{ marginBottom: 6 }}>
                  <Badge severity={f.risk_label} size="sm" />
                  <span style={{ fontWeight: 700, fontSize: 13.5 }}>{f.rule_name}</span>
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-4)" }}>{f.rule_id}</span>
                </div>
                <ol style={{ margin: "8px 0 0", paddingLeft: 18, color: "var(--text-2)", lineHeight: 1.55, fontSize: 13 }}>
                  {parseRec(f.recommendation).slice(0, 4).map((s, j) => <li key={j} style={{ marginBottom: 3 }}>{s}</li>)}
                </ol>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Asset Criticality Tiers" sub="Score multiplier applied per tier">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { tier: 1, label: "Tier 1 — Crown Jewel", mult: "1.5", sev: "CRITICAL" },
              { tier: 2, label: "Tier 2 — Core Infrastructure", mult: "1.2", sev: "HIGH" },
              { tier: 3, label: "Tier 3 — Standard", mult: "1.0", sev: "MEDIUM" },
            ].map(t => {
              const tierFindings = findings.filter(f => f.asset_tier === t.tier);
              const assets = [...new Set(tierFindings.flatMap(f => f.affected_assets || []))];
              return (
                <div key={t.tier} style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 14, alignItems: "center", padding: "12px 14px", background: "var(--surface-2)", borderRadius: 8, border: "1px solid var(--border)" }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: `var(--${sevClass(t.sev)}-soft)`, color: `var(--${sevClass(t.sev)})`, display: "grid", placeItems: "center", fontWeight: 700, fontSize: 14 }}>T{t.tier}</div>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{t.label}</div>
                    <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 2 }}>
                      {tierFindings.length} finding(s){assets.length ? " · " + assets.join(", ") : ""}
                    </div>
                  </div>
                  <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: `var(--${sevClass(t.sev)})` }}>×{t.mult}</div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-3)" }}>
            Risk scores for findings on higher-tier assets are amplified by the multiplier shown. Counts reflect findings in this run.
          </div>
        </Card>
      </div>
    </div>
  );
};

function parseRec(text) {
  if (!text) return [];
  text = text.trim();
  if (/\d+\.\s+/.test(text)) {
    return text.split(/\s*\d+\.\s+/).filter(Boolean).map(s => s.trim().replace(/\.$/, ""));
  }
  return text.split(". ").filter(Boolean).map(s => s.trim().replace(/\.$/, ""));
}

Object.assign(window, { ExecutiveView, parseRec });
