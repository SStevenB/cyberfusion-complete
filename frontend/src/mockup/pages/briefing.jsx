// AI Briefing page
const BriefingPage = () => {
  const d = window.CFData;
  const [briefing, setBriefing] = useState(d.briefing);
  const [generating, setGenerating] = useState(false);
  const [liveText, setLiveText] = useState(null);   // markdown from a fresh run
  const [status, setStatus] = useState(null);       // {backend, ollama, ...}
  const [tab, setTab] = useState("brief");
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState(null);   // null = not loaded yet

  // Build the export-prompt text once so Copy + Download share it.
  const promptText = `You are a senior CTI analyst. Given the live pipeline data below, write a
structured daily briefing with these sections:

  1. Overall Risk Level
  2. What Requires Attention
  3. Active Exploitation Activity
  4. Exposed Services
  5. Recommended Actions

Findings:
${JSON.stringify(d.findings.map(f => ({ id: f.rule_id, name: f.rule_name, sev: f.risk_label, score: f.risk_score })), null, 2)}

KEV-confirmed CVEs in scope: ${d.findings.flatMap(f => f.kev_confirmed_cves || []).join(", ") || "(none)"}

Keep total length under 400 words.`;

  // Compose the current briefing as markdown for download.
  const briefingMarkdown = () => {
    const lines = [`# Daily Security Briefing`, ``,
      `Generated: ${briefing.generatedAt} · Backend: ${briefing.backend} · Risk: ${briefing.overallRisk}`, ``];
    if (liveText) { lines.push(liveText, ``); }
    briefing.sections.forEach((sec, i) => {
      lines.push(`## ${i + 1}. ${sec.title}`, ``, sec.body, ``);
    });
    return lines.join("\n");
  };

  const downloadText = (filename, text, mime) => {
    const blob = new Blob([text], { type: mime || "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  };

  const copyPrompt = async () => {
    try { await navigator.clipboard.writeText(promptText); setCopied(true); setTimeout(() => setCopied(false), 1500); }
    catch { downloadText("cyberfusion_briefing_prompt.txt", promptText); }
  };

  useEffect(() => {
    window.CFApi.briefingStatus().then(setStatus).catch(() => {});
  }, []);

  // Load history lazily the first time the user opens the History tab.
  useEffect(() => {
    if (tab === "history" && history === null) {
      window.CFApi.briefingHistory()
        .then(d => setHistory(d.briefings || []))
        .catch(() => setHistory([]));
    }
  }, [tab]);

  const downloadHistoryItem = async (filename) => {
    try {
      const r = await window.CFApi.getBriefing(filename);
      downloadText(filename, r.text, "text/markdown");
    } catch (e) { alert("Could not download: " + String(e)); }
  };

  const openHistoryItem = async (filename) => {
    try {
      const r = await window.CFApi.getBriefing(filename);
      setLiveText(r.text);
      setBriefing({ ...briefing, backend: "saved", generatedAt: filename });
      setTab("brief");
    } catch (e) { alert("Could not open: " + String(e)); }
  };

  const onGenerate = async () => {
    setGenerating(true);
    try {
      const r = await window.CFApi.generateBriefing();   // calls Ollama if running
      setLiveText(r.text);
      setBriefing({ ...briefing, backend: r.backend, generatedAt: "just now" });
    } catch (e) {
      setLiveText("Briefing generation failed: " + String(e));
    }
    setGenerating(false);
  };

  return (
    <div className="page" data-screen-label="AI Briefing">
      <div className="page-head">
        <div>
          <h1 className="page-title">Daily Security Briefing</h1>
          <div className="page-sub">Structured threat summary generated from current pipeline data — grounded in live findings, never hallucinated.</div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => downloadText("cyberfusion_briefing.md", briefingMarkdown(), "text/markdown")}><Icon name="download" size={14}/>Download .md</button>
          <button className="btn btn-accent" onClick={onGenerate} disabled={generating}>
            <Icon name="sparkles" size={14}/>{generating ? "Generating…" : "Generate briefing"}
          </button>
        </div>
      </div>

      {/* Status row */}
      <div className="grid-3" style={{ marginBottom: 16 }}>
        <Card>
          <div className="section-h">Backend</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: 50, background: "var(--low)", boxShadow: "0 0 0 4px rgba(22,163,74,0.15)" }} />
            <strong style={{ fontSize: 14 }}>{status ? status.backend : briefing.backend}</strong>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 6 }}>
            {status ? (status.ollama ? "Ollama running (local, free)" :
              status.anthropic ? "Anthropic API key configured" :
              "No local LLM running — using pipeline-derived template. Start Ollama for AI-written briefings.")
              : "Checking backend…"}
          </div>
        </Card>
        <Card>
          <div className="section-h">Last generated</div>
          <div style={{ fontWeight: 700, fontSize: 14 }}>{briefing.generatedAt}</div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 6 }}>Pipeline run: {d.org.lastRun}</div>
        </Card>
        <Card>
          <div className="section-h">Assessed risk</div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Badge severity="HIGH" solid>{briefing.overallRisk}</Badge>
            <span style={{ fontSize: 12, color: "var(--text-3)" }}>from latest run</span>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 6 }}>Generated from current pipeline data</div>
        </Card>
      </div>

      <div className="tabs">
        <button className={"tab" + (tab === "brief" ? " active" : "")} onClick={() => setTab("brief")}><Icon name="sparkles" size={13}/>Briefing</button>
        <button className={"tab" + (tab === "prompt" ? " active" : "")} onClick={() => setTab("prompt")}><Icon name="file" size={13}/>Export prompt</button>
        <button className={"tab" + (tab === "history" ? " active" : "")} onClick={() => setTab("history")}><Icon name="list" size={13}/>Past briefings</button>
      </div>

      {tab === "brief" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>
          <Card>
            {liveText && (
              <div style={{ marginBottom: 18, padding: "12px 14px", background: "var(--surface-2)",
                border: "1px solid var(--border)", borderRadius: 8, whiteSpace: "pre-wrap",
                fontSize: 13.5, lineHeight: 1.6, color: "var(--text-1)" }}>
                <div className="section-h" style={{ marginBottom: 8 }}>Freshly generated ({briefing.backend})</div>
                {liveText}
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
              {briefing.sections.map((s, i) => (
                <div key={i}>
                  <div className="row-gap" style={{ marginBottom: 6 }}>
                    <span style={{ width: 24, height: 24, borderRadius: 6, background: "var(--accent-soft)", color: "var(--accent-dark)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700 }}>{i + 1}</span>
                    <h3 style={{ margin: 0, fontSize: 15, letterSpacing: "-0.01em" }}>{s.title}</h3>
                  </div>
                  <p style={{ margin: 0, color: "var(--text-2)", lineHeight: 1.65, fontSize: 14, paddingLeft: 32 }}>{s.body}</p>
                </div>
              ))}
            </div>
          </Card>

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Card title="Context used" sub="Real pipeline data only">
              <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
                {[
                  { label: "Findings", value: d.findings.length, icon: "link" },
                  { label: "Recent CVEs", value: d.cves.length, icon: "bug" },
                  { label: "KEV entries", value: d.kev.length, icon: "flame" },
                  { label: "Open ports", value: d.ports.reduce((s, h) => s + h.openCount, 0), icon: "network" },
                  { label: "News items", value: d.news.length, icon: "feed" },
                  { label: "Breach signals", value: d.breaches.length, icon: "file" },
                ].map(r => (
                  <div key={r.label} style={{ display: "flex", alignItems: "center", gap: 9 }}>
                    <span style={{ width: 26, height: 26, borderRadius: 6, background: "var(--surface-2)", border: "1px solid var(--border)", display: "grid", placeItems: "center", color: "var(--text-3)" }}>
                      <Icon name={r.icon} size={12} />
                    </span>
                    <span style={{ flex: 1, color: "var(--text-2)" }}>{r.label}</span>
                    <span className="mono" style={{ fontWeight: 700 }}>{r.value}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Distribution" sub="Real channels — Slack is wired; others on the roadmap">
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ padding: "10px 12px", border: "1px solid var(--border)", borderRadius: 7, background: "var(--surface-2)" }}>
                  <div className="row-gap" style={{ marginBottom: 4 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, flex: 1 }}>Slack alerts</div>
                    <button className="btn btn-sm btn-accent" onClick={async (e) => {
                      const b = e.currentTarget; const o = b.textContent;
                      b.disabled = true; b.textContent = "Sending…";
                      try {
                        const r = await window.CFApi.notifySlack();
                        b.textContent = r.sent ? "Sent ✓" : "Not configured";
                        if (!r.sent) alert(r.message);
                      } catch (err) { b.textContent = "Failed"; }
                      finally { setTimeout(() => { b.disabled = false; b.textContent = o; }, 2200); }
                    }}>Send now</button>
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-3)" }}>
                    Uses <code className="mono">notifier.py</code> + incoming-webhook. Configure
                    <code className="mono"> slack.webhook_url</code> in <code className="mono">config/config.yaml</code>.
                  </div>
                </div>

                <div style={{ padding: "10px 12px", border: "1px dashed var(--border)", borderRadius: 7, background: "var(--surface)", opacity: .75 }}>
                  <div className="row-gap" style={{ marginBottom: 4 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, flex: 1 }}>Email digest</div>
                    <span className="chip">roadmap</span>
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-3)" }}>Bundle the PDF report with the briefing to a distribution list.</div>
                </div>

                <div style={{ padding: "10px 12px", border: "1px dashed var(--border)", borderRadius: 7, background: "var(--surface)", opacity: .75 }}>
                  <div className="row-gap" style={{ marginBottom: 4 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, flex: 1 }}>Ticket auto-creation</div>
                    <span className="chip">roadmap</span>
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-3)" }}>Open Jira/Linear issues for criticals via API.</div>
                </div>
              </div>
            </Card>
          </div>
        </div>
      )}

      {tab === "prompt" && (
        <Card title="Export prompt" sub="Paste into Claude.ai / ChatGPT / Gemini to generate the briefing manually">
          <div style={{ background: "var(--navy-900)", color: "#c5cbdb", padding: 18, borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", maxHeight: 360, overflow: "auto" }}>
{promptText}
          </div>
          <div className="row-gap" style={{ marginTop: 12 }}>
            <button className="btn btn-primary" onClick={copyPrompt}>{copied ? "Copied ✓" : "Copy to clipboard"}</button>
            <button className="btn" onClick={() => downloadText("cyberfusion_briefing_prompt.txt", promptText)}><Icon name="download" size={13}/>Download .txt</button>
          </div>
        </Card>
      )}

      {tab === "history" && (
        <Card padded={false} title="Past briefings" sub="Real saved briefings from data/outputs/briefings/">
          {history === null && (
            <div className="empty" style={{ padding: 28 }}>Loading saved briefings…</div>
          )}
          {history !== null && history.length === 0 && (
            <div className="empty" style={{ padding: 28 }}>
              No saved briefings yet. Click <strong>Generate briefing</strong> above —
              every generated briefing is saved here.
            </div>
          )}
          {history !== null && history.length > 0 && (
            <table className="data">
              <thead><tr><th>Generated</th><th>Filename</th><th>Size</th><th>Preview</th><th style={{textAlign:"right"}}></th></tr></thead>
              <tbody>
                {history.map((b, i) => (
                  <tr key={b.filename}>
                    <td className="mono">{b.generated_at}</td>
                    <td className="mono" style={{ color: "var(--text-3)", fontSize: 12 }}>{b.filename}</td>
                    <td className="mono" style={{ color: "var(--text-3)" }}>{(b.size_bytes/1024).toFixed(1)} KB</td>
                    <td style={{ color: "var(--text-2)", maxWidth: 360 }}>{b.preview || "—"}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <button className="btn btn-sm btn-ghost" onClick={() => openHistoryItem(b.filename)}>Open</button>
                      <button className="btn btn-sm btn-ghost" onClick={() => downloadHistoryItem(b.filename)} style={{ marginLeft: 6 }}>
                        <Icon name="download" size={12}/>Download
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
};

window.BriefingPage = BriefingPage;
