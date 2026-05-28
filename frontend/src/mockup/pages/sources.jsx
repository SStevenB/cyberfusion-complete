// pages/sources.jsx — unified Data Sources page (source registry + upload),
// styled with the real design system (Card / Badge / Icon / .tabs / .btn / .data).
const SourcesPage = () => {
  const [sources, setSources] = useState([]);
  const [types, setTypes] = useState([]);
  const [ws, setWs] = useState(null);
  const [uploads, setUploads] = useState([]);
  const [tab, setTab] = useState("manage");
  const [msg, setMsg] = useState(null);

  const reload = async () => {
    try {
      const [s, t, w, u] = await Promise.all([
        window.CFApi.sources(), window.CFApi.sourceTypes(),
        window.CFApi.workspace(), window.CFApi.listUploads()]);
      setSources(s.sources || []); setTypes(t.source_types || []);
      setWs(w); setUploads(u.uploads || []);
    } catch (e) { setMsg({ kind: "err", text: String(e) }); }
  };
  useEffect(() => { reload(); }, []);

  const totalRecords = uploads.reduce((n, u) => n + (u.record_count || 0), 0);

  return (
    <div className="page" data-screen-label="Data Sources">
      <div className="page-head">
        <div>
          <h1 className="page-title">Data Sources</h1>
          <div className="page-sub">
            Connect or upload authorized evidence · <span className="mono">{ws ? ws.scope : ""}</span>
            {ws && <> · {(ws.mode || "demo").toUpperCase()} mode</>}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-accent" onClick={() => setTab("add")}>
            <Icon name="plus" size={14} />Add source
          </button>
        </div>
      </div>

      <div className="alert info" style={{ marginBottom: 14 }}>
        <Icon name="info" size={15} style={{ marginTop: 1 }} />
        <div><span className="alert-strong">Two ways to connect.</span> An API connector for supported
        vendors, or manual file upload as a universal fallback. Upload mode is fully implemented for
        every source; live API connectors are clearly labeled where scaffolded. Upload only data for
        systems and domains you are authorized to assess.</div>
      </div>

      {msg && (
        <div className={"alert " + (msg.kind === "ok" ? "info" : "warn")} style={{ marginBottom: 14 }}>
          <Icon name={msg.kind === "ok" ? "check" : "info"} size={15} style={{ marginTop: 1 }} />
          <div>{msg.text}</div>
        </div>
      )}

      <div className="tabs">
        <button className={"tab" + (tab === "manage" ? " active" : "")} onClick={() => setTab("manage")}>
          <Icon name="server" size={13} /> Configured Sources <span className="tab-count">{sources.length}</span>
        </button>
        <button className={"tab" + (tab === "upload" ? " active" : "")} onClick={() => setTab("upload")}>
          <Icon name="download" size={13} /> Upload Evidence <span className="tab-count">{uploads.length}</span>
        </button>
        <button className={"tab" + (tab === "add" ? " active" : "")} onClick={() => setTab("add")}>
          <Icon name="plus" size={13} /> Add Source
        </button>
      </div>

      {tab === "add" &&
        <AddSourceForm types={types} onAdded={() => { reload(); setTab("manage"); setMsg({ kind: "ok", text: "Source added." }); }} />}
      {tab === "manage" &&
        <SourceList sources={sources} types={types} onChange={reload} setMsg={setMsg} />}
      {tab === "upload" &&
        <UploadPanel types={types} uploads={uploads} totalRecords={totalRecords}
          onChange={reload} setMsg={setMsg} />}
    </div>
  );
};

// ── Add a source ────────────────────────────────────────────────────────────
const AddSourceForm = ({ types, onAdded }) => {
  const [stype, setStype] = useState(types[0]?.key || "");
  const [mode, setMode] = useState("upload");
  const [name, setName] = useState("");
  const meta = types.find(t => t.key === stype);
  useEffect(() => { if (meta) { setMode(meta.modes[0]); setName(meta.label); } }, [stype]);

  const submit = async () => {
    try { await window.CFApi.addSource({ source_type: stype, name: name || meta.label, mode }); onAdded(); }
    catch (e) { alert(String(e)); }
  };

  return (
    <Card title="Add a data source" sub="Register a connector or an upload-backed source">
      <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 560 }}>
        <label className="field">
          <span className="field-label">Source type</span>
          <select className="select" value={stype} onChange={e => setStype(e.target.value)}>
            {types.map(t => <option key={t.key} value={t.key}>{t.label} · {t.category}</option>)}
          </select>
        </label>

        {meta && <>
          <div style={{ fontSize: 13, color: "var(--text-2)", lineHeight: 1.5 }}>{meta.description}</div>
          <div className="row-gap" style={{ fontSize: 12.5, color: "var(--text-3)" }}>
            <Icon name="shield" size={13} /> {meta.authorization_note}
          </div>

          <label className="field">
            <span className="field-label">Connection mode</span>
            <div className="tabs" style={{ marginBottom: 0 }}>
              {meta.modes.map(m => (
                <button key={m} type="button"
                  className={"tab" + (mode === m ? " active" : "")} onClick={() => setMode(m)}>
                  <Icon name={m === "connector" ? "link" : "download"} size={13} />
                  {m === "connector" ? "API connector" : "File upload"}
                </button>
              ))}
            </div>
          </label>

          {mode === "connector" && meta.connector_status === "scaffolded" &&
            <div className="alert warn">
              <Icon name="info" size={15} style={{ marginTop: 1 }} />
              <div><span className="alert-strong">Connector scaffolded.</span> Configuration and
              connection-test work; live API fetch isn't enabled in this build. Upload mode for this
              source is fully working.</div>
            </div>}

          <label className="field">
            <span className="field-label">Display name</span>
            <input className="input" value={name} onChange={e => setName(e.target.value)} />
          </label>

          <div className="row-gap">
            <button className="btn btn-accent" onClick={submit}>
              <Icon name="plus" size={14} />Add source
            </button>
          </div>
        </>}
      </div>
    </Card>
  );
};

// ── Configured source list (grouped by category) ─────────────────────────────
const SourceList = ({ sources, types, onChange, setMsg }) => {
  if (!sources.length)
    return <Card><div className="empty">No sources configured yet. Use <strong>Add Source</strong> to create one.</div></Card>;
  const byCat = {};
  sources.forEach(s => {
    const cat = (types.find(t => t.key === s.type) || {}).category || "Other";
    (byCat[cat] = byCat[cat] || []).push(s);
  });
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {Object.entries(byCat).map(([cat, items]) => (
        <div key={cat}>
          <div className="section-h" style={{ marginBottom: 8 }}>{cat}</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {items.map(s => <SourceCard key={s.id} s={s} types={types} onChange={onChange} setMsg={setMsg} />)}
          </div>
        </div>
      ))}
    </div>
  );
};

const SourceCard = ({ s, types, onChange, setMsg }) => {
  const meta = types.find(t => t.key === s.type) || {};
  const [open, setOpen] = useState(false);
  const statusSev = { ok: "LOW", configured: "MEDIUM", never_synced: "", error: "CRITICAL" }[s.status] || "MEDIUM";

  const toggle = async () => { await window.CFApi.updateSource(s.id, { enabled: !s.enabled }); onChange(); };
  const remove = async () => { if (confirm(`Remove ${s.name}?`)) { await window.CFApi.deleteSource(s.id); onChange(); } };
  const test = async () => {
    const r = await window.CFApi.testSource(s.id);
    setMsg({ kind: r.ok ? "ok" : "err", text: r.message });
  };

  return (
    <Card padded={false}>
      <div className="src-row" onClick={() => setOpen(!open)} style={{ cursor: "pointer" }}>
        <div className="row-gap">
          <Icon name={s.mode === "connector" ? "link" : "download"} size={15} style={{ color: "var(--text-3)" }} />
          <strong style={{ fontSize: 14 }}>{s.name}</strong>
          <span className="chip">{s.mode === "connector" ? "Connector" : "Upload"}</span>
          <Badge severity={statusSev} size="sm">{s.status}</Badge>
          {!s.enabled && <span className="chip">disabled</span>}
        </div>
        <Icon name="chevron" size={15} style={{ color: "var(--text-4)", transform: open ? "rotate(90deg)" : "none", transition: "transform .15s" }} />
      </div>

      {open && (
        <div style={{ padding: "0 16px 16px" }}>
          <div className="src-grid">
            <div><div className="kv-label">Type</div><div>{meta.label || s.type}</div></div>
            <div><div className="kv-label">Status</div><div><Badge severity={statusSev} size="sm">{s.status}</Badge></div></div>
            <div><div className="kv-label">Last sync</div><div className="mono">{(s.last_sync || "—").slice(0, 19).replace("T", " ") || "—"}</div></div>
            <div><div className="kv-label">Records</div><div className="mono">{s.record_count || 0}</div></div>
          </div>
          <div style={{ fontSize: 11.5, color: "var(--text-4)", margin: "10px 0" }}>
            Provenance — source_type <code className="mono">{s.provenance?.source_type}</code> ·
            method <code className="mono">{s.provenance?.ingestion_method}</code> ·
            id <code className="mono">{s.id}</code>
          </div>
          {s.last_error && <div className="alert warn"><Icon name="info" size={14} style={{marginTop:1}}/><div>{s.last_error}</div></div>}
          {s.mode === "connector" && <ConnectorConfig s={s} meta={meta} onTest={test} setMsg={setMsg} />}
          <div className="row-gap" style={{ marginTop: 12 }}>
            <button className="btn btn-sm" onClick={toggle}>{s.enabled ? "Disable" : "Enable"}</button>
            <button className="btn btn-sm btn-ghost" onClick={remove} style={{ color: "var(--crit)" }}>Remove</button>
          </div>
        </div>
      )}
    </Card>
  );
};

const ConnectorConfig = ({ s, meta, onTest, setMsg }) => {
  const fields = meta.connector_fields || [];
  const isSecret = (f) => /key|secret|password|token|api_root/i.test(f);
  const [vals, setVals] = useState({});
  const save = async () => {
    for (const f of fields.filter(isSecret)) if (vals[f]) await window.CFApi.setSecret(s.id, f, vals[f]);
    const cfg = {}; fields.filter(f => !isSecret(f)).forEach(f => { if (vals[f]) cfg[f] = vals[f]; });
    if (Object.keys(cfg).length) await window.CFApi.updateSource(s.id, { config: { ...(s.config || {}), ...cfg } });
    setMsg({ kind: "ok", text: "Connector settings saved." });
  };
  return (
    <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 4 }}>
      <div className="section-h" style={{ marginBottom: 8 }}>Connector configuration</div>
      <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 10 }}>
        <Icon name="shield" size={12} /> Credentials are stored in your OS keychain — never written to git.
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10, maxWidth: 460 }}>
        {fields.map(f => (
          <label key={f} className="field">
            <span className="field-label">{f}{isSecret(f) ? " · secret" : ""}</span>
            <input className="input" type={isSecret(f) ? "password" : "text"}
              placeholder={isSecret(f) ? "•••• stored securely" : (s.config?.[f] || "")}
              onChange={e => setVals({ ...vals, [f]: e.target.value })} />
          </label>
        ))}
      </div>
      <div className="row-gap" style={{ marginTop: 12 }}>
        <button className="btn btn-sm" onClick={save}>Save settings</button>
        <button className="btn btn-sm btn-accent" onClick={onTest}><Icon name="radar" size={13} />Test connection</button>
        {meta.connector_status === "implemented" && (
          <button className="btn btn-sm btn-accent" onClick={async (e) => {
            const b = e.currentTarget; const o = b.textContent;
            b.disabled = true; b.textContent = "Syncing…";
            try {
              const r = await window.CFApi.fetchSource(s.id);
              if (r.ok) {
                setMsg({ kind: "ok", text: `Synced — pulled ${r.records} record(s) from the vendor API. Run the pipeline to correlate.` });
              } else {
                setMsg({ kind: "err", text: r.message || "Sync did not complete." });
              }
            } catch (err) { setMsg({ kind: "err", text: String(err) }); }
            finally { b.disabled = false; b.textContent = o; }
          }}><Icon name="download" size={13} />Sync now</button>
        )}
      </div>
    </div>
  );
};

// ── Upload panel (folded in from the old Upload Evidence page) ────────────────
const UploadPanel = ({ types, uploads, totalRecords, onChange, setMsg }) => {
  const [forced, setForced] = useState("auto");
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef(null);
  const upTypes = [{ key: "auto", label: "Auto-detect file type" },
    ...types.map(t => ({ key: (t.parser_key || t.key), label: t.label }))];

  const onPick = async (f) => {
    setFile(f); setPreview(null); setMsg(null);
    if (!f) return;
    setBusy(true);
    try { setPreview(await window.CFApi.uploadPreview(f, forced)); }
    catch (e) { setMsg({ kind: "err", text: String(e) }); }
    setBusy(false);
  };
  const commit = async () => {
    if (!file) return;
    setBusy(true); setMsg(null);
    try {
      const r = await window.CFApi.uploadCommit(file, forced);
      setMsg({ kind: "ok", text: `Saved ${r.record_count} record(s) from ${file.name}. Run the pipeline to correlate.` });
      setFile(null); setPreview(null); if (fileRef.current) fileRef.current.value = ""; onChange();
    } catch (e) { setMsg({ kind: "err", text: String(e) }); }
    setBusy(false);
  };
  const clearAll = async () => {
    if (!confirm("Clear all staged evidence?")) return;
    setBusy(true);
    try { await window.CFApi.clearUploads(); onChange(); setMsg({ kind: "ok", text: "Cleared staged evidence." }); }
    catch (e) { setMsg({ kind: "err", text: String(e) }); }
    setBusy(false);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card title="Upload a file" sub="Parsed and validated before anything is saved">
        <div className="row-gap" style={{ flexWrap: "wrap" }}>
          <input ref={fileRef} type="file" accept=".xml,.csv,.json" style={{ display: "none" }}
            onChange={e => onPick(e.target.files[0])} />
          <button className="btn btn-accent" onClick={() => fileRef.current && fileRef.current.click()}>
            <Icon name="download" size={14} />Choose file
          </button>
          <span style={{ fontSize: 13, color: file ? "var(--text-1)" : "var(--text-3)" }}>
            {file ? file.name : "No file selected · .xml, .csv, .json"}
          </span>
          <span className="spacer" />
          <label className="field" style={{ minWidth: 220 }}>
            <select className="select" value={forced} onChange={e => setForced(e.target.value)}>
              {upTypes.map(t => <option key={t.key} value={t.key}>{t.label}</option>)}
            </select>
          </label>
        </div>

        {busy && <div style={{ marginTop: 12, fontSize: 13, color: "var(--text-3)" }}>Working…</div>}

        {preview && preview.errors && preview.errors.length > 0 && (
          <div className="alert warn" style={{ marginTop: 12 }}>
            <Icon name="info" size={15} style={{ marginTop: 1 }} />
            <div><span className="alert-strong">Parsing issues:</span>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                {preview.errors.slice(0, 8).map((e, i) => <li key={i}>{e}</li>)}</ul>
            </div>
          </div>
        )}

        {preview && preview.ok && (
          <div style={{ marginTop: 14 }}>
            <div className="row-gap" style={{ marginBottom: 10 }}>
              <Icon name="check" size={15} style={{ color: "var(--low)" }} />
              <span style={{ fontSize: 13 }}>{preview.summary}</span>
              <span className="chip">{preview.file_type}</span>
            </div>
            <table className="data">
              <thead><tr><th>Type</th><th>Title</th><th>Severity</th><th>Asset</th></tr></thead>
              <tbody>
                {preview.preview.map((r, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: "var(--text-2)" }}>{r.type}</td>
                    <td>{r.title}</td>
                    <td><Badge severity={r.severity} size="sm" /></td>
                    <td className="mono" style={{ color: "var(--text-2)" }}>{r.asset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="row-gap" style={{ marginTop: 12 }}>
              <button className="btn btn-accent" disabled={busy} onClick={commit}>
                <Icon name="check" size={14} />Confirm &amp; add to evidence store
              </button>
            </div>
          </div>
        )}
      </Card>

      <Card title="Staged Evidence" sub="Included on the next pipeline run"
        action={uploads.length > 0 &&
          <button className="btn btn-sm btn-ghost" onClick={clearAll}>Clear all</button>}
        padded={false}>
        {uploads.length === 0 ? (
          <div className="empty">No staged evidence yet. Choose a file above to add some.</div>
        ) : (
          <>
            <table className="data">
              <thead><tr><th>File</th><th>Type</th><th>Records</th><th>Ingested</th></tr></thead>
              <tbody>
                {uploads.map((u, i) => (
                  <tr key={i}>
                    <td>{u.filename}</td>
                    <td className="mono" style={{ color: "var(--text-2)" }}>{u.file_type}</td>
                    <td className="mono">{u.record_count}</td>
                    <td className="mono" style={{ color: "var(--text-3)" }}>{u.ingested_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ padding: "10px 16px", fontSize: 12.5, color: "var(--text-3)" }}>
              {uploads.length} file(s) · {totalRecords} record(s) staged.
            </div>
          </>
        )}
      </Card>
    </div>
  );
};

window.SourcesPage = SourcesPage;
