// CyberFusion — shared components
const { useState, useEffect, useMemo, useRef } = React;

// ── Icons (Lucide-style hand-rolled SVG) ─────────────────────────────
const Icon = ({ name, size = 16, strokeWidth = 2, ...rest }) => {
  const s = size;
  const props = { width: s, height: s, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth, strokeLinecap: "round", strokeLinejoin: "round", ...rest };
  const paths = {
    shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></>,
    home: <><path d="M3 12 12 3l9 9"/><path d="M5 10v10h14V10"/></>,
    sparkles: <><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8"/></>,
    feed: <><circle cx="5" cy="19" r="2"/><path d="M3 5a16 16 0 0 1 16 16"/><path d="M3 11a10 10 0 0 1 10 10"/></>,
    radar: <><circle cx="12" cy="12" r="9"/><path d="M12 3v9l6 4"/></>,
    link: <><path d="M9 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M15 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></>,
    flask: <><path d="M9 3v6l-5 9a3 3 0 0 0 2.6 4.5h10.8A3 3 0 0 0 20 18l-5-9V3"/><path d="M9 3h6"/></>,
    info: <><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></>,
    chevron: <><path d="m9 18 6-6-6-6"/></>,
    chevronDown: <><path d="m6 9 6 6 6-6"/></>,
    bell: <><path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/></>,
    refresh: <><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></>,
    download: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    external: <><path d="M7 7h10v10"/><path d="M7 17 17 7"/></>,
    plus: <><path d="M12 5v14M5 12h14"/></>,
    filter: <><path d="M3 6h18l-7 9v5l-4-2v-3z"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></>,
    arrowUp: <><path d="M12 19V5M5 12l7-7 7 7"/></>,
    arrowDown: <><path d="M12 5v14M5 12l7 7 7-7"/></>,
    check: <><path d="M20 6 9 17l-5-5"/></>,
    flame: <><path d="M8.5 14.5C9 12 11.5 11 12 8c.5 3 3 4.5 3.5 6.5a3.5 3.5 0 1 1-7 0Z"/><path d="M12 22a7 7 0 0 0 7-7c0-3.5-2.5-5-3-7-1.5-3-4-5-4-5s-2.5 2-4 5c-.5 2-3 3.5-3 7a7 7 0 0 0 7 7z"/></>,
    bug: <><rect x="8" y="6" width="8" height="14" rx="4"/><path d="M12 6V4M5 9l3 1M19 9l-3 1M5 16l3-1M19 16l-3-1M5 13h3M16 13h3"/></>,
    eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></>,
    map: <><path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2-6-2z"/><path d="M9 4v14M15 6v14"/></>,
    cog: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></>,
    server: <><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 8h.01M7 17h.01"/></>,
    network: <><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M12 12H5v4M12 12h7v4"/></>,
    file: <><path d="M14 3v6h6"/><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/></>,
    play: <><polygon points="6 4 20 12 6 20 6 4"/></>,
    list: <><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></>,
  };
  return <svg {...props}>{paths[name] || null}</svg>;
};

// ── Badge ────────────────────────────────────────────────────────────
const sevClass = (s) => ({ CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" }[(s||"").toUpperCase()] || "unknown");
const Badge = ({ severity, children, solid, size, ...rest }) => (
  <span className={`badge ${sevClass(severity)}${solid ? " solid" : ""}${size === "sm" ? " sm" : ""}`} {...rest}>
    {!solid && <span className="badge-dot" />}
    {children || severity}
  </span>
);
const KevBadge = () => (
  <span className="badge kev">
    <Icon name="flame" size={11} />
    KEV · ACTIVELY EXPLOITED
  </span>
);

// ── Sidebar ──────────────────────────────────────────────────────────
const Sidebar = ({ page, onNav, summary }) => {
  const nav = [
    { key: "executive", icon: "home", label: "Executive View" },
    { key: "sources",   icon: "server", label: "Data Sources" },
    { key: "briefing",  icon: "sparkles", label: "AI Briefing" },
    { key: "findings",  icon: "link", label: "Correlated Findings", count: summary.total, countCrit: summary.critical > 0 },
    { key: "feed",      icon: "feed", label: "Threat Feed" },
    { key: "exposure",  icon: "radar", label: "Exposure & Breach" },
  ];
  const meta = [
    { key: "methodology", icon: "flask", label: "Methodology" },
    { key: "architecture", icon: "info", label: "Architecture" },
  ];
  return (
    <aside className="sidebar">
      <div className="sb-brand">
        <div className="sb-mark">CF</div>
        <div>
          <div className="sb-name">CyberFusion</div>
          <div className="sb-sub">CTI · Risk Fusion</div>
        </div>
      </div>
      <div className="sb-org">
        <div className="sb-org-label">Workspace</div>
        <div className="sb-org-name">{window.CFData?.org?.name || "My Organization"}</div>
        <div className="sb-org-scope">{window.CFData?.org?.scope || ""}</div>
      </div>
      <div className="sb-section">
        <div className="sb-section-label">Workspace</div>
        <ul className="sb-nav">
          {nav.map(n => (
            <li key={n.key}>
              <button className={"sb-nav-item" + (page === n.key ? " active" : "")} onClick={() => onNav(n.key)}>
                <span className="sb-nav-icon"><Icon name={n.icon} size={15} /></span>
                {n.label}
                {n.count != null && <span className={"sb-nav-count" + (n.countCrit ? " crit" : "")}>{n.count}</span>}
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="sb-section">
        <div className="sb-section-label">Reference</div>
        <ul className="sb-nav">
          {meta.map(n => (
            <li key={n.key}>
              <button className={"sb-nav-item" + (page === n.key ? " active" : "")} onClick={() => onNav(n.key)}>
                <span className="sb-nav-icon"><Icon name={n.icon} size={15} /></span>
                {n.label}
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="sb-foot">
        <div className="sb-status">
          <span className="sb-dot" />
          Pipeline healthy
        </div>
        <div>Last run · {window.CFData.org.lastRun}</div>
        <div>Next run · {window.CFData.org.nextRun}</div>
        <button className="sb-refresh" onClick={async (e) => {
          const btn = e.currentTarget;
          const orig = btn.textContent;
          btn.disabled = true; btn.textContent = "Running pipeline…";
          try {
            await window.CFApi.runPipeline(true);
            await window.CFApi.refreshData();
            location.reload();
          } catch (err) {
            btn.textContent = "Pipeline failed — see API log";
            setTimeout(() => { btn.disabled = false; btn.textContent = orig; }, 2500);
          }
        }}>
          <Icon name="refresh" size={12} />
          Run pipeline now
        </button>
      </div>
    </aside>
  );
};

// ── Topbar ───────────────────────────────────────────────────────────
const PAGE_LABELS = {
  executive: "Executive View",
  sources: "Data Sources",
  briefing: "AI Briefing",
  findings: "Correlated Findings",
  feed: "Threat Feed",
  exposure: "Exposure & Breach",
  methodology: "Methodology",
  architecture: "Architecture",
  detail: "Finding Detail",
};
const Topbar = ({ page, subPage, onNav }) => (
  <header className="topbar">
    <div className="crumbs">
      <span>Workspace</span>
      <span className="crumb-sep">›</span>
      {page === "detail" ? (
        <>
          <a className="btn btn-ghost btn-sm" onClick={() => onNav("findings")} style={{padding:"4px 6px"}}>Correlated Findings</a>
          <span className="crumb-sep">›</span>
          <strong>{subPage}</strong>
        </>
      ) : (
        <strong>{PAGE_LABELS[page]}</strong>
      )}
    </div>
    <div className="topbar-actions">
      {window.CFData?.org?.mode && (
        <span className="chip" title="Workspace mode">
          {(window.CFData.org.mode || "demo").toUpperCase()} mode
        </span>
      )}
    </div>
  </header>
);

// ── Card ─────────────────────────────────────────────────────────────
const Card = ({ title, sub, action, foot, children, padded = true, className = "" }) => (
  <div className={`card ${className}`}>
    {(title || action) && (
      <div className="card-head">
        <div>
          {title && <h3 className="card-title">{title}</h3>}
          {sub && <div className="card-sub">{sub}</div>}
        </div>
        {action}
      </div>
    )}
    <div className={padded ? "card-body" : ""}>{children}</div>
    {foot && <div className="card-foot">{foot}</div>}
  </div>
);

// ── Score ring (SVG donut) ───────────────────────────────────────────
const ScoreRing = ({ value, max = 100, size = 132, stroke = 12, color }) => {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(1, value / max);
  const dash = pct * c;
  return (
    <div className="score-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} stroke="#eef0f4" strokeWidth={stroke} fill="none" />
        <circle cx={size/2} cy={size/2} r={r} stroke={color} strokeWidth={stroke} fill="none"
          strokeDasharray={`${dash} ${c}`} strokeLinecap="round" style={{transition: "stroke-dasharray .6s"}} />
      </svg>
      <div className="score-ring-num">{Math.round(value)}</div>
    </div>
  );
};

// Distribution bar
const DistBar = ({ data }) => {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  return (
    <>
      <div className="distbar">
        {data.map((d, i) => (
          <span key={i} style={{ width: `${(d.value/total)*100}%`, background: d.color }} title={`${d.label}: ${d.value}`} />
        ))}
      </div>
      <div className="dist-legend">
        {data.map((d, i) => (
          <div key={i}>
            <span className="sw" style={{ background: d.color }} />
            {d.label} <strong style={{color:"var(--text-1)"}}>{d.value}</strong>
          </div>
        ))}
      </div>
    </>
  );
};

// Donut for severity distribution
const SeverityDonut = ({ summary }) => {
  const segs = [
    { key: "critical", value: summary.critical, color: "var(--crit)", label: "Critical" },
    { key: "high",     value: summary.high,     color: "var(--high)", label: "High" },
    { key: "medium",   value: summary.medium,   color: "var(--med)",  label: "Medium" },
    { key: "low",      value: summary.low,      color: "var(--low)",  label: "Low" },
  ];
  const total = segs.reduce((s, d) => s + d.value, 0) || 1;
  const size = 200, stroke = 22;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donut" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} stroke="#eef0f4" strokeWidth={stroke} fill="none" />
        {segs.map((s, i) => {
          if (!s.value) return null;
          const len = (s.value / total) * c;
          const el = (
            <circle key={i} cx={size/2} cy={size/2} r={r}
              stroke={resolveCSSVar(s.color)} strokeWidth={stroke} fill="none"
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
            />
          );
          offset += len;
          return el;
        })}
      </svg>
      <div className="donut-center">
        <div>
          <div className="num">{total}</div>
          <div className="lbl">Findings</div>
        </div>
      </div>
    </div>
  );
};

function resolveCSSVar(v) {
  if (typeof v !== "string" || !v.startsWith("var(")) return v;
  const name = v.slice(4, -1).trim();
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

// ── Stacked area trend ───────────────────────────────────────────────
const TrendBars = ({ trend }) => {
  const max = Math.max(...trend.map(t => t.crit + t.high + t.med + t.low));
  return (
    <div>
      <div className="sparkbars">
        {trend.map((t, i) => {
          const total = t.crit + t.high + t.med + t.low;
          const h = (total / max) * 100;
          return (
            <div className="bar" key={i} style={{ height: "100%", background: "transparent" }} title={`${t.d} · C${t.crit} H${t.high} M${t.med} L${t.low}`}>
              <div style={{ height: `${100 - h}%` }} />
              <span className="seg crit" style={{ height: `${(t.crit/max)*100}%` }} />
              <span className="seg high" style={{ height: `${(t.high/max)*100}%` }} />
              <span className="seg med"  style={{ height: `${(t.med/max)*100}%` }} />
              <span className="seg low"  style={{ height: `${(t.low/max)*100}%` }} />
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, fontSize: 11, color: "var(--text-3)" }}>
        <span>{trend[0].d}</span>
        <span>{trend[Math.floor(trend.length/2)].d}</span>
        <span>{trend[trend.length-1].d}</span>
      </div>
    </div>
  );
};

// ── Mini horizontal bar chart for finding scores ────────────────────
const FindingScoreBars = ({ findings }) => {
  const max = 100;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {findings.map(f => (
        <div key={f.rule_id}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5, fontSize: 12.5 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="mono" style={{ color: "var(--text-3)", fontSize: 11.5 }}>{f.rule_id}</span>
              <span style={{ fontWeight: 600 }}>{f.rule_name}</span>
            </div>
            <span className="mono" style={{ fontWeight: 700 }}>{f.risk_score}</span>
          </div>
          <div style={{ height: 8, background: "var(--border)", borderRadius: 4, overflow: "hidden", position: "relative" }}>
            <div style={{
              width: `${(f.risk_score/max)*100}%`, height: "100%",
              background: `var(--${sevClass(f.risk_label)})`,
              borderRadius: 4,
              transition: "width .6s"
            }} />
          </div>
        </div>
      ))}
    </div>
  );
};

Object.assign(window, {
  Icon, Badge, KevBadge, Sidebar, Topbar, Card, ScoreRing,
  DistBar, SeverityDonut, TrendBars, FindingScoreBars, sevClass,
});
