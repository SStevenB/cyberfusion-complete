// CyberFusion main app
const App = () => {
  const [page, setPage] = useState("executive");
  const [detailId, setDetailId] = useState(null);
  // First-run gate: show onboarding until the workspace is set up.
  const [onboarded, setOnboarded] = useState(!!(window.CFData?.org?.onboarded));

  // Tweaks
  const defaults = /*EDITMODE-BEGIN*/{
    "accent": "#0FB5A8",
    "density": "comfortable",
    "darkSidebar": true,
    "showPeerBenchmark": true
  }/*EDITMODE-END*/;
  const [t, setTweak] = (typeof useTweaks !== "undefined") ? useTweaks(defaults) : [defaults, () => {}];

  // Apply tweaks live
  useEffect(() => {
    document.documentElement.style.setProperty("--accent", t.accent);
    document.documentElement.style.setProperty("--accent-dark", shade(t.accent, -0.15));
    document.documentElement.style.setProperty("--accent-soft", tint(t.accent, 0.88));
  }, [t.accent]);

  // Light-sidebar mode
  useEffect(() => {
    if (!t.darkSidebar) {
      document.documentElement.style.setProperty("--navy-800", "#ffffff");
      document.documentElement.style.setProperty("--navy-900", "#f6f7fb");
      document.documentElement.style.setProperty("--navy-700", "#f6f7fb");
      document.documentElement.style.setProperty("--sidebar-text", "#475569");
      document.documentElement.style.setProperty("--sidebar-text-dim", "#94a3b8");
      document.documentElement.style.setProperty("--sidebar-border", "#e5e8ef");
    } else {
      document.documentElement.style.removeProperty("--navy-800");
      document.documentElement.style.removeProperty("--navy-900");
      document.documentElement.style.removeProperty("--navy-700");
      document.documentElement.style.removeProperty("--sidebar-text");
      document.documentElement.style.removeProperty("--sidebar-text-dim");
      document.documentElement.style.removeProperty("--sidebar-border");
    }
  }, [t.darkSidebar]);

  const openFinding = (id) => { setDetailId(id); setPage("detail"); };
  const onNav = (p) => { setPage(p); setDetailId(null); };

  // After onboarding: land on Data Sources for upload/connect, Executive for demo.
  const finishOnboarding = (choice) => {
    setOnboarded(true);
    setPage(choice === "demo" ? "executive" : "sources");
  };

  const summary = window.CFData.summary;

  if (!onboarded) {
    return <OnboardingPage onDone={finishOnboarding} onNav={onNav} />;
  }

  return (
    <div className="app">
      <Sidebar page={page} onNav={onNav} summary={summary} />
      <main className="main">
        <Topbar page={page} subPage={detailId ? (window.CFData.findings.find(f => f.rule_id === detailId)?.rule_name || "") : ""} onNav={onNav} />
        {page === "executive" && <ExecutiveView onOpenFinding={openFinding} onNav={onNav} />}
        {page === "briefing"  && <BriefingPage />}
        {page === "findings"  && <FindingsPage onOpenFinding={openFinding} />}
        {page === "feed"      && <ThreatFeed />}
        {page === "exposure"  && <ExposurePage />}
        {page === "methodology" && <MethodologyPage />}
        {page === "architecture" && <ArchitecturePage />}
        {page === "detail"    && <FindingDetail ruleId={detailId} onBack={() => onNav("findings")} />}
      </main>

      {typeof TweaksPanel !== "undefined" && (
        <TweaksPanel title="Tweaks">
          <TweakSection title="Brand">
            <TweakColor label="Accent color" value={t.accent} onChange={v => setTweak("accent", v)}
              options={["#0FB5A8", "#2563EB", "#F26430", "#8B5CF6", "#0EA5E9"]} />
          </TweakSection>
          <TweakSection title="Layout">
            <TweakRadio label="Sidebar" value={t.darkSidebar ? "dark" : "light"} onChange={v => setTweak("darkSidebar", v === "dark")}
              options={[{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }]} />
            <TweakRadio label="Density" value={t.density} onChange={v => setTweak("density", v)}
              options={[{ value: "compact", label: "Compact" }, { value: "comfortable", label: "Roomy" }]} />
          </TweakSection>
          <TweakSection title="Executive view">
            <TweakToggle label="Show peer benchmark" value={t.showPeerBenchmark} onChange={v => setTweak("showPeerBenchmark", v)} />
          </TweakSection>
        </TweaksPanel>
      )}
    </div>
  );
};

// ── color helpers ────────────────────────────────────────────────────
function hexToRgb(h) {
  h = h.replace("#", "");
  if (h.length === 3) h = h.split("").map(c => c+c).join("");
  return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)];
}
function rgbToHex(r,g,b) {
  return "#" + [r,g,b].map(v => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2,"0")).join("");
}
function shade(hex, pct) {
  const [r,g,b] = hexToRgb(hex);
  const f = pct < 0 ? 1 + pct : 1;
  const t = pct < 0 ? 0 : 255 * pct;
  return rgbToHex(r*f + t, g*f + t, b*f + t);
}
function tint(hex, pct) {
  // mix with white by pct (0..1)
  const [r,g,b] = hexToRgb(hex);
  return rgbToHex(r + (255-r)*pct, g + (255-g)*pct, b + (255-b)*pct);
}

// Apply density tweak
const styleEl = document.createElement("style");
document.head.appendChild(styleEl);
const observer = new MutationObserver(() => {});

// dark-sidebar toggle
document.documentElement.dataset.sidebar = "dark";

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
