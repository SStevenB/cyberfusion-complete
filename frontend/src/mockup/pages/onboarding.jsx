// pages/onboarding.jsx — first-run welcome screen.
// Shown when the workspace is not yet onboarded. Lets the user choose how to
// start: upload evidence, connect an API source, or load demo data.
const OnboardingPage = ({ onDone, onNav }) => {
  const [step, setStep] = useState("welcome");   // welcome | identity
  const [choice, setChoice] = useState(null);     // upload | connect | demo
  const [org, setOrg] = useState("");
  const [scope, setScope] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const pick = (c) => { setChoice(c); setStep("identity"); };

  const finish = async () => {
    setBusy(true); setErr(null);
    try {
      const mode = choice === "demo" ? "demo" : "real";
      await window.CFApi.onboard({
        org_name: org.trim() || "My Organization",
        scope: scope.trim() || (choice === "demo" ? "northstar-analytics.local" : "my-org.local"),
        mode,
        load_samples: choice === "demo",
      });
      // Refresh CFData so the app shows the new workspace identity + any samples.
      await window.CFApi.refreshData();
      onDone(choice);   // App decides where to land
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="onb-wrap">
      <div className="onb-card">
        <div className="onb-brand">
          <span className="onb-logo">CF</span>
          <div>
            <div className="onb-title">CyberFusion</div>
            <div className="onb-sub">Threat Intelligence &amp; Risk Fusion</div>
          </div>
        </div>

        {step === "welcome" && (
          <>
            <h1 className="onb-h1">Let's set up your workspace</h1>
            <p className="onb-lead">
              CyberFusion fuses authorized security evidence — scans, vulnerability
              exports, asset inventories, breach &amp; identity data, threat intel —
              into correlated, scored, explainable findings. How would you like to start?
            </p>

            <div className="onb-choices">
              <button className="onb-choice" onClick={() => pick("upload")}>
                <span className="onb-choice-ico"><Icon name="download" size={22} /></span>
                <span className="onb-choice-title">Upload evidence</span>
                <span className="onb-choice-desc">Drop in a scan, vuln export, asset inventory, or breach file. We parse and correlate it.</span>
              </button>

              <button className="onb-choice" onClick={() => pick("connect")}>
                <span className="onb-choice-ico"><Icon name="link" size={22} /></span>
                <span className="onb-choice-title">Connect a source</span>
                <span className="onb-choice-desc">Configure an API connector (Tenable, Qualys, HIBP, M365, STIX). CSV fallback always available.</span>
              </button>

              <button className="onb-choice onb-choice-alt" onClick={() => pick("demo")}>
                <span className="onb-choice-ico"><Icon name="flask" size={22} /></span>
                <span className="onb-choice-title">Explore with demo data</span>
                <span className="onb-choice-desc">Load clearly-labeled sample evidence and see the full correlation pipeline in action.</span>
              </button>
            </div>

            <p className="onb-foot">
              <Icon name="shield" size={13} /> Authorized use only. CyberFusion never scans external
              infrastructure itself — it interprets evidence you provide.
            </p>
          </>
        )}

        {step === "identity" && (
          <>
            <button className="onb-back" onClick={() => setStep("welcome")}>
              <Icon name="chevron" size={14} style={{ transform: "rotate(180deg)" }} /> Back
            </button>
            <h1 className="onb-h1">
              {choice === "demo" ? "Name your demo workspace" : "Name your workspace"}
            </h1>
            <p className="onb-lead">
              {choice === "demo"
                ? "We'll load sample evidence for a fictional org so you can explore. You can rename this anytime."
                : "This labels the data you'll be analyzing. You can change it later in Data Sources."}
            </p>

            <div className="onb-form">
              <label className="field">
                <span className="field-label">Organization / workspace name</span>
                <input className="input" autoFocus value={org} onChange={e => setOrg(e.target.value)}
                  placeholder={choice === "demo" ? "Northstar Analytics" : "Acme Corp"} />
              </label>
              <label className="field">
                <span className="field-label">Primary scope (domain or environment)</span>
                <input className="input" value={scope} onChange={e => setScope(e.target.value)}
                  placeholder={choice === "demo" ? "northstar-analytics.local" : "acme.com"} />
              </label>
            </div>

            {err && <div className="alert warn" style={{ marginTop: 14 }}>
              <Icon name="info" size={15} style={{ marginTop: 1 }} /><div>{err}</div></div>}

            <div className="onb-actions">
              <button className="btn btn-accent" disabled={busy} onClick={finish}>
                {busy ? "Setting up…" :
                  choice === "demo" ? "Load demo & continue" : "Create workspace & continue"}
                {!busy && <Icon name="chevron" size={14} />}
              </button>
            </div>

            <p className="onb-foot">
              {choice === "upload" && "Next: you'll land on Data Sources to upload your first file."}
              {choice === "connect" && "Next: you'll land on Data Sources to add a connector."}
              {choice === "demo" && "Next: the Executive View, populated with sample correlations."}
            </p>
          </>
        )}
      </div>
    </div>
  );
};

window.OnboardingPage = OnboardingPage;
