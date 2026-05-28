// capture_screenshots.mjs — capture clean PNGs of each page for the README.
// Uses the system Chrome via puppeteer-core. Requires the app running on :8000.
import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "docs", "screenshots");
mkdirSync(OUT, { recursive: true });

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const BASE = "http://localhost:8000";

// Each page: nav label to click + output filename.
const PAGES = [
  { label: "Executive View",     file: "01-executive.png" },
  { label: "Data Sources",       file: "02-data-sources.png" },
  { label: "Correlated Findings",file: "03-findings.png" },
  { label: "AI Briefing",        file: "04-briefing.png" },
  { label: "Threat Feed",        file: "05-threat-feed.png" },
  { label: "Exposure & Breach",  file: "06-exposure.png" },
  { label: "Methodology",        file: "07-methodology.png" },
];

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--window-size=1440,900"],
  defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 },  // retina-quality
});

const page = await browser.newPage();
await page.goto(BASE, { waitUntil: "networkidle2", timeout: 30000 });
await sleep(2500);  // let CFData load + render

// If onboarding shows, the nav won't exist — bail with a clear message.
const hasNav = await page.evaluate(() => !!document.querySelector(".sb-nav-item"));
if (!hasNav) {
  console.error("Onboarding screen is showing — reset not expected. Capturing it anyway.");
  await page.screenshot({ path: join(OUT, "00-onboarding.png") });
  await browser.close();
  process.exit(0);
}

for (const p of PAGES) {
  // Click the matching nav item
  const clicked = await page.evaluate((label) => {
    const btn = [...document.querySelectorAll(".sb-nav-item")]
      .find(b => b.textContent.trim().startsWith(label));
    if (btn) { btn.click(); return true; }
    return false;
  }, p.label);
  if (!clicked) { console.warn("could not find nav:", p.label); continue; }
  await sleep(1400);  // let the page render
  await page.screenshot({ path: join(OUT, p.file) });
  console.log("captured", p.file);
}

await browser.close();
console.log("done →", OUT);
