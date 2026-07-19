import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:8000";
const SEVERITY_RANK = { critical: 0, warning: 1, safe: 2, info: 3 };
const FILTER_TABS = [
  { key: "all", label: "All Issues" },
  { key: "critical", label: "Critical" },
  { key: "warning", label: "Warning" },
  { key: "safe", label: "Safe" },
  { key: "info", label: "Info" },
];

function repoNameFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/#?]+)/);
  if (!match) return url;
  return `${match[1]}/${match[2].replace(/\.git$/, "")}`;
}

function Logo() {
  return (
    <a href="#" className="logo">
      <svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true">
        <polygon
          points="28,16 22,26.39 10,26.39 4,16 10,5.61 22,5.61"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
        />
        <circle
          cx="16"
          cy="15.5"
          r="5.5"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
        />
        <line
          x1="19.6"
          y1="19.2"
          x2="23"
          y2="22.6"
          stroke="#FFFFFF"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
      <span className="logo-text">QLint</span>
    </a>
  );
}

function ThemeToggle({ theme, onToggle, extraClass = "" }) {
  return (
    <button
      className={`theme-toggle ${extraClass}`.trim()}
      type="button"
      onClick={onToggle}
      aria-label="Toggle theme"
    >
      {theme === "light" ? (
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      ) : (
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="#00FF41"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <circle cx="12" cy="12" r="4" />
          <line x1="12" y1="2" x2="12" y2="4.5" />
          <line x1="12" y1="19.5" x2="12" y2="22" />
          <line x1="2" y1="12" x2="4.5" y2="12" />
          <line x1="19.5" y1="12" x2="22" y2="12" />
          <line x1="5" y1="5" x2="6.8" y2="6.8" />
          <line x1="17.2" y1="17.2" x2="19" y2="19" />
          <line x1="5" y1="19" x2="6.8" y2="17.2" />
          <line x1="17.2" y1="6.8" x2="19" y2="5" />
        </svg>
      )}
    </button>
  );
}

function Navbar({ theme, onToggleTheme }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="navbar-left">
          <button
            className="hamburger"
            type="button"
            aria-label="Menu"
            onClick={() => setSidebarOpen((prev) => !prev)}
          >
            <span className="hamburger-line" />
            <span className="hamburger-line" />
            <span className="hamburger-line" />
          </button>
          <Logo />
        </div>
        <div className="nav-actions">
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          <a
            className="nav-btn"
            href="https://github.com/Abhushan187/QLint"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
          <button className="nav-btn" type="button">
            Log in
          </button>
          <button className="nav-btn" type="button">
            Sign up
          </button>
        </div>
      </div>
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <nav className={`sidebar${sidebarOpen ? " sidebar-open" : ""}`}>
        <a
          className="sidebar-item"
          href="https://github.com/Abhushan187/QLint"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>
        <button className="sidebar-item" type="button">
          Log in
        </button>
        <button className="sidebar-item" type="button">
          Sign up
        </button>
      </nav>
    </header>
  );
}

function Hero() {
  return (
    <section className="hero">
      <div className="hero-inner">
        <div className="hero-badge">
          <span className="dot dot-safe" />
          <span>PQC &amp; Cryptography Security Scanner</span>
        </div>
        <h1>Is your codebase quantum-ready? Find out in seconds.</h1>
        <p className="hero-sub">
          QLint scans your codebase for quantum-vulnerable cryptographic
          algorithms and generates a NIST PQC 2024 compliant migration report.
        </p>
      </div>
    </section>
  );
}

function RateLimitBar({ rateLimit, statusFailed }) {
  if (statusFailed) {
    return (
      <div className="rate-bar">
        <span className="rate-text">GitHub API status unavailable</span>
      </div>
    );
  }
  if (!rateLimit) {
    return (
      <div className="rate-bar">
        <span className="rate-text">Checking GitHub API status...</span>
      </div>
    );
  }
  const { remaining, reset_at } = rateLimit;
  const dotClass =
    remaining > 500 ? "dot-safe" : remaining >= 100 ? "dot-warning" : "dot-critical";
  return (
    <div className="rate-bar-wrap">
      <div className="rate-bar">
        <span className={`dot dot-8 ${dotClass}`} />
        <span className="rate-text">
          GitHub API: {remaining} requests remaining
        </span>
      </div>
      {remaining < 100 && (
        <p className="rate-warning">
          Rate limit too low. Resets at {reset_at}. Add a GitHub token above
          for higher limits.
        </p>
      )}
    </div>
  );
}

function ScanInputCard({
  repoUrl,
  setRepoUrl,
  githubToken,
  setGithubToken,
  tokenVisible,
  setTokenVisible,
  urlError,
  rateLimit,
  statusFailed,
  scanning,
  onScan,
  error,
  onClearError,
}) {
  const rateTooLow = rateLimit != null && rateLimit.remaining < 100;
  return (
    <section className="scan-section" id="scan-input">
      <div className="scan-card">
        <div className="scan-label">Enter GitHub repository URL</div>
        <div className="scan-row">
          <input
            className="scan-input"
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onScan();
            }}
            placeholder="https://github.com/username/repository"
          />
          <button
            className="token-toggle"
            type="button"
            onClick={() => setTokenVisible(!tokenVisible)}
          >
            {tokenVisible ? "Hide token" : "Add token"}
          </button>
          <button
            className="scan-btn"
            type="button"
            onClick={onScan}
            disabled={scanning || rateTooLow}
          >
            Scan Repository
          </button>
        </div>
        {urlError && <p className="url-error">{urlError}</p>}
        {tokenVisible && (
          <div className="token-section">
            <div className="token-label">GitHub Personal Access Token</div>
            <input
              className="scan-input token-input"
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
            />
            <p className="token-note">
              Your token is used only for this request and never stored.
              Required for private repos and higher rate limits.
            </p>
          </div>
        )}
        <RateLimitBar rateLimit={rateLimit} statusFailed={statusFailed} />
      </div>
      {error && (
        <div className="error-card">
          <div className="error-title">Scan failed</div>
          <div className="error-message">{error}</div>
          <button className="error-retry" type="button" onClick={onClearError}>
            Try again
          </button>
        </div>
      )}
      <p className="privacy-note">
        We only read public repositories. Your code is never stored on our
        servers.
      </p>
    </section>
  );
}

function LanguagesStrip() {
  const comingSoon = ["JavaScript", "TypeScript", "Java", "Go", "Rust"];
  return (
    <section className="langs">
      <div className="langs-inner">
        <div className="langs-label">Supported Languages</div>
        <div className="langs-row">
          <span className="lang-pill lang-active">
            Python
            <span className="lang-tag tag-active">Active</span>
          </span>
          {comingSoon.map((name) => (
            <span className="lang-pill lang-soon" key={name}>
              {name}
              <span className="lang-tag tag-soon">Coming Soon</span>
            </span>
          ))}
        </div>
        <p className="langs-desc">
          More languages are in active development. Python scanning is
          available now.
        </p>
      </div>
    </section>
  );
}

const PRICING_PLANS = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    features: [
      "5 repository scans",
      "Python codebase support",
      "NIST PQC migration report",
      "Standard fix snippets",
    ],
    cta: "Get started",
    highlighted: false,
  },
  {
    name: "Developer",
    price: "$9",
    period: "/ month",
    features: [
      "20 repository scans / month",
      "Python codebase support",
      "NIST PQC migration report",
      "Standard fix snippets",
      "Scan history",
    ],
    cta: "Start free trial",
    highlighted: false,
  },
  {
    name: "Team",
    price: "$29",
    period: "/ month",
    features: [
      "100 repository scans / month",
      "Python + JS/TS support (Q4 2026)",
      "NIST PQC migration report",
      "Standard fix snippets",
      "Scan history + team dashboard",
      "Priority support",
    ],
    cta: "Get started",
    highlighted: true,
  },
  {
    name: "Enterprise",
    price: "$79",
    period: "/ month",
    features: [
      "Unlimited repository scans",
      "All supported languages",
      "NIST PQC migration report",
      "AI context-aware patches (coming soon)",
      "Admin dashboard + usage analytics",
      "GitHub App integration",
      "Dedicated support",
    ],
    cta: "Contact us",
    highlighted: false,
  },
];

function Pricing() {
  return (
    <section className="pricing">
      <div className="pricing-inner">
        <h2>Simple, transparent pricing</h2>
        <p className="pricing-sub">Start free. Scale as you grow.</p>
        <div className="pricing-cards">
        {PRICING_PLANS.map((plan) => (
          <div
            className={`price-card${plan.highlighted ? " price-popular" : ""}`}
            key={plan.name}
          >
            {plan.highlighted && (
              <span className="popular-badge">Most Popular</span>
            )}
            <div className="plan-name">{plan.name}</div>
            <div className="plan-price">{plan.price}</div>
            <div className="plan-period">{plan.period}</div>
            <div className="plan-divider" />
            <div className="plan-features">
              {plan.features.map((feature) => (
                <div key={feature}>{feature}</div>
              ))}
            </div>
            <button
              className={plan.highlighted ? "cta-navy" : "cta-ghost"}
              type="button"
            >
              {plan.cta}
            </button>
          </div>
        ))}
        </div>
      </div>
    </section>
  );
}

function ScanningView({ repoUrl }) {
  return (
    <div className="scanning-wrap">
      <div className="scanning-card">
        <div className="scanning-label">Scanning repository</div>
        <div className="scanning-repo">{repoNameFromUrl(repoUrl)}</div>
        <div className="progress">
          <div className="progress-inner" />
        </div>
        <p className="scanning-status">Fetching repository files...</p>
        <p className="scanning-note">
          This typically takes 10 to 30 seconds depending on repository size.
        </p>
      </div>
    </div>
  );
}

function scoreClass(score) {
  if (score < 40) return "score-critical";
  if (score < 70) return "score-warning";
  return "score-safe";
}

function buildReportText(result) {
  const date = new Date().toISOString().slice(0, 10);
  const lines = [
    "QLint PQC Migration Report",
    `Repository: ${result.repo}`,
    `Scan date: ${date}`,
    `PQC Readiness Score: ${result.pqc_readiness_score} / 100`,
    `Files scanned: ${result.scanned_files}`,
    `Total findings: ${result.total_findings}`,
    "",
  ];
  for (const findings of Object.values(result.findings_by_file)) {
    for (const f of findings) {
      lines.push(
        `FILE: ${f.file} | LINE: ${f.line} | ALGORITHM: ${f.algorithm} | ` +
          `SEVERITY: ${f.severity} | REPLACEMENT: ${f.replacement ?? "None"}`
      );
      lines.push("");
    }
  }
  return lines.join("\n");
}

function downloadReport(result) {
  const date = new Date().toISOString().slice(0, 10);
  const blob = new Blob([buildReportText(result)], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `qlint-report-${result.repo.replace("/", "-")}-${date}.txt`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function splitFixSnippet(snippet) {
  const lines = snippet.split("\n");
  const splitIndex = lines.findIndex((line) => {
    const trimmed = line.trim();
    return trimmed.startsWith("# After:") || trimmed.startsWith("# After ");
  });
  if (splitIndex === -1) return null;
  return {
    before: lines.slice(0, splitIndex).join("\n").trim(),
    after: lines.slice(splitIndex).join("\n").trim(),
  };
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
  return Promise.resolve();
}

function CopyButton({ text, variant }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    copyText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      className={`copy-btn copy-${variant}`}
      type="button"
      onClick={handleCopy}
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function FixPanels({ snippet }) {
  const parts = splitFixSnippet(snippet);
  if (!parts) {
    return (
      <div className="fix-panels">
        <div className="fix-panel fix-panel-neutral">
          <div className="fix-panel-header fix-header-neutral">
            <span className="fix-panel-title fix-title-neutral">
              Migration Pattern
            </span>
            <CopyButton text={snippet} variant="neutral" />
          </div>
          <pre className="fix-panel-body fix-body-neutral">{snippet}</pre>
        </div>
      </div>
    );
  }
  return (
    <div className="fix-panels">
      <div className="fix-panel fix-panel-before">
        <div className="fix-panel-header fix-header-before">
          <span className="fix-panel-title fix-title-before">
            Before (Vulnerable)
          </span>
          <CopyButton text={parts.before} variant="before" />
        </div>
        <pre className="fix-panel-body fix-body-before">{parts.before}</pre>
      </div>
      <div className="fix-panel fix-panel-after">
        <div className="fix-panel-header fix-header-after">
          <span className="fix-panel-title fix-title-after">
            After (Quantum-Safe)
          </span>
          <CopyButton text={parts.after} variant="after" />
        </div>
        <pre className="fix-panel-body fix-body-after">{parts.after}</pre>
      </div>
    </div>
  );
}

function FindingRow({ finding, fixKey, fixExpanded, onToggleFix }) {
  return (
    <div className="finding">
      <div className="finding-top">
        <div className="finding-title">
          <span className={`sev-badge sev-${finding.severity}`}>
            {finding.severity}
          </span>
          <span className="finding-algo">{finding.algorithm}</span>
        </div>
        <span className="finding-line">
          Line {finding.line}:{finding.col}
        </span>
      </div>
      <p className="finding-vector">
        Attack vector: {finding.attack_vector}
      </p>
      {finding.replacement != null && (
        <p className="finding-replacement">
          <span className="finding-replacement-label">Replace with:</span>{" "}
          {finding.replacement}
        </p>
      )}
      <p className="finding-reason">{finding.replacement_reason}</p>
      <button
        className="fix-toggle"
        type="button"
        onClick={() => onToggleFix(fixKey)}
      >
        {fixExpanded ? "Hide fix" : "Show fix"}
      </button>
      {fixExpanded && <FixPanels snippet={finding.fix_snippet} />}
    </div>
  );
}

function ResultsView({
  result,
  activeFilter,
  setActiveFilter,
  expandedFiles,
  setExpandedFiles,
  expandedFixes,
  setExpandedFixes,
  onReset,
}) {
  const allFindings = Object.values(result.findings_by_file).flat();

  // Highest severity seen per algorithm, for pill coloring
  const algoSeverity = {};
  for (const f of allFindings) {
    const current = algoSeverity[f.algorithm];
    if (
      current === undefined ||
      SEVERITY_RANK[f.severity] < SEVERITY_RANK[current]
    ) {
      algoSeverity[f.algorithm] = f.severity;
    }
  }

  const tabCounts = {
    all: result.total_findings,
    critical: result.severity_summary.critical,
    warning: result.severity_summary.warning,
    safe: result.severity_summary.safe,
    info: result.severity_summary.info,
  };

  const visibleFiles = Object.entries(result.findings_by_file)
    .map(([file, findings]) => [
      file,
      activeFilter === "all"
        ? findings
        : findings.filter((f) => f.severity === activeFilter),
    ])
    .filter(([, findings]) => findings.length > 0);

  const toggleFile = (file) =>
    setExpandedFiles((prev) => ({ ...prev, [file]: !prev[file] }));
  const toggleFix = (key) =>
    setExpandedFixes((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="results">
      <div className="results-header">
        <div>
          <div className="results-repo">{result.repo}</div>
          <div className="results-meta">
            Scanned {result.scanned_files} files in{" "}
            {result.scan_duration_seconds}s
          </div>
        </div>
        <div className="results-actions">
          <button
            className="btn-ghost btn-small"
            type="button"
            onClick={() => downloadReport(result)}
          >
            Download Report
          </button>
          <button
            className="btn-primary btn-small"
            type="button"
            onClick={onReset}
          >
            Scan Another Repository
          </button>
        </div>
      </div>

      <div className="score-row">
        <div className="score-card">
          <div className="card-label">PQC Readiness Score</div>
          <div
            className={`score-value ${scoreClass(result.pqc_readiness_score)}`}
          >
            {result.pqc_readiness_score}
          </div>
          <div className="score-out-of">out of 100</div>
        </div>
        {["critical", "warning", "safe", "info"].map((sev) => (
          <div className={`sum-card sum-${sev}`} key={sev}>
            <div className="card-label">{sev}</div>
            <div className="sum-count">{result.severity_summary[sev]}</div>
          </div>
        ))}
      </div>

      {result.algorithms_found.length > 0 && (
        <>
          <div className="algo-label">Algorithms Detected</div>
          <div className="algo-row">
            {result.algorithms_found.map((algo) => (
              <span
                className={`algo-pill pill-${algoSeverity[algo] ?? "info"}`}
                key={algo}
              >
                {algo}
              </span>
            ))}
          </div>
        </>
      )}

      {result.total_findings === 0 ? (
        <div className="empty-state">
          <div className="empty-heading">
            No quantum-vulnerable algorithms detected.
          </div>
          <p className="empty-sub">
            This repository appears PQC-ready based on NIST 2024 standards.
          </p>
        </div>
      ) : (
        <>
          <div className="tabs">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`tab${activeFilter === tab.key ? " tab-active" : ""}`}
                onClick={() => setActiveFilter(tab.key)}
              >
                {tab.label} ({tabCounts[tab.key]})
              </button>
            ))}
          </div>

          {visibleFiles.length === 0 ? (
            <div className="no-findings">No {activeFilter} findings.</div>
          ) : (
            visibleFiles.map(([file, findings]) => {
              const expanded = !!expandedFiles[file];
              const hasCritical = findings.some(
                (f) => f.severity === "critical"
              );
              return (
                <div className="file-section" key={file}>
                  <div
                    className={`file-header${expanded ? " file-header-open" : ""}`}
                    onClick={() => toggleFile(file)}
                  >
                    <span className="file-name">{file}</span>
                    <span className="file-header-right">
                      <span
                        className={`file-badge${
                          hasCritical ? " file-badge-critical" : ""
                        }`}
                      >
                        {findings.length}
                      </span>
                      <span
                        className={`chevron${expanded ? " chevron-open" : ""}`}
                      >
                        v
                      </span>
                    </span>
                  </div>
                  {expanded && (
                    <div className="file-body">
                      {findings.map((finding, i) => {
                        const fixKey = `${file}:${finding.line}:${i}`;
                        return (
                          <FindingRow
                            key={fixKey}
                            finding={finding}
                            fixKey={fixKey}
                            fixExpanded={!!expandedFixes[fixKey]}
                            onToggleFix={toggleFix}
                          />
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </>
      )}
    </div>
  );
}

function FooterCTA() {
  const scrollToScan = () => {
    const el = document.getElementById("scan-input");
    if (el) el.scrollIntoView({ behavior: "smooth" });
  };
  return (
    <section className="cta-banner">
      <div className="cta-inner">
        <h2>Ready to secure your entire organization?</h2>
        <p>
          Connect QLint with your GitHub organization to continuously scan
          repositories and prevent quantum-vulnerable code from shipping.
        </p>
        <button className="cta-white" type="button" onClick={scrollToScan}>
          Get Started
        </button>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-left">
          <a href="#">Terms of Service</a>
          <a href="#">Privacy Policy</a>
          <a href="mailto:abhushan4625@gmail.com">Support</a>
        </div>
        <div className="footer-copy">QLint &copy; 2026</div>
      </div>
    </footer>
  );
}

export default function App() {
  const [view, setView] = useState("input");
  const [theme, setTheme] = useState("light");
  const [repoUrl, setRepoUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [tokenVisible, setTokenVisible] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [rateLimit, setRateLimit] = useState(null);
  const [statusFailed, setStatusFailed] = useState(false);
  const [activeFilter, setActiveFilter] = useState("all");
  const [expandedFiles, setExpandedFiles] = useState({});
  const [expandedFixes, setExpandedFixes] = useState({});
  const [urlError, setUrlError] = useState(null);

  const fetchRateLimit = () => {
    fetch(`${API_BASE}/scan/status`)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setRateLimit(data);
        setStatusFailed(false);
      })
      .catch(() => {
        setRateLimit(null);
        setStatusFailed(true);
      });
  };

  useEffect(fetchRateLimit, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const toggleTheme = () =>
    setTheme((prev) => (prev === "light" ? "dark" : "light"));

  const handleScan = async () => {
    setUrlError(null);
    setError(null);
    const trimmed = repoUrl.trim();
    if (!trimmed.startsWith("https://github.com/")) {
      setUrlError("Please enter a valid GitHub repository URL");
      return;
    }
    setView("scanning");
    try {
      const post = (body) =>
        fetch(`${API_BASE}/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });

      let res = await post(
        githubToken
          ? { repo_url: trimmed, github_token: githubToken }
          : { repo_url: trimmed }
      );
      if (res.status === 422 && githubToken) {
        res = await post({ repo_url: trimmed });
      }

      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const detail =
          data && typeof data.detail === "string" ? data.detail : null;
        throw new Error(
          detail || "Scan failed. Please check the URL and try again."
        );
      }

      const expanded = {};
      for (const [file, findings] of Object.entries(
        data.findings_by_file || {}
      )) {
        expanded[file] = findings.some(
          (f) => f.severity === "critical" || f.severity === "warning"
        );
      }
      setScanResult(data);
      setExpandedFiles(expanded);
      setExpandedFixes({});
      setActiveFilter("all");
      setView("results");
      fetchRateLimit();
    } catch (err) {
      const message =
        err instanceof TypeError
          ? "Scan failed. Could not reach the QLint backend."
          : err.message || "Scan failed. Please check the URL and try again.";
      setError(message);
      setView("input");
    }
  };

  const handleReset = () => {
    setRepoUrl("");
    setGithubToken("");
    setTokenVisible(false);
    setScanResult(null);
    setActiveFilter("all");
    setExpandedFiles({});
    setExpandedFixes({});
    setError(null);
    setUrlError(null);
    setView("input");
    fetchRateLimit();
  };

  return (
    <>
      <Navbar theme={theme} onToggleTheme={toggleTheme} />
      <main className="main">
        {view === "input" && (
          <>
            <Hero />
            <ScanInputCard
              repoUrl={repoUrl}
              setRepoUrl={setRepoUrl}
              githubToken={githubToken}
              setGithubToken={setGithubToken}
              tokenVisible={tokenVisible}
              setTokenVisible={setTokenVisible}
              urlError={urlError}
              rateLimit={rateLimit}
              statusFailed={statusFailed}
              scanning={false}
              onScan={handleScan}
              error={error}
              onClearError={() => setError(null)}
            />
            <LanguagesStrip />
            <Pricing />
            <FooterCTA />
          </>
        )}
        {view === "scanning" && <ScanningView repoUrl={repoUrl} />}
        {view === "results" && scanResult && (
          <ResultsView
            result={scanResult}
            activeFilter={activeFilter}
            setActiveFilter={setActiveFilter}
            expandedFiles={expandedFiles}
            setExpandedFiles={setExpandedFiles}
            expandedFixes={expandedFixes}
            setExpandedFixes={setExpandedFixes}
            onReset={handleReset}
          />
        )}
      </main>
      <Footer />
    </>
  );
}
