import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Badge, Button, Card, Input, Spinner, Text } from "@fluentui/react-components";
import { ArrowClockwise24Regular, CheckmarkCircle24Regular, Copy24Regular, Globe24Regular, Search24Regular, ShieldCheckmark24Regular, Warning24Regular } from "@fluentui/react-icons";
import { api } from "./api";
import type { AnalysisResult, ApiHealth, SecurityFinding } from "./api/types";

type Page = "scan" | "result" | "sources";
const verdictText: Record<AnalysisResult["verdict"], string> = { low_concern: "Low risk", review: "Review needed", high_risk: "High risk" };

function App() {
  const [page, setPage] = useState<Page>("scan");
  const [url, setUrl] = useState("");
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [analysisTime, setAnalysisTime] = useState<Date | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [retryUrl, setRetryUrl] = useState("");
  const [notice, setNotice] = useState("");
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [healthError, setHealthError] = useState("");
  const autoScanUrl = useRef<string | null>(null);
  const requestId = useRef(0);

  useEffect(() => {
    let active = true;
    void api.getHealth().then((result) => { if (active) { setHealth(result); setHealthError(""); } }).catch((reason: unknown) => { if (active) setHealthError(reason instanceof Error ? reason.message : "The API health check failed."); });
    return () => { active = false; };
  }, []);

  async function analyze(targetUrl: string) {
    const submittedUrl = targetUrl.trim();
    if (!submittedUrl) return;
    const currentRequest = ++requestId.current;
    setError(""); setRetryUrl(""); setLoading(true);
    try {
      const result = await api.analyze(submittedUrl);
      if (currentRequest !== requestId.current) return;
      setAnalysis(result); setAnalysisTime(new Date()); setUrl(submittedUrl); setPage("result");
    } catch (reason) {
      if (currentRequest !== requestId.current) return;
      setError(reason instanceof Error ? reason.message : "The analysis request failed."); setRetryUrl(submittedUrl);
    } finally {
      if (currentRequest === requestId.current) setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    async function scanCurrentTab() {
      if (typeof chrome === "undefined" || !chrome.tabs?.query) return;
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!active || !tab?.url) return;
        if (!/^https?:\/\//i.test(tab.url)) { setError("This browser page cannot be scanned. Open an HTTP or HTTPS website first."); return; }
        if (autoScanUrl.current === tab.url) return;
        autoScanUrl.current = tab.url; setUrl(tab.url); await analyze(tab.url);
      } catch (reason) { if (active) setError(reason instanceof Error ? reason.message : "Could not read the current tab."); }
    }
    void scanCurrentTab();
    return () => { active = false; };
  }, []);

  async function analyzeCurrentTab() {
    setError("");
    if (typeof chrome === "undefined" || !chrome.tabs?.query) { setError("Current-tab access is only available in the installed Chrome extension."); return; }
    try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); if (!tab?.url || !/^https?:\/\//i.test(tab.url)) throw new Error("This browser page cannot be scanned. Open an HTTP or HTTPS website first."); autoScanUrl.current = tab.url; await analyze(tab.url); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not read the current tab."); }
  }

  function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); void analyze(url); }
  async function copyReport() { if (!analysis) return; try { await navigator.clipboard.writeText(JSON.stringify(analysis, null, 2)); setNotice("Report copied"); } catch { setNotice("Could not copy the report"); } window.setTimeout(() => setNotice(""), 2200); }
  const currentHost = getHostname(url);

  return <div className="app-shell">
    <header className="app-header"><div className="brand"><span className="brand-mark" aria-hidden="true"><ShieldCheckmark24Regular /></span><span><Text as="span" weight="semibold" className="brand-name">PhishNet</Text><Text as="span" className="brand-caption">URL intelligence & phishing analysis</Text></span></div><Badge appearance="outline" color={healthError ? "danger" : health?.status === "healthy" ? "success" : "warning"}>{healthError ? "API unavailable" : health?.status === "healthy" ? "Auto scan enabled" : "Checking API"}</Badge></header>
    <nav className="primary-nav" aria-label="PhishNet pages"><NavButton selected={page === "scan"} icon={<Search24Regular />} onClick={() => setPage("scan")}>Scan URL</NavButton><NavButton selected={page === "result"} icon={<Warning24Regular />} onClick={() => setPage("result")}>Report</NavButton><NavButton selected={page === "sources"} icon={<Globe24Regular />} onClick={() => setPage("sources")}>Sources</NavButton></nav>
    <main className="main-content">
      {page === "scan" && <ScanPage url={url} setUrl={setUrl} currentHost={currentHost} loading={loading} error={error} retryUrl={retryUrl} onSubmit={submit} onCurrentTab={() => void analyzeCurrentTab()} onClear={() => { setUrl(""); setError(""); }} onRetry={() => void analyze(retryUrl)} />}
      {page === "result" && <><SectionHeading title="Intelligence report" hint="Live response from PhishNet" icon={<Warning24Regular />} />{loading && <StateMessage kind="loading" message="Analyzing URL and collecting bounded intelligence…" />}{error && <StateMessage kind="error" message={error} action={retryUrl ? <Button appearance="subtle" size="small" icon={<ArrowClockwise24Regular />} onClick={() => void analyze(retryUrl)}>Retry</Button> : undefined} />}{analysis ? <AnalysisView analysis={analysis} checkedAt={analysisTime} onCopy={() => void copyReport()} onRefresh={() => void analyze(analysis.url)} onScan={() => setPage("scan")} /> : !loading && !error ? <EmptyState title="No report yet" description="Analyze a URL to see domain, DNS, TLS, HTTP, and phishing evidence." action={<Button appearance="primary" icon={<Search24Regular />} onClick={() => setPage("scan")}>Scan a URL</Button>} /> : null}{notice && <div className="toast" role="status">{notice}</div>}</>}
      {page === "sources" && <SourcesPage analysis={analysis} health={health} healthError={healthError} onScan={() => setPage("scan")} />}
    </main>
    <footer className="app-footer"><span><ShieldCheckmark24Regular /> Advisory analysis; no scripts or credentials are collected.</span><span>No scan history saved</span></footer>
  </div>;
}

function ScanPage({ url, setUrl, currentHost, loading, error, retryUrl, onSubmit, onCurrentTab, onClear, onRetry }: { url: string; setUrl: (value: string) => void; currentHost: string; loading: boolean; error: string; retryUrl: string; onSubmit: (event: FormEvent<HTMLFormElement>) => void; onCurrentTab: () => void; onClear: () => void; onRetry: () => void }) {
  return <><SectionHeading title="Check before you click" hint="Automatic current-tab scan + manual analysis" icon={<Search24Regular />} /><div className="current-site" aria-live="polite"><span className="current-site-mark" aria-hidden="true"><Globe24Regular /></span><span className="current-site-copy"><span className="eyebrow">CURRENT TAB</span><strong>{currentHost || "No website selected"}</strong></span><span className="manual-scan-label">Auto scan on popup open</span></div><form className="scan-form" onSubmit={onSubmit}><label className="field-label" htmlFor="scan-url">URL to analyze</label><Input id="scan-url" type="url" value={url} onChange={(_, data) => setUrl(data.value)} placeholder="https://example.com/" required maxLength={2048} contentBefore={<Globe24Regular />} aria-describedby="scan-help" /><Text id="scan-help" className="field-help">Only HTTP(S) URLs are accepted. Network access is bounded and private destinations are blocked.</Text><div className="form-actions"><Button type="button" appearance="secondary" onClick={onCurrentTab} disabled={loading}>Use current tab</Button><Button type="button" appearance="subtle" onClick={onClear} disabled={loading || !url}>Clear</Button><Button appearance="primary" type="submit" icon={<Search24Regular />} disabled={loading || !url.trim()}>Analyze URL</Button></div></form>{loading && <StateMessage kind="loading" message="Analyzing URL…" />}{error && <StateMessage kind="error" message={error} action={retryUrl ? <Button appearance="subtle" size="small" icon={<ArrowClockwise24Regular />} onClick={onRetry}>Retry</Button> : undefined} />}<div className="privacy-note"><ShieldCheckmark24Regular /><span>PhishNet reads the active tab URL only. It does not collect browsing history, credentials, or page scripts.</span></div></>;
}

function AnalysisView({ analysis, checkedAt, onCopy, onRefresh, onScan }: { analysis: AnalysisResult; checkedAt: Date | null; onCopy: () => void; onRefresh: () => void; onScan: () => void }) {
  const riskLevel = analysis.phishing.risk_level; const severity = riskLevel === "critical" || riskLevel === "high" ? "danger" : riskLevel === "medium" ? "warning" : "safe";
  return <><Card className={`analysis-card ${severity}`}><div className="verdict-banner"><span className="verdict-icon" aria-hidden="true">{severity === "safe" ? <CheckmarkCircle24Regular /> : <Warning24Regular />}</span><div className="verdict-copy"><Badge appearance="outline" color={severity === "danger" ? "danger" : severity === "warning" ? "warning" : "success"}>{verdictText[analysis.verdict]}</Badge><h3>{analysis.phishing.threat_intelligence_match ? "Threat intelligence match" : `${capitalize(riskLevel)} risk assessment`}</h3><p>{analysis.phishing.threat_intelligence_match ? "A configured threat feed reported this URL. Avoid opening it." : "Heuristic indicators are advisory and do not prove that a website is safe or malicious."}</p></div></div><div className="result-url-row"><div className="result-url-copy"><span className="eyebrow">ANALYZED URL</span><Text as="p" className="analysis-url">{analysis.normalized_url}</Text><span className="checked-at">{checkedAt ? `Scanned ${checkedAt.toLocaleString()}` : "Scan timestamp unavailable"}</span></div><div className="result-actions"><Button appearance="subtle" size="small" icon={<Copy24Regular />} onClick={onCopy} aria-label="Copy report" title="Copy report" /><Button appearance="subtle" size="small" icon={<ArrowClockwise24Regular />} onClick={onRefresh} aria-label="Refresh scan" title="Refresh scan" /></div></div><div className="score-grid"><Metric label="Phishing probability" value={formatProbability(analysis.phishing.phishing_probability)} hint="Calibrated model" /><Metric label="Model confidence" value={formatProbability(analysis.phishing.model_confidence)} hint="Validated confidence" /><Metric label="Heuristic risk" value={`${Math.round(analysis.phishing.heuristic_score * 100)}%`} hint="Transparent signals" /></div><div className="unavailable-note">Probability and confidence are shown as unavailable until a calibrated model and held-out validation data are configured.</div><Overview analysis={analysis} /></Card><details className="report-section" open><summary>Domain information</summary><KeyValueTable entries={objectEntries(analysis.domain_info, ["source", "status"])} /></details><details className="report-section" open><summary>DNS & IP intelligence</summary><KeyValueTable entries={[...[['Resolved IPs', analysis.resolved_ip_addresses.join(", ") || "Unavailable"] as [string, unknown]], ...objectEntries(analysis.dns.records as Record<string, unknown> | undefined), ...analysis.ip_intelligence.map((item) => [`IP ${item.ip}`, `${item.organization || item.isp || "Organization unavailable"}${item.country ? ` · ${item.country}` : ""}`] as [string, unknown])]} /></details><details className="report-section"><summary>SSL/TLS analysis</summary><KeyValueTable entries={objectEntries(analysis.ssl)} /></details><details className="report-section"><summary>HTTP & server intelligence</summary><KeyValueTable entries={objectEntries(analysis.http, ["headers", "security_headers", "redirect_chain"])} />{analysis.redirects.length > 0 && <div className="redirect-list">{analysis.redirects.map((item, index) => <div key={index}>{String(item.from)} → {String(item.to)}</div>)}</div>}</details><details className="report-section" open><summary>Security findings <span className="summary-count">{analysis.phishing.findings.length}</span></summary><div className="finding-list">{analysis.phishing.findings.map((finding, index) => <Finding key={`${finding.name}-${index}`} finding={finding} />)}</div></details><details className="report-section"><summary>Phishing detection</summary><KeyValueTable entries={[["Verdict", verdictText[analysis.verdict]], ["Risk level", analysis.phishing.risk_level], ["Threat intelligence", analysis.phishing.threat_intelligence_match ? "Match found" : "No match reported"], ["Probability basis", analysis.phishing.probability_basis]]} /><ul className="reason-list">{analysis.phishing.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></details><div className="action-bar"><Button appearance="primary" onClick={onScan}>Analyze another URL</Button></div></>;
}

function Overview({ analysis }: { analysis: AnalysisResult }) { const part = analysis.url_parts; const firstIp = analysis.ip_intelligence[0]; return <section className="overview"><h4>Overview</h4><div className="overview-grid"><Metric label="Website" value={part.registered_domain} hint={part.protocol} /><Metric label="IP address" value={analysis.resolved_ip_addresses[0] || "Unavailable"} hint={firstIp?.organization || "Hosting unavailable"} /><Metric label="Country" value={firstIp?.country || "Unavailable"} hint="Approximate hosting location" /><Metric label="Domain age" value={formatDomainAge(analysis.domain_info.domain_age_days)} hint="RDAP when available" /></div></section>; }
function Finding({ finding }: { finding: SecurityFinding }) { const color = finding.severity === "critical" || finding.severity === "high" ? "danger" : finding.severity === "medium" ? "warning" : "informative"; return <div className="finding"><div className="finding-heading"><strong>{finding.name}</strong><Badge appearance="outline" color={color}>{finding.severity}</Badge></div><p>{finding.explanation}</p><small>Evidence: {finding.evidence || "Unavailable"} · Source: {finding.source} · {finding.kind}</small></div>; }
function SourcesPage({ analysis, health, healthError, onScan }: { analysis: AnalysisResult | null; health: ApiHealth | null; healthError: string; onScan: () => void }) { return <><SectionHeading title="Threat intelligence" hint="Configured provider status" icon={<Globe24Regular />} /><div className="source-table-wrap"><table className="source-table"><thead><tr><th>Source</th><th>Status</th><th>Interpretation</th></tr></thead><tbody><tr><td>OpenPhish</td><td>{formatServiceStatus(health?.services.openphish, healthError)}</td><td>Known-feed match only</td></tr><tr><td>PhishTank</td><td>{formatServiceStatus(health?.services.phishtank, healthError)}</td><td>Known-feed match only</td></tr></tbody></table>{healthError && <StateMessage kind="error" message={healthError} />}</div>{analysis && <div className="matches-card"><Text className="checked-url">{analysis.normalized_url}</Text><SourceMatch name="OpenPhish" check={analysis.sourceChecks.openphish} /><SourceMatch name="PhishTank" check={analysis.sourceChecks.phishtank} /></div>}<div className="action-bar"><Button appearance="primary" onClick={onScan}>Scan a URL</Button></div></>; }
function SourceMatch({ name, check }: { name: string; check: AnalysisResult["sourceChecks"]["openphish"] }) { const label = check.matched === true ? "Match found" : check.matched === false && check.status === "available" ? "No match" : formatSourceStatus(check.status); return <div className="source-match"><Text weight="semibold">{name}</Text><Badge appearance="outline" color={check.matched ? "danger" : check.status === "available" ? "success" : "warning"}>{label}</Badge></div>; }
function Metric({ label, value, hint }: { label: string; value: string; hint: string }) { return <div className="metric"><span className="eyebrow">{label}</span><strong>{value}</strong><small>{hint}</small></div>; }
function KeyValueTable({ entries }: { entries: Array<[string, unknown]> }) { return <div className="key-value-table">{entries.length ? entries.map(([key, value]) => <div key={key}><span>{humanize(key)}</span><strong>{formatValue(value)}</strong></div>) : <div><span>Data</span><strong>Unavailable</strong></div>}</div>; }
function NavButton({ selected, icon, children, onClick }: { selected: boolean; icon: ReactNode; children: ReactNode; onClick: () => void }) { return <button className={`nav-link ${selected ? "selected" : ""}`} onClick={onClick} aria-current={selected ? "page" : undefined}>{icon}<span>{children}</span></button>; }
function SectionHeading({ title, hint, icon }: { title: string; hint: string; icon?: ReactNode }) { return <div className="section-heading"><h2>{icon}<span>{title}</span></h2><Text className="section-hint">{hint}</Text></div>; }
function StateMessage({ kind, message, action }: { kind: "loading" | "error"; message: string; action?: ReactNode }) { return <div className={`state-message ${kind}`} role={kind === "error" ? "alert" : "status"}>{kind === "loading" ? <Spinner size="tiny" /> : <Warning24Regular />}<Text>{message}</Text>{action}</div>; }
function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) { return <section className="empty-state"><span className="empty-icon"><Globe24Regular /></span><Text as="h3">{title}</Text><Text>{description}</Text>{action}</section>; }
function formatProbability(value: number | null) { return value === null ? "Unavailable" : `${Math.round(value * 100)}%`; }
function formatDomainAge(value: unknown) { return typeof value === "number" ? `${value} days` : "Unavailable"; }
function getHostname(value: string) { try { return new URL(value).hostname; } catch { return ""; } }
function formatServiceStatus(status: string | undefined, error: string) { if (error) return "API unavailable"; if (status === "not_configured") return "Not configured"; if (status === "available") return "Configured"; return "Checking"; }
function formatSourceStatus(status: AnalysisResult["sourceChecks"]["openphish"]["status"]) { return status === "not_configured" ? "Not configured" : status === "unavailable" ? "Unavailable" : "Checked"; }
function capitalize(value: string) { return value.charAt(0).toUpperCase() + value.slice(1); }
function humanize(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (item) => item.toUpperCase()); }
function formatValue(value: unknown): string { if (value === null || value === undefined || value === "") return "Unavailable"; if (typeof value === "boolean") return value ? "Yes" : "No"; if (Array.isArray(value)) return value.length ? value.join(", ") : "None observed"; if (typeof value === "object") return Object.entries(value as Record<string, unknown>).map(([key, item]) => `${humanize(key)}: ${formatValue(item)}`).join(" · "); return String(value); }
function objectEntries(value: unknown, excluded: string[] = []): Array<[string, unknown]> { if (!value || typeof value !== "object" || Array.isArray(value)) return []; return Object.entries(value as Record<string, unknown>).filter(([key]) => !excluded.includes(key)); }

export default App;
