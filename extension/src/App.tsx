import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Input,
  Spinner,
  Text,
} from "@fluentui/react-components";
import {
  ArrowLeft24Regular,
  ArrowRight24Regular,
  CheckmarkCircle24Regular,
  Globe24Regular,
  Search24Regular,
  ShieldCheckmark24Regular,
  Warning24Regular,
} from "@fluentui/react-icons";
import { api } from "./api";
import type { AnalysisResult, ApiHealth } from "./api/types";

type Page = "scan" | "result" | "sources";

const sampleUrls = [
  {
    url: "https://news.example/",
    label: "HTTPS example",
    description: "Ordinary HTTPS fixture. Nothing is submitted until Analyze URL is selected.",
    entry: "Active tab or manual",
  },
  {
    url: "http://192.0.2.25/sign-in",
    label: "IP literal",
    description: "Reserved documentation address for checking explainable URL features.",
    entry: "Manual",
  },
  {
    url: "https://xn--bcher-kva.example/account",
    label: "Punycode host",
    description: "Reserved sample host for showing a hostname signal without implying a live threat match.",
    entry: "Manual",
  },
];

const verdictText: Record<AnalysisResult["verdict"], string> = {
  low_concern: "Low concern",
  review: "Review",
  high_risk: "High risk",
};

function App() {
  const [page, setPage] = useState<Page>("scan");
  const [url, setUrl] = useState(sampleUrls[0].url);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [healthError, setHealthError] = useState("");

  useEffect(() => {
    let active = true;
    void api.getHealth()
      .then((result) => {
        if (active) {
          setHealth(result);
          setHealthError("");
        }
      })
      .catch((reason: unknown) => {
        if (active) {
          setHealthError(reason instanceof Error ? reason.message : "The API health check failed.");
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function analyze(targetUrl: string) {
    setError("");
    setAnalysis(null);
    setLoading(true);
    try {
      const result = await api.analyze(targetUrl.trim());
      setAnalysis(result);
      setUrl(targetUrl.trim());
      setPage("result");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The analysis request failed.");
    } finally {
      setLoading(false);
    }
  }

  async function analyzeCurrentTab() {
    setError("");
    if (typeof chrome === "undefined" || !chrome.tabs?.query) {
      setError("Current-tab access is only available in the installed Chrome extension.");
      return;
    }
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
        throw new Error("The current tab does not have an HTTP or HTTPS URL.");
      }
      setUrl(tab.url);
      await analyze(tab.url);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not read the current tab.");
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void analyze(url);
  }

  const isLoading = loading;
  const visibleError = error;
  const result = analysis;

  function choosePage(nextPage: Page) {
    setPage(nextPage);
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true"><ShieldCheckmark24Regular /></span>
          <span>
            <Text as="span" weight="semibold" className="brand-name">PhishNet</Text>
            <Text as="span" className="brand-caption">Clear signals. Safer decisions.</Text>
          </span>
        </div>
        <Badge
          appearance="outline"
          color={healthError ? "danger" : health?.status === "healthy" ? "informative" : "warning"}
        >
          {healthError ? "API unavailable" : health?.status === "healthy" ? "API connected" : "Checking API"}
        </Badge>
      </header>

      <nav className="primary-nav" aria-label="PhishNet pages">
        <button className={`nav-link ${page === "scan" ? "selected" : ""}`} onClick={() => choosePage("scan")} aria-current={page === "scan" ? "page" : undefined}>
          <Search24Regular /> <span>Scan URL</span>
        </button>
        <button className={`nav-link ${page === "result" ? "selected" : ""}`} onClick={() => choosePage("result")} aria-current={page === "result" ? "page" : undefined}>
          <Warning24Regular /> <span>Analysis Result</span>
        </button>
        <button className={`nav-link ${page === "sources" ? "selected" : ""}`} onClick={() => choosePage("sources")} aria-current={page === "sources" ? "page" : undefined}>
          <Globe24Regular /> <span>Threat Sources</span>
        </button>
      </nav>

      <main className="main-content">
        {page === "scan" && (
          <>
            <SectionHeading title="Check a URL" hint="Analysis is request-scoped" icon={<Search24Regular />} />
            <form className="scan-form" onSubmit={submit}>
              <label className="field-label" htmlFor="scan-url">URL to analyze</label>
              <Input
                id="scan-url"
                type="url"
                value={url}
                onChange={(_, data) => setUrl(data.value)}
                placeholder="https://news.example/"
                required
                maxLength={2048}
                contentBefore={<Globe24Regular />}
                aria-describedby="scan-help"
              />
              <Text id="scan-help" className="field-help">Paste a URL, or use the active tab URL when available.</Text>
              <div className="form-actions">
                <Button type="button" appearance="secondary" icon={<ArrowRight24Regular />} onClick={() => void analyzeCurrentTab()} disabled={isLoading}>
                  Use current tab
                </Button>
                <Button appearance="primary" type="submit" icon={<Search24Regular />} disabled={isLoading || !url.trim()}>
                  Analyze URL
                </Button>
              </div>
            </form>

            {isLoading && <StateMessage kind="loading" message="Analyzing URL…" />}
            {visibleError && <StateMessage kind="error" message={visibleError} />}

            <SectionHeading title="Example inputs" hint="Reserved sample domains" />
            <div className="sample-list">
              {sampleUrls.map((sample) => (
                <Card key={sample.url} className="sample-card">
                  <div className="sample-heading">
                    <Text as="h3" className="sample-url">{sample.url}</Text>
                    <Badge appearance="outline" color={sample.label === "HTTPS example" ? "informative" : "warning"}>{sample.label}</Badge>
                  </div>
                  <Text className="sample-description">{sample.description}</Text>
                  <div className="sample-footer">
                    <span>Entry: {sample.entry}</span><span aria-hidden="true">·</span><span>Not persisted</span>
                    <Button appearance="subtle" size="small" onClick={() => setUrl(sample.url)}>Use URL</Button>
                  </div>
                </Card>
              ))}
            </div>
          </>
        )}

        {page === "result" && (
          <>
            <SectionHeading title="Explainable analysis" hint="Live API response" icon={<Warning24Regular />} />
            {isLoading && <StateMessage kind="loading" message="Analyzing URL…" />}
            {visibleError && <StateMessage kind="error" message={visibleError} />}
            {result ? (
              <AnalysisView analysis={result} onScan={() => choosePage("scan")} />
            ) : !isLoading && !visibleError ? (
              <EmptyState
                title="No analysis to show"
                description="Analyze a URL to see its baseline signals and optional source-check status. No scan history is saved."
                action={<Button appearance="primary" icon={<Search24Regular />} onClick={() => choosePage("scan")}>Scan a URL</Button>}
              />
            ) : null}
          </>
        )}

        {page === "sources" && (
          <>
            <SectionHeading title="Optional threat intelligence" hint="Configured on the API" icon={<Globe24Regular />} />
            <div className="source-table-wrap">
              <table className="source-table">
                <thead><tr><th>Source</th><th>Configuration</th><th>When unavailable</th></tr></thead>
                <tbody>
                  <tr><td>OpenPhish</td><td><Badge appearance="outline">{formatServiceStatus(health?.services.openphish, healthError)}</Badge></td><td>Skip lookup; keep baseline result</td></tr>
                  <tr><td>PhishTank</td><td><Badge appearance="outline">{formatServiceStatus(health?.services.phishtank, healthError)}</Badge></td><td>Skip lookup; keep baseline result</td></tr>
                </tbody>
              </table>
              {healthError && <StateMessage kind="error" message={healthError} />}
            </div>
            <SectionHeading title="Matches for this URL" hint="Current request only" />
            {result && analysis ? (
              <div className="matches-card">
                <Text className="checked-url">{analysis.url}</Text>
                <SourceMatch name="OpenPhish" check={analysis.sourceChecks.openphish} />
                <SourceMatch name="PhishTank" check={analysis.sourceChecks.phishtank} />
              </div>
            ) : (
              <EmptyState
                title="No source matches available"
                description="Analyze a URL to see its current source-check statuses. Optional source failures do not suppress the baseline analysis."
                icon={<Globe24Regular />}
              />
            )}
            <div className="action-bar">
              <Button appearance="primary" icon={<Search24Regular />} onClick={() => choosePage("scan")}>Scan a URL</Button>
            </div>
          </>
        )}
      </main>

      <footer className="app-footer">
        <span>Baseline signals are explanatory, not a guarantee.</span>
        <span>No scan history saved</span>
      </footer>
    </div>
  );
}

function SectionHeading({ title, hint, icon }: { title: string; hint: string; icon?: ReactNode }) {
  return (
    <div className="section-heading">
      <h2>{icon}<span>{title}</span></h2>
      <Text className="section-hint">{hint}</Text>
    </div>
  );
}

function StateMessage({ kind, message }: { kind: "loading" | "error"; message: string }) {
  return (
    <div className={`state-message ${kind}`} role={kind === "error" ? "alert" : "status"}>
      {kind === "loading" ? <Spinner size="tiny" /> : <Warning24Regular />}
      <Text>{message}</Text>
    </div>
  );
}

function AnalysisView({ analysis, onScan }: { analysis: AnalysisResult; onScan: () => void }) {
  const concern = analysis.verdict !== "low_concern";
  return (
    <>
      <Card className={`analysis-card ${concern ? "caution" : "clear"}`}>
        <CardHeader
          header={<Text as="h3" className="analysis-url">{analysis.url}</Text>}
          action={<Badge appearance="tint" color={concern ? "warning" : "success"} icon={concern ? <Warning24Regular /> : <CheckmarkCircle24Regular />}>{verdictText[analysis.verdict]}</Badge>}
        />
        <Text className="illustrative-note">Baseline signals are advisory and do not guarantee that a URL is safe or malicious.</Text>
        <h4>Signals that informed this result</h4>
        <ul className="indicator-list">
          {analysis.indicators.map((indicator) => (
            <li key={indicator.code}>
              <span className="indicator-icon"><CheckmarkCircle24Regular /></span>
              <span><strong>{indicator.label}</strong><small>{indicator.detail}</small></span>
            </li>
          ))}
        </ul>
        <div className="source-summary">
          <span>OpenPhish: {formatSourceStatus(analysis.sourceChecks.openphish.status)}</span>
          <span>PhishTank: {formatSourceStatus(analysis.sourceChecks.phishtank.status)}</span>
        </div>
      </Card>
      <div className="action-bar">
        <Button appearance="primary" icon={<ArrowLeft24Regular />} onClick={onScan}>Analyze another URL</Button>
      </div>
    </>
  );
}

function SourceMatch({ name, check }: { name: string; check: AnalysisResult["sourceChecks"]["openphish"] }) {
  return (
    <div className="source-match">
      <Text weight="semibold">{name}</Text>
      <Badge appearance="outline" color={check.matched ? "danger" : "informative"}>
        {check.matched ? "Match found" : formatSourceStatus(check.status)}
      </Badge>
    </div>
  );
}

function EmptyState({ title, description, action, icon }: { title: string; description: string; action?: ReactNode; icon?: ReactNode }) {
  return (
    <section className="empty-state">
      <span className="empty-icon">{icon ?? <Globe24Regular />}</span>
      <Text as="h3">{title}</Text>
      <Text>{description}</Text>
      {action}
    </section>
  );
}

function formatSourceStatus(status: AnalysisResult["sourceChecks"]["openphish"]["status"]) {
  if (status === "not_configured") return "not configured";
  if (status === "unavailable") return "temporarily unavailable";
  return "checked";
}

function formatServiceStatus(status: string | undefined, error: string) {
  if (error) return "API unavailable";
  if (status === "not_configured") return "Not configured";
  if (status === "available") return "Configured";
  return "Checking API";
}

export default App;
