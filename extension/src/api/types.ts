export type AnalysisVerdict = "low_concern" | "review" | "high_risk";

export type SourceStatus = "not_configured" | "available" | "unavailable";

export interface Indicator {
  code: string;
  label: string;
  detail: string;
}

export interface SourceCheck {
  status: SourceStatus;
  matched: boolean | null;
}

export interface AnalysisResult {
  url: string;
  verdict: AnalysisVerdict;
  indicators: Indicator[];
  sourceChecks: {
    openphish: SourceCheck;
    phishtank: SourceCheck;
  };
  risk_score?: number;
  model?: string;
  features?: Record<string, number | boolean | null>;
  reasons?: string[];
  normalized_url: string;
  url_parts: UrlParts;
  domain_info: Record<string, unknown>;
  dns: Record<string, unknown>;
  ip_intelligence: IpIntelligence[];
  resolved_ip_addresses: string[];
  ssl: Record<string, unknown>;
  http: Record<string, unknown>;
  redirects: Array<Record<string, unknown>>;
  phishing: PhishingAnalysis;
  scan_metadata: Record<string, unknown>;
}

export interface UrlParts {
  protocol: string;
  hostname: string;
  domain: string;
  registered_domain: string;
  subdomain: string;
  tld: string | null;
  port: number;
  path: string;
  query: string | null;
  fragment: string | null;
  origin: string;
}

export interface IpIntelligence {
  ip: string;
  version: number;
  classification: string;
  reverse_dns?: string | null;
  asn?: number | string | null;
  isp?: string | null;
  organization?: string | null;
  country?: string | null;
  region?: string | null;
  status: string;
}

export interface SecurityFinding {
  name: string;
  severity: string;
  explanation: string;
  evidence: string | null;
  source: string;
  kind: string;
}

export interface PhishingAnalysis {
  verdict: AnalysisVerdict;
  risk_level: string;
  heuristic_score: number;
  phishing_probability: number | null;
  model_confidence: number | null;
  probability_basis: string;
  reasons: string[];
  findings: SecurityFinding[];
  threat_intelligence_match: boolean;
}

export interface ApiHealth {
  status: string;
  services: Record<string, string>;
}

export interface ApiClient {
  getHealth(): Promise<ApiHealth>;
  analyze(url: string): Promise<AnalysisResult>;
}
