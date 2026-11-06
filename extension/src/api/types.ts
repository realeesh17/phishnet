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
}

export interface ApiHealth {
  status: string;
  services: Record<string, string>;
}

export interface ApiClient {
  getHealth(): Promise<ApiHealth>;
  analyze(url: string): Promise<AnalysisResult>;
}
