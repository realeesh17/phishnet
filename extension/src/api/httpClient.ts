import type { AnalysisResult, ApiClient, ApiHealth } from "./types";

const apiBaseUrl = import.meta.env.VITE_PHISHNET_API_BASE_URL
  ?? (import.meta.env.DEV ? "/api" : "http://localhost:7071/api");

interface ApiErrorPayload {
  error?: {
    message?: string;
  };
}

export class HttpApiClient implements ApiClient {
  async getHealth(): Promise<ApiHealth> {
    return this.request<ApiHealth>("/health");
  }

  async analyze(url: string): Promise<AnalysisResult> {
    return this.request<AnalysisResult>("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${apiBaseUrl}${path}`, init);
    } catch {
      throw new Error("The API did not respond. Check the API connection and try again.");
    }

    if (!response.ok) {
      let payload: ApiErrorPayload = {};
      try {
        payload = (await response.json()) as ApiErrorPayload;
      } catch {
        // Use the status-based message when the server does not return JSON.
      }
      throw new Error(payload.error?.message ?? `The request failed (HTTP ${response.status}).`);
    }

    return (await response.json()) as T;
  }
}
