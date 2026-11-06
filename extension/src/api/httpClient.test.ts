import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpApiClient } from "./httpClient";

describe("HttpApiClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("requests live API health data", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "healthy",
          services: { analysis: "healthy", openphish: "not_configured", phishtank: "available" },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(new HttpApiClient().getHealth()).resolves.toMatchObject({
      status: "healthy",
      services: { phishtank: "available" },
    });
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/health$/), undefined);
  });

  it("posts a URL and returns the live analysis response", async () => {
    const response = {
      url: "https://news.example/",
      verdict: "low_concern",
      indicators: [{ code: "https", label: "HTTPS scheme", detail: "The URL uses HTTPS." }],
      sourceChecks: {
        openphish: { status: "not_configured", matched: null },
        phishtank: { status: "unavailable", matched: null },
      },
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(new HttpApiClient().analyze(response.url)).resolves.toEqual(response);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/analyze$/),
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: response.url }),
      }),
    );
  });

  it("surfaces API validation errors", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: { message: "Only HTTP and HTTPS URLs are accepted." } }), {
        status: 422,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(new HttpApiClient().analyze("file:///etc/passwd")).rejects.toThrow(
      "Only HTTP and HTTPS URLs are accepted.",
    );
  });
});
