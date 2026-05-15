import {
  WorkflowEntrypoint,
  WorkflowStep,
  WorkflowEvent,
} from "cloudflare:workers";
import type { Env, SecurityAnalysisInput, SecurityReport } from "./types";
import {
  analyzeHeaders,
  analyzeSSL,
  analyzeDNS,
  analyzeRedirects,
  calculateGrade,
} from "./analyzers";

export class SecurityAnalysisWorkflow extends WorkflowEntrypoint<
  Env,
  SecurityAnalysisInput
> {
  async run(event: WorkflowEvent<SecurityAnalysisInput>, step: WorkflowStep) {
    const { url } = event.payload;

    let hostname: string;
    try {
      hostname = new URL(url).hostname;
    } catch {
      throw new Error(`Invalid URL: ${url}`);
    }

    // ── Step 1: Parallel data collection ──────────────────────────────────────
    const [headers, ssl, dns, redirects] = await Promise.all([
      step.do(
        "analyze-headers",
        { retries: { limit: 2, delay: "1 second" } },
        async () => {
          return await analyzeHeaders(url);
        },
      ),
      step.do(
        "analyze-ssl",
        { retries: { limit: 2, delay: "1 second" } },
        async () => {
          return await analyzeSSL(url);
        },
      ),
      step.do(
        "analyze-dns",
        { retries: { limit: 2, delay: "1 second" } },
        async () => {
          return await analyzeDNS(hostname);
        },
      ),
      step.do(
        "analyze-redirects",
        { retries: { limit: 2, delay: "1 second" } },
        async () => {
          return await analyzeRedirects(url);
        },
      ),
    ]);

    // ── Step 2: AI reasoning over collected data ───────────────────────────────
    const aiInsights = await step.do("ai-analysis", async () => {
      const allWarnings = [
        ...headers.warnings,
        ...ssl.warnings,
        ...dns.warnings,
        ...redirects.warnings,
      ];

      const prompt = buildAIPrompt(
        url,
        hostname,
        headers,
        ssl,
        dns,
        redirects,
        allWarnings,
      );

      const response = await this.env.AI.run(
        "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        {
          messages: [
            {
              role: "system",
              content: `You are a senior web security engineer at Cloudflare. You analyze security posture of websites and provide clear, actionable insights. Be concise but thorough. Use technical language appropriate for developers. Format your response in clear sections.`,
            },
            {
              role: "user",
              content: prompt,
            },
          ],
          max_tokens: 1024,
        },
      );

      return (response as any).response || "AI analysis unavailable";
    });

    // ── Step 3: Build final report ─────────────────────────────────────────────
    const report = await step.do("build-report", async () => {
      const overallScore = Math.round(
        headers.score * 0.35 +
          ssl.score * 0.3 +
          dns.score * 0.2 +
          redirects.score * 0.15,
      );

      const allWarnings = [
        ...headers.warnings,
        ...ssl.warnings,
        ...dns.warnings,
        ...redirects.warnings,
      ];

      // Extract top recommendations from warnings
      const recommendations = allWarnings
        .filter((w) => !w.startsWith("Failed") && !w.startsWith("Could not"))
        .slice(0, 8)
        .map((w) => w);

      const report: SecurityReport = {
        url,
        timestamp: new Date().toISOString(),
        overallScore,
        grade: calculateGrade(overallScore),
        headers,
        ssl,
        dns,
        redirects,
        aiInsights: aiInsights as string,
        recommendations,
      };

      return report;
    });

    return report;
  }
}

function buildAIPrompt(
  url: string,
  hostname: string,
  headers: any,
  ssl: any,
  dns: any,
  redirects: any,
  allWarnings: string[],
): string {
  return `Analyze the security posture of ${url} (${hostname}) based on the following collected data:

## HTTP Security Headers
- Present headers: ${headers.present.join(", ") || "none"}
- Missing headers: ${headers.missing.join(", ") || "none"}
- Header score: ${headers.score}/100

## SSL/TLS
- Valid certificate: ${ssl.valid}
- Score: ${ssl.score}/100
${ssl.issuer ? `- Issuer info: ${ssl.issuer}` : ""}

## DNS Configuration
- SPF record: ${dns.hasSPF ? "✓ Present" : "✗ Missing"}
- DMARC record: ${dns.hasDMARC ? "✓ Present" : "✗ Missing"}
- DNSSEC: ${dns.hasDNSSEC ? "✓ Enabled" : "✗ Not detected"}
- DNS score: ${dns.score}/100
${dns.records.length > 0 ? `- Records found: ${dns.records.slice(0, 5).join("; ")}` : ""}

## HTTP→HTTPS Redirects
- Enforces HTTPS: ${redirects.followsHTTPS ? "Yes" : "No"}
- Redirect chain length: ${redirects.redirectChain.length}
- Redirect score: ${redirects.score}/100

## All Warnings
${allWarnings.length > 0 ? allWarnings.map((w) => `- ${w}`).join("\n") : "No warnings"}

Please provide:
1. **Executive Summary** (2-3 sentences on overall posture)
2. **Top 3 Critical Issues** to fix immediately, with brief explanation of the risk
3. **Quick Wins** (changes that take <1 hour to implement)
4. **One Cloudflare-specific recommendation** that could improve security

Keep your response focused, practical, and under 400 words.`;
}
