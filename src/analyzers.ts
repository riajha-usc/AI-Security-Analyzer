import type {
  HeaderAnalysis,
  SSLAnalysis,
  DNSAnalysis,
  RedirectAnalysis,
} from "./types";

// ── Security Headers ──────────────────────────────────────────────────────────

const CRITICAL_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
];

const RECOMMENDED_HEADERS = [
  "referrer-policy",
  "permissions-policy",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

const DEPRECATED_HEADERS = ["x-xss-protection", "public-key-pins"];

export async function analyzeHeaders(url: string): Promise<HeaderAnalysis> {
  const present: string[] = [];
  const missing: string[] = [];
  const warnings: string[] = [];

  try {
    const parsed = new URL(url);
    const targetUrl =
      parsed.protocol === "http:" ? url.replace("http://", "https://") : url;

    const response = await fetch(targetUrl, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });

    const headers = response.headers;

    // Check critical headers
    for (const header of CRITICAL_HEADERS) {
      if (headers.get(header)) {
        present.push(header);
      } else {
        missing.push(header);
        warnings.push(`Missing critical security header: ${header}`);
      }
    }

    // Check recommended headers
    for (const header of RECOMMENDED_HEADERS) {
      if (headers.get(header)) {
        present.push(header);
      } else {
        missing.push(header);
      }
    }

    // Check deprecated/dangerous headers
    for (const header of DEPRECATED_HEADERS) {
      if (headers.get(header)) {
        warnings.push(
          `Deprecated header present: ${header} — consider removing`,
        );
      }
    }

    // Check HSTS value if present
    const hsts = headers.get("strict-transport-security");
    if (hsts) {
      const maxAge = hsts.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 31536000) {
        warnings.push(
          "HSTS max-age is less than 1 year — consider increasing to 31536000",
        );
      }
      if (!hsts.includes("includeSubDomains")) {
        warnings.push("HSTS does not include subdomains");
      }
    }

    // Check CSP value if present
    const csp = headers.get("content-security-policy");
    if (csp) {
      if (csp.includes("unsafe-inline")) {
        warnings.push("CSP contains 'unsafe-inline' — weakens XSS protection");
      }
      if (csp.includes("unsafe-eval")) {
        warnings.push("CSP contains 'unsafe-eval' — weakens XSS protection");
      }
      if (csp.includes("*")) {
        warnings.push("CSP uses wildcard (*) — consider restricting sources");
      }
    }

    // Score: critical headers weighted more heavily
    const criticalPresent = CRITICAL_HEADERS.filter((h) =>
      present.includes(h),
    ).length;
    const recommendedPresent = RECOMMENDED_HEADERS.filter((h) =>
      present.includes(h),
    ).length;
    const score = Math.round(
      (criticalPresent / CRITICAL_HEADERS.length) * 70 +
        (recommendedPresent / RECOMMENDED_HEADERS.length) * 30,
    );

    return { present, missing, warnings, score };
  } catch (err) {
    return {
      present,
      missing: [...CRITICAL_HEADERS, ...RECOMMENDED_HEADERS],
      warnings: [
        `Failed to fetch headers: ${err instanceof Error ? err.message : "Unknown error"}`,
      ],
      score: 0,
    };
  }
}

// ── SSL / TLS ─────────────────────────────────────────────────────────────────

export async function analyzeSSL(url: string): Promise<SSLAnalysis> {
  const warnings: string[] = [];

  try {
    const parsed = new URL(url);

    if (parsed.protocol === "http:") {
      return {
        valid: false,
        warnings: ["Site is served over HTTP — no SSL/TLS encryption"],
        score: 0,
      };
    }

    const httpsUrl = url.startsWith("https://")
      ? url
      : `https://${parsed.hostname}`;

    const response = await fetch(httpsUrl, {
      method: "HEAD",
      signal: AbortSignal.timeout(8000),
    });

    // Cloudflare Workers expose cert info via cf object on the request
    // We parse what we can from response headers as a proxy
    const server = response.headers.get("server") || "Unknown";
    const cfRay = response.headers.get("cf-ray");

    // Check for mixed content indicators
    const csp = response.headers.get("content-security-policy");
    if (csp && csp.includes("http://")) {
      warnings.push("CSP allows HTTP sources — potential mixed content issue");
    }

    if (!response.headers.get("strict-transport-security")) {
      warnings.push(
        "HSTS not set — browsers won't enforce HTTPS on repeat visits",
      );
    }

    const score =
      warnings.length === 0 ? 100 : Math.max(60, 100 - warnings.length * 15);

    return {
      valid: true,
      issuer: cfRay
        ? "Cloudflare-proxied (cert info not directly accessible from edge)"
        : server,
      warnings,
      score,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (
      msg.includes("SSL") ||
      msg.includes("certificate") ||
      msg.includes("cert")
    ) {
      return {
        valid: false,
        warnings: [`SSL certificate error: ${msg}`],
        score: 0,
      };
    }

    return {
      valid: false,
      warnings: [`Could not verify SSL: ${msg}`],
      score: 0,
    };
  }
}

// ── DNS Records ───────────────────────────────────────────────────────────────

export async function analyzeDNS(hostname: string): Promise<DNSAnalysis> {
  const warnings: string[] = [];
  const records: string[] = [];
  let hasSPF = false;
  let hasDMARC = false;
  let hasDNSSEC = false;

  try {
    // Query Cloudflare's DNS over HTTPS (1.1.1.1) for TXT records
    const [txtResponse, dmarcResponse] = await Promise.allSettled([
      fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=TXT`, {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(5000),
      }),
      fetch(
        `https://cloudflare-dns.com/dns-query?name=_dmarc.${hostname}&type=TXT`,
        {
          headers: { Accept: "application/dns-json" },
          signal: AbortSignal.timeout(5000),
        },
      ),
    ]);

    if (txtResponse.status === "fulfilled" && txtResponse.value.ok) {
      const data = (await txtResponse.value.json()) as any;
      const answers = data.Answer || [];

      for (const record of answers) {
        if (record.type === 16) {
          // TXT record
          const value = record.data?.replace(/"/g, "") || "";
          records.push(
            `TXT: ${value.substring(0, 80)}${value.length > 80 ? "..." : ""}`,
          );

          if (value.startsWith("v=spf1")) {
            hasSPF = true;
            if (value.includes("+all")) {
              warnings.push(
                "SPF uses '+all' — allows any server to send mail on your behalf",
              );
            }
            if (value.includes("?all")) {
              warnings.push(
                "SPF uses '?all' — neutral result provides no protection",
              );
            }
          }
        }
      }

      // Check DNSSEC via AD flag
      if (data.AD === true) {
        hasDNSSEC = true;
        records.push("DNSSEC: Validated (AD flag set)");
      } else {
        warnings.push("DNSSEC not detected — DNS responses could be spoofed");
      }
    }

    if (dmarcResponse.status === "fulfilled" && dmarcResponse.value.ok) {
      const data = (await dmarcResponse.value.json()) as any;
      const answers = data.Answer || [];

      for (const record of answers) {
        if (record.type === 16) {
          const value = record.data?.replace(/"/g, "") || "";
          if (value.startsWith("v=DMARC1")) {
            hasDMARC = true;
            records.push(`DMARC: ${value.substring(0, 80)}`);

            if (value.includes("p=none")) {
              warnings.push(
                "DMARC policy is 'none' — no enforcement, only monitoring",
              );
            }
            if (value.includes("p=quarantine")) {
              records.push("DMARC policy: quarantine (good)");
            }
            if (value.includes("p=reject")) {
              records.push("DMARC policy: reject (best)");
            }
          }
        }
      }
    }

    if (!hasSPF)
      warnings.push(
        "No SPF record found — domain is vulnerable to email spoofing",
      );
    if (!hasDMARC)
      warnings.push("No DMARC record found — no email authentication policy");

    const score = Math.round(
      (hasSPF ? 30 : 0) + (hasDMARC ? 40 : 0) + (hasDNSSEC ? 30 : 0),
    );

    return { hasSPF, hasDMARC, hasDNSSEC, records, warnings, score };
  } catch (err) {
    return {
      hasSPF: false,
      hasDMARC: false,
      hasDNSSEC: false,
      records: [],
      warnings: [
        `DNS analysis failed: ${err instanceof Error ? err.message : "Unknown"}`,
      ],
      score: 0,
    };
  }
}

// ── Redirects ─────────────────────────────────────────────────────────────────

export async function analyzeRedirects(url: string): Promise<RedirectAnalysis> {
  const warnings: string[] = [];
  const redirectChain: string[] = [];
  let followsHTTPS = false;

  try {
    const parsed = new URL(url);
    const httpUrl =
      parsed.protocol === "https:" ? url.replace("https://", "http://") : url;

    redirectChain.push(httpUrl);

    // Follow redirects manually to observe the chain
    let currentUrl = httpUrl;
    let hops = 0;
    const maxHops = 10;

    while (hops < maxHops) {
      const response = await fetch(currentUrl, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) break;

        const nextUrl = location.startsWith("http")
          ? location
          : new URL(location, currentUrl).toString();
        redirectChain.push(nextUrl);
        currentUrl = nextUrl;
        hops++;

        if (nextUrl.startsWith("https://")) {
          followsHTTPS = true;
        }
      } else {
        break;
      }
    }

    if (hops >= maxHops) {
      warnings.push(
        `Redirect chain exceeds ${maxHops} hops — possible redirect loop`,
      );
    }

    if (!followsHTTPS) {
      const parsed2 = new URL(url);
      if (parsed2.protocol === "https:") {
        // Site is already HTTPS, check if HTTP redirects to HTTPS
        const httpTest = await fetch(`http://${parsed2.hostname}`, {
          method: "HEAD",
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
        }).catch(() => null);

        if (httpTest) {
          const location = httpTest.headers.get("location");
          if (location?.startsWith("https://")) {
            followsHTTPS = true;
          } else {
            warnings.push(
              "HTTP does not redirect to HTTPS — users on HTTP get no upgrade",
            );
          }
        }
      } else {
        warnings.push("Site does not use HTTPS");
      }
    }

    if (redirectChain.length > 3) {
      warnings.push(
        `Long redirect chain (${redirectChain.length} hops) — adds latency`,
      );
    }

    const score =
      followsHTTPS && redirectChain.length <= 3 && warnings.length === 0
        ? 100
        : Math.max(
            20,
            100 -
              warnings.length * 25 -
              Math.max(0, redirectChain.length - 3) * 10,
          );

    return { followsHTTPS, redirectChain, warnings, score };
  } catch (err) {
    return {
      followsHTTPS: false,
      redirectChain,
      warnings: [
        `Redirect analysis failed: ${err instanceof Error ? err.message : "Unknown"}`,
      ],
      score: 0,
    };
  }
}

// ── Grade Calculator ──────────────────────────────────────────────────────────

export function calculateGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
