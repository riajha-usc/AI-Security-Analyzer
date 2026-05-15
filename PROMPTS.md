# PROMPTS.md - AI Prompts Used in Development

This file documents the AI prompts used during the development of `cf_ai_security_analyzer`, as required by the assignment.

---

## 1. Workflow Step Design

**Prompt:**
> Design a Cloudflare Workflow for a web security analyzer. The workflow should collect security data from 4 sources in parallel (HTTP headers, SSL/TLS, DNS records, HTTP redirects), then pass all results to an LLM for synthesis. Each step should have retry logic. Show the TypeScript class using WorkflowEntrypoint. The final output should be a structured SecurityReport object.

**Used for:** `src/workflow.ts` - the `SecurityAnalysisWorkflow` class structure and step ordering.

---

## 2. Security Header Analysis Logic

**Prompt:**
> Write a TypeScript function `analyzeHeaders(url: string)` for a Cloudflare Worker that:
> - Fetches the URL with a HEAD request
> - Checks for these critical headers: strict-transport-security, content-security-policy, x-frame-options, x-content-type-options
> - Checks for recommended headers: referrer-policy, permissions-policy, cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-resource-policy
> - Flags HSTS max-age < 1 year, HSTS without includeSubDomains, CSP with unsafe-inline/unsafe-eval/wildcard
> - Returns a score weighted 70% on critical headers, 30% on recommended
> - Runs in a Cloudflare Worker (no Node.js APIs)

**Used for:** `analyzeHeaders()` in `src/analyzers.ts`.

---

## 3. DNS Analysis via DoH

**Prompt:**
> Write a TypeScript function `analyzeDNS(hostname: string)` for a Cloudflare Worker that queries Cloudflare's DNS-over-HTTPS API (cloudflare-dns.com/dns-query) to check:
> - SPF records (TXT records starting with v=spf1), flagging +all and ?all
> - DMARC records (_dmarc.hostname), flagging p=none as weak
> - DNSSEC validation via the AD flag in the DoH response
> Run both queries in parallel with Promise.allSettled. Return a score: 30pts for SPF, 40pts for DMARC, 30pts for DNSSEC.

**Used for:** `analyzeDNS()` in `src/analyzers.ts`.

---

## 4. LLM Prompt for Threat Analysis

**Prompt:**
> Write a detailed system + user prompt pair for Llama 3.3 70B that takes structured security scan data (header scores, SSL validity, DNS records, redirect chain, list of warnings) for a given URL and produces:
> 1. A 2-3 sentence executive summary of the site's security posture
> 2. Top 3 critical issues with brief risk explanations
> 3. Quick wins (under 1 hour to fix)
> 4. One Cloudflare-specific recommendation
> Keep total output under 400 words. Use **bold** for section headers.

**Used for:** `buildAIPrompt()` and the system message in `src/workflow.ts`.

---

## 5. Conversational Fallback System Prompt

**Prompt:**
> Write a system prompt for an AI security assistant called SentinelAI that is embedded in a web security analyzer tool. It should: answer questions about HTTP headers, SSL/TLS, DNS security (SPF/DMARC/DNSSEC), HTTPS enforcement, OWASP Top 10, and Cloudflare features. Sound like a senior security engineer - technical but approachable. Keep answers concise and practical. Explain the A-F grading scale if asked.

**Used for:** The system message in `handleConversational()` in `src/index.ts`.

---

## 6. Frontend Chat UI Design

**Prompt:**
> Design a dark-themed chat UI for a web security analyzer called SentinelAI. Use a terminal/cyberpunk aesthetic with: Space Mono for monospace elements, DM Sans for body text, a deep navy/black background (#050810), cyan accent color (#00d4ff), animated grid background, hexagonal logo mark. The interface has a header with a pulsing status dot, a scrollable message area, animated "thinking" indicator with step-by-step progress, and a security report card component that shows: A-F grade badge, 4 score bar charts (headers/SSL/DNS/redirects), DNS check grid (pass/fail icons), warnings list, redirect chain, and AI insights section. All in a single HTML file with no external dependencies except Google Fonts.

**Used for:** `public/index.html` - the complete frontend design and report rendering.

---

## 7. Score Weighting & Grading Rationale

**Prompt:**
> For a web security analyzer that checks HTTP headers, SSL/TLS, DNS records, and HTTPS redirects, suggest a weighted scoring model that produces a 0-100 overall score. Justify the weights based on real-world security impact. Also define letter grade thresholds.

**Used for:** The `overallScore` calculation in `src/workflow.ts` and `calculateGrade()` in `src/analyzers.ts`.

---

## 8. Build Script Design

**Prompt:**
> Write a Node.js ES module build script (build.mjs) that reads public/index.html, escapes it as a JavaScript template literal (escaping backticks, backslashes, and ${), then inlines it into a copy of src/index.ts by replacing a __HTML_PLACEHOLDER__ token. Output to a dist/ directory. Also copy all other .ts files from src/ to dist/.

**Used for:** `build.mjs`.

---

## Notes

- All prompts were iterated on during development - the versions above represent the final, most effective form used.
- Code generated from these prompts was reviewed, debugged, and adapted to fit the Cloudflare Workers runtime (no Node.js built-ins, edge-compatible fetch, Workflow API specifics).
- The frontend HTML was substantially hand-tuned for visual polish after the initial generation.
