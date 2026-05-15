## SentinelAI
> **AI-powered web security analyzer** built on Cloudflare Workers, Workflows, and Workers AI (Llama 3.3 70B).

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/yourusername/cf_ai_security_analyzer)

---

## What It Does

SentinelAI is a chat-based security analysis tool. You enter any URL or domain, and it:

1. **Scans HTTP security headers** - checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more
2. **Verifies SSL/TLS configuration** - detects HTTPS enforcement, certificate validity, mixed content signals
3. **Queries DNS records** - checks for SPF, DMARC, DNSSEC using Cloudflare's 1.1.1.1 DNS-over-HTTPS API
4. **Traces the redirect chain** - follows HTTP→HTTPS redirects and flags loops or excessive hops
5. **Runs Llama 3.3 70B threat analysis** - synthesizes all gathered data into a prioritized, actionable security report with an A–F grade

You can also ask general security questions in the chat (e.g. *"What does HSTS do?"* or *"What's the difference between SPF and DMARC?"*).

---

## Architecture

```
Browser (Chat UI)
      │
      ▼
Cloudflare Worker (src/index.ts)          ← Routes requests, serves HTML
      │
      ├── POST /api/chat
      │         │
      │         ▼
      │   SecurityAnalysisWorkflow         ← Cloudflare Workflow (src/workflow.ts)
      │         │
      │         ├── step: analyze-headers  ← Fetches & inspects HTTP response headers
      │         ├── step: analyze-ssl      ← Verifies HTTPS / TLS posture
      │         ├── step: analyze-dns      ← Queries 1.1.1.1 DoH for SPF/DMARC/DNSSEC
      │         ├── step: analyze-redirects← Traces HTTP→HTTPS redirect chain
      │         └── step: ai-analysis      ← Workers AI · Llama 3.3 70B
      │
      └── Conversational fallback          ← Workers AI · Llama 3.3 70B (no URL)
```

### Cloudflare Primitives Used

| Primitive | Role |
|---|---|
| **Workers** | HTTP routing, serving the frontend, orchestrating requests |
| **Workflows** | Durable multi-step analysis pipeline with automatic retries |
| **Workers AI** | Llama 3.3 70B for threat synthesis + conversational Q&A |
| **DNS over HTTPS (1.1.1.1)** | SPF, DMARC, DNSSEC record lookups |

---

## Running Locally

### Prerequisites

- [Node.js](https://nodejs.org/) ≥ 18
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- Wrangler CLI authenticated: `npx wrangler login`

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/AI-Security-Analyzer
cd cf_ai_security_analyzer

# 2. Install dependencies
npm install

# 3. Build (inlines HTML into the Worker)
npm run build

# 4. Run locally with Wrangler
npm run dev
```

Open [http://localhost:8787](http://localhost:8787) in your browser.

> **Note:** Workers AI runs in Cloudflare's cloud even during local dev - you need an authenticated Wrangler session for AI calls to work.

---

## Deploying to Cloudflare

```bash
npm run deploy
```

Wrangler will output your live URL (e.g. `https://cf-ai-security-analyzer.yoursubdomain.workers.dev`).

---

## Example Queries

| Input | What happens |
|---|---|
| `https://cloudflare.com` | Full security scan + AI report |
| `Check github.com` | URL extracted, full scan runs |
| `example.com` | Normalized to `https://example.com`, scanned |
| `What does HSTS do?` | Conversational AI answer |
| `Explain DMARC vs SPF` | Conversational AI answer |
| `What does grade F mean?` | AI explains scoring |

---

## Scoring Methodology

| Category | Weight | What's Checked |
|---|---|---|
| HTTP Headers | 35% | 4 critical + 5 recommended headers |
| SSL/TLS | 30% | HTTPS validity, HSTS presence, mixed content |
| DNS Config | 20% | SPF, DMARC (+ policy strictness), DNSSEC |
| Redirects | 15% | HTTP→HTTPS enforcement, chain length |

**Grades:** A (90–100) · B (80–89) · C (70–79) · D (60–69) · F (<60)

---

## Project Structure

```
cf_ai_security_analyzer/
├── src/
│   ├── index.ts          # Worker entry point + chat API handler
│   ├── workflow.ts       # Cloudflare Workflow (multi-step pipeline)
│   ├── analyzers.ts      # Header / SSL / DNS / redirect analysis logic
│   └── types.ts          # Shared TypeScript interfaces
├── public/
│   └── index.html        # Chat UI frontend
├── build.mjs             # Build script (inlines HTML into Worker)
├── wrangler.toml         # Cloudflare deployment config
├── tsconfig.json
├── package.json
├── README.md
└── PROMPTS.md            # AI prompts used during development
```

---

## Security & Privacy

- **No data is stored.** Analysis runs entirely in-flight through the Workflow.
- **No user data is logged.** The Worker does not write to KV, D1, or any storage.
- DNS queries go through Cloudflare's own 1.1.1.1 infrastructure.

---

## Screenshots for the local-run

- **<img width="1440" height="860" alt="Screenshot 2026-05-14 at 8 03 02 PM" src="https://github.com/user-attachments/assets/e40afcc4-18a9-4b2c-a79f-df50455f4e2d" />
-
- **<img width="1440" height="862" alt="Screenshot 2026-05-14 at 8 03 37 PM" src="https://github.com/user-attachments/assets/ae780db2-ebbd-4596-ba1a-bf37a3d0ed51" />

## License

MIT
