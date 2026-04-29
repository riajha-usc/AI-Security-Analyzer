**AI-powered web security analyzer** built on Cloudflare Workers, Workflows, and Workers AI (Llama 3.3 70B).

## What It Does

SentinelAI is a chat-based security analysis tool. You enter any URL or domain, and it:

1. **Scans HTTP security headers** - checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more
2. **Verifies SSL/TLS configuration** - detects HTTPS enforcement, certificate validity, mixed content signals
3. **Queries DNS records** - checks for SPF, DMARC, DNSSEC using Cloudflare's 1.1.1.1 DNS-over-HTTPS API
4. **Traces the redirect chain** - follows HTTP→HTTPS redirects and flags loops or excessive hops
5. **Runs Llama 3.3 70B threat analysis** - synthesizes all gathered data into a prioritized, actionable security report with an A–F grade

You can also ask general security questions in the chat (e.g. *"What does HSTS do?"* or *"What's the difference between SPF and DMARC?"*).

---
