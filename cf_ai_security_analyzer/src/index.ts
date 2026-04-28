import { SecurityAnalysisWorkflow } from "./workflow";
import type { Env, ChatMessage } from "./types";

export { SecurityAnalysisWorkflow };

// ── HTML served from the Worker (embedded at build time) ──────────────────────
const HTML = `__HTML_PLACEHOLDER__`;

// ── Main Worker ───────────────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Serve the frontend
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // Chat API endpoint
    if (url.pathname === "/api/chat" && request.method === "POST") {
      return handleChat(request, env);
    }

    // Workflow status endpoint (for polling)
    if (url.pathname.startsWith("/api/status/") && request.method === "GET") {
      return handleStatus(url, env);
    }

    return new Response("Not Found", { status: 404 });
  },
};

// ── Chat Handler ──────────────────────────────────────────────────────────────
async function handleChat(request: Request, env: Env): Promise<Response> {
  let body: { message: string; url?: string; history?: ChatMessage[] };

  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400);
  }

  const { message, url: targetUrl, history = [] } = body;

  if (!message) return jsonError("Missing message field", 400);

  // If a URL was detected in the message, run the full security analysis
  if (targetUrl) {
    try {
      new URL(targetUrl); // validate
    } catch {
      return jsonResponse({
        message: `I couldn't parse that as a valid URL. Try something like \`https://example.com\``,
      });
    }

    try {
      // Create a Workflow instance
      const instance = await env.SECURITY_WORKFLOW.create({
        params: { url: targetUrl },
      });

      // Poll for completion (Workflows are async; we wait synchronously here
      // for demo purposes — in production you'd use webhooks or SSE)
      const report = await pollWorkflow(instance, 45_000);
      return jsonResponse({ report });
    } catch (err) {
      console.error("Workflow error:", err);
      return jsonResponse({
        message: `Security analysis failed: ${err instanceof Error ? err.message : "Unknown error"}. Please check the URL and try again.`,
      });
    }
  }

  // No URL — answer as a knowledgeable security assistant
  const aiReply = await handleConversational(message, history, env);
  return jsonResponse({ message: aiReply });
}

// ── Poll Workflow until complete ──────────────────────────────────────────────
async function pollWorkflow(
  instance: WorkflowInstance,
  timeoutMs: number,
): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  const pollInterval = 1500;

  while (Date.now() < deadline) {
    const status = await instance.status();

    if (status.status === "complete") {
      return (status as any).output;
    }

    if (status.status === "errored" || status.status === "terminated") {
      throw new Error(
        `Workflow ${status.status}: ${JSON.stringify((status as any).error || {})}`,
      );
    }

    // Still running — wait and poll again
    await sleep(pollInterval);
  }

  throw new Error(
    "Analysis timed out after 45 seconds. The target may be slow or unreachable.",
  );
}

// ── Conversational (no URL) ───────────────────────────────────────────────────
async function handleConversational(
  message: string,
  history: ChatMessage[],
  env: Env,
): Promise<string> {
  const messages = [
    ...history.slice(-8).map((m) => ({ role: m.role, content: m.content })),
    { role: "user" as const, content: message },
  ];

  try {
    const response = await env.AI.run(
      "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
      {
        messages: [
          {
            role: "system",
            content: `You are SentinelAI, a web security expert assistant built on Cloudflare Workers AI. You help developers understand web security concepts, analyze threats, and improve their site's security posture.

You specialize in: HTTP security headers (HSTS, CSP, X-Frame-Options, etc.), SSL/TLS configuration, DNS security (SPF, DMARC, DNSSEC), HTTPS enforcement, OWASP top 10, and Cloudflare security features.

When users provide a URL, the system automatically runs a technical scan. For general questions, provide expert but approachable answers. Keep responses concise and practical. Use markdown-style formatting with **bold** for emphasis.

If users ask what grades mean: A=90-100 (excellent), B=80-89 (good), C=70-79 (fair), D=60-69 (needs work), F=<60 (critical issues).`,
          },
          ...messages,
        ],
        max_tokens: 512,
      },
    );

    return (
      (response as any).response ||
      "I couldn't generate a response. Please try again."
    );
  } catch (err) {
    return `I encountered an error: ${err instanceof Error ? err.message : "Unknown"}. Please try again.`;
  }
}

// ── Status endpoint ───────────────────────────────────────────────────────────
async function handleStatus(url: URL, env: Env): Promise<Response> {
  const instanceId = url.pathname.replace("/api/status/", "");
  if (!instanceId) return jsonError("Missing instance ID", 400);

  try {
    const instance = await env.SECURITY_WORKFLOW.get(instanceId);
    const status = await instance.status();
    return jsonResponse(status);
  } catch (err) {
    return jsonError(`Instance not found: ${instanceId}`, 404);
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function jsonError(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
