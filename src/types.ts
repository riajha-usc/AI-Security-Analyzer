export interface Env {
  AI: Ai;
  SECURITY_WORKFLOW: Workflow;
}

export interface SecurityAnalysisInput {
  url: string;
  chatHistory?: ChatMessage[];
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface HeaderAnalysis {
  present: string[];
  missing: string[];
  warnings: string[];
  score: number;
}

export interface SSLAnalysis {
  valid: boolean;
  issuer?: string;
  expiry?: string;
  daysUntilExpiry?: number;
  protocol?: string;
  warnings: string[];
  score: number;
}

export interface DNSAnalysis {
  hasSPF: boolean;
  hasDMARC: boolean;
  hasDNSSEC: boolean;
  records: string[];
  warnings: string[];
  score: number;
}

export interface RedirectAnalysis {
  followsHTTPS: boolean;
  redirectChain: string[];
  warnings: string[];
  score: number;
}

export interface SecurityReport {
  url: string;
  timestamp: string;
  overallScore: number;
  grade: string;
  headers: HeaderAnalysis;
  ssl: SSLAnalysis;
  dns: DNSAnalysis;
  redirects: RedirectAnalysis;
  aiInsights: string;
  recommendations: string[];
}

export interface WorkflowStepResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}
