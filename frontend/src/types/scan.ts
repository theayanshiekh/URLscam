export type Classification = "legitimate" | "suspicious" | "phishing";

export interface RiskFactor {
  name: string;
  severity: string;
  score: number;
  explanation: string;
  evidence?: string;
  what_it_means?: string;
  why_it_matters?: string;
  what_to_do?: string;
}

export interface UrlBreakdown {
  scheme?: string | null;
  username?: string | null;
  hostname?: string | null;
  port?: number | null;
  path?: string | null;
  query?: string | null;
  fragment?: string | null;
  registrable_domain?: string | null;
  subdomains: string[];
  tld?: string | null;
  is_ip: boolean;
  punycode: boolean;
  suspicious_components: string[];
}

export interface AnalyzeResult {
  id?: number | null;
  url: string;
  normalized_url: string;
  classification: Classification;
  risk_score: number;
  confidence: number;
  threat_level: string;
  summary: string;
  recommendation: string;
  features: Record<string, unknown>;
  risk_factors: RiskFactor[];
  url_breakdown: UrlBreakdown;
  analysis_sources: string[];
  ml: Record<string, unknown>;
  intel: Record<string, unknown>;
  https_note: string;
  confidence_note: string;
  demo: boolean;
  created_at?: string | null;
  stages: string[];
}

export interface HistoryItem {
  id: number;
  url: string;
  classification: string;
  risk_score: number;
  confidence: number;
  threat_level: string;
  created_at: string;
  demo: boolean;
}
