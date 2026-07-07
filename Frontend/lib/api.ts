// API service for communicating with the Django backend

import axios from 'axios';

// API base URL from environment variables
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

// Cache duration from environment variables or default to 5 minutes
const CACHE_DURATION = parseInt(process.env.NEXT_PUBLIC_CACHE_TTL || '300') * 1000;

// Request timeout from environment variables or default to 2 minutes
const REQUEST_TIMEOUT = parseInt(process.env.NEXT_PUBLIC_REQUEST_TIMEOUT || '120000');

// Configure axios defaults
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: REQUEST_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add authorization token if available
api.interceptors.request.use((config) => {
  const token = process.env.NEXT_PUBLIC_API_TOKEN;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Cache to store API results and reduce redundant requests
const apiCache = new Map();

export interface RiskBreakdownCategory {
  score: number;
  max: number;
  factors: string[];
}

export interface RiskBreakdownData {
  domain_name?:    RiskBreakdownCategory;
  registration?:   RiskBreakdownCategory;
  infrastructure?: RiskBreakdownCategory;
  dns_analysis?:   RiskBreakdownCategory;
  total?: number;
  entropy?: number;
  phishing?: { brand: string; similarity: number; distance: number };
  override?: string;
}

export interface ThreatIntelData {
  threat_level?: string;
  listed_on_feeds?: number;
  feeds?: {
    urlhaus?: {
      listed: boolean | null;
      urls_count?: number;
      active_urls?: number;
      tags?: string[];
      source?: string;
      error?: string;
    };
  };
}

export interface DomainAnalysisResponse {
  Domain: string;
  Domain_Exists?: boolean;
  Summary: string;
  IP_Address?: string;
  ASN_Info?: {
    asn: string;
    city: string;
    region: string;
    country: string;
    country_code?: string;
    latitude: string;
    longitude: string;
  };
  Registrar?: string;
  Country?: string;
  Updated_Date?: string;
  Creation_Date?: string;
  Expiration_Date?: string;
  Registrant_Name?: string;
  Registrant_Organization?: string;
  Subdomains?: string[];
  Historical_DNS?: any[];
  Server_Location?: {
    lat: string;
    lng: string;
  } | string;
  Security_Analysis?: {
    result: string[] | string;
    is_suspicious: boolean;
    risk_score: number;
  };
  Risk_Breakdown?: RiskBreakdownData;
  Threat_Intel?: ThreatIntelData;
  AI_Summary?: string;
  Shodan_Info?: {
    ip: string;
    ports: number[];
    hostnames: string[];
    os: string;
    isp: string;
    org: string;
    country_name: string;
    city: string;
    vulns: string[];
    last_update: string;
    services: { port: number; transport: string; product: string; version: string }[];
    error?: string;
  };
}

export interface ScanHistoryEntry {
  domain: string;
  scan_date: string;
  risk_score: number;
  is_suspicious: boolean;
  ip_address?: string;
  risk_breakdown?: RiskBreakdownData;
}

export interface ScanHistoryResponse {
  domain: string;
  history: ScanHistoryEntry[];
  count: number;
}

export interface DashboardDataResponse {
  basic_stats: {
    total_scans: number;
    total_domains: number;
    avg_risk_score: number;
    suspicious_domains: number;
    safe_domains: number;
  };
  time_based_stats: {
    today_scans: number;
    week_scans: number;
    month_scans: number;
  };
  risk_distribution: {
    range: string;
    count: number;
    percentage: number;
  }[];
  recent_scans: {
    domain: string;
    risk_score: number;
    scan_date: string;
    is_suspicious: boolean;
    ip_address: string;
    country: string;
  }[];
  daily_trends: {
    date: string;
    total_scans: number;
    suspicious_count: number;
    avg_risk_score: number;
  }[];
  top_suspicious: {
    domain: string;
    risk_score: number;
    scan_date: string;
  }[];
  geo_distribution: {
    country: string;
    count: number;
  }[];
  last_updated: string;
  pagination: {
    page: number;
    page_size: number;
    total: number;
  };
}

export interface SuspiciousDomainsParams {
  page: number;
  limit: number;
  search: string;
  filter: string | null;
}

export interface SuspiciousDomainsResponse {
  domains: {
    domain: string;
    risk_score: number;
    category: string;
    status: string;
    scan_date: string;
    is_suspicious: boolean;
    is_flagged: boolean;
  }[];
  total: number;
}

export interface ExportParams {
  search?: string;
  filter?: string | null;
}

export type AttackSurfaceNodeType = 'domain' | 'subdomain' | 'ip' | 'asn' | 'country' | 'ssl';

export interface AttackSurfaceNode {
  id: string;
  type: AttackSurfaceNodeType;
  key: string;
  label: string;
  data: Record<string, any>;
}

export interface AttackSurfaceEdge {
  id: string;
  source: string;
  target: string;
  source_type: AttackSurfaceNodeType;
  target_type: AttackSurfaceNodeType;
  relationship: 'HAS_SUBDOMAIN' | 'RESOLVES_TO' | 'BELONGS_TO' | 'LOCATED_IN' | 'USES_SSL';
}

export interface AttackSurfaceGraphResponse {
  domain: string;
  generated_at: string;
  subdomain_count: number;
  neo4j_persisted: boolean;
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  cached: boolean;
  error?: string;
}

/**
 * Cached fetch function to handle API requests with built-in caching and verbose logging
 */
async function cachedFetch(url: string, options?: RequestInit, bypassCache = false): Promise<any> {
  const cacheKey = `${url}${options ? JSON.stringify(options) : ''}`;
  const now = Date.now();

  // Enable/disable logging based on environment
  const enableLogging = process.env.NEXT_PUBLIC_ENABLE_API_LOGGING === 'true';
  if (enableLogging) {
    console.log(`API Request: ${options?.method || 'GET'} ${url}`);
  }

  // Check if using mock data
  const isUsingMock = process.env.NODE_ENV !== 'production';
  if (isUsingMock && enableLogging) {
    console.log(`API: Using mock data (process.env.NODE_ENV = ${process.env.NODE_ENV})`);
  }

  // Check cache unless told to bypass
  if (!bypassCache && apiCache.has(cacheKey)) {
    const { data, timestamp } = apiCache.get(cacheKey);
    if (now - timestamp < CACHE_DURATION) {
      if (enableLogging) console.log(`API: Using cached response for ${url}`);
      return data; // Return cached data if not expired
    }
    if (enableLogging) console.log(`API: Cache expired for ${url}`);
  }

  try {
    if (enableLogging) console.log(`API: Fetching data from ${url}`);

    // Add timeout for better error handling
    const controller = new AbortController();
    const timeoutMs = parseInt(process.env.NEXT_PUBLIC_FETCH_TIMEOUT || '10000');
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const requestOptions = {
      ...options,
      signal: controller.signal,
    };

    const response = await fetch(url, requestOptions);
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      if (enableLogging) console.error(`API Error: ${response.status} - ${response.statusText}`, errorText);
      throw new Error(`API request failed with status: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    if (enableLogging) console.log(`API Success: ${url}`);

    // Cache the result
    apiCache.set(cacheKey, { data, timestamp: now });

    return data;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      console.error(`API Timeout: Request to ${url} took too long`);
      throw new Error('Request timed out. Please check your network connection or try again later.');
    }

    console.error('API Request Error:', error);

    // Try to check if the server is running
    if (!isUsingMock) {
      try {
        await fetch(`${API_BASE_URL}/health`, { method: 'HEAD', mode: 'no-cors' });
        console.log('API: Server appears to be running but returned an error');
      } catch (serverCheckError) {
        console.error('API: Server does not appear to be running', serverCheckError);
        throw new Error('Cannot connect to the backend server. Please ensure it is running.');
      }
    }

    throw error;
  }
}

/**
 * Analyze a domain and get detailed security information
 */
export const analyzeDomain = async (domain: string): Promise<DomainAnalysisResponse> => {
  try {
    const response = await api.get('/api/analyze', {
      params: { domain },
    });
    return response.data;
  } catch (error) {
    console.error('Error analyzing domain:', error);
    throw error;
  }
};

/**
 * Get suspicious analysis for a domain
 */
export const getSuspiciousAnalysis = async (domain: string) => {
  try {
    const response = await api.get('/api/suspicious', {
      params: { domain },
    });
    return response.data;
  } catch (error) {
    console.error('Error getting suspicious analysis:', error);
    throw error;
  }
};

/**
 * Flag or unflag a domain
 */
export const flagDomain = async (domain: string, flag: boolean = true) => {
  try {
    const response = await api.post('/api/flag_domain', {
      domain,
      flag,
    });
    return response.data;
  } catch (error) {
    console.error('Error flagging domain:', error);
    throw error;
  }
};

/**
 * Get dashboard data
 */
export const getDashboardData = async () => {
  try {
    const response = await api.get('/api/dashboard');
    return response.data;
  } catch (error) {
    console.error('Error getting dashboard data:', error);
    throw error;
  }
};

/**
 * Get list of suspicious domains
 */
export const getSuspiciousDomains = async (params?: SuspiciousDomainsParams | number, limit?: number, search?: string, filter?: string) => {
  try {
    // Support both object and positional parameter styles
    let queryParams: Record<string, any>;
    if (typeof params === 'object' && params !== null && params !== undefined) {
      queryParams = {
        page: params.page,
        limit: params.limit,
        search: params.search,
        filter: params.filter,
      };
    } else {
      queryParams = {
        page: params ?? 1,
        limit: limit ?? 10,
        search: search ?? '',
        filter: filter ?? '',
      };
    }

    const response = await api.get('/api/suspicious_domains', {
      params: queryParams,
    });
    return response.data;
  } catch (error) {
    console.error('Error getting suspicious domains:', error);
    throw error;
  }
};

/**
 * Export suspicious domains as CSV (client-side generation)
 */
export const exportSuspiciousDomains = async (params?: ExportParams): Promise<Blob> => {
  try {
    // Fetch all suspicious domains (use a large limit to get them all)
    const data = await getSuspiciousDomains({
      page: 1,
      limit: 1000,
      search: params?.search || '',
      filter: params?.filter || null,
    });

    // Generate CSV content
    const headers = ['Domain', 'Risk Score', 'Category', 'Status', 'Scan Date', 'Suspicious'];
    const rows = (data.domains || []).map((d: any) => [
      d.domain,
      d.risk_score,
      d.category || 'N/A',
      d.status || 'N/A',
      d.scan_date || 'N/A',
      d.is_suspicious ? 'Yes' : 'No',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map((row: any[]) => row.map((val: any) => `"${String(val).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    return new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  } catch (error) {
    console.error('Error exporting suspicious domains:', error);
    throw error;
  }
};

/**
 * Scan a domain's attack surface (subdomains, IPs, ASN, country, SSL) and
 * return the infrastructure graph. Backed by a 12h Redis cache + Neo4j.
 */
export const attackSurfaceScan = async (domain: string): Promise<AttackSurfaceGraphResponse> => {
  try {
    const response = await api.get('/api/attack-surface/scan', {
      params: { domain },
    });
    return response.data;
  } catch (error) {
    console.error('Error scanning attack surface:', error);
    throw error;
  }
};

/**
 * Get scan history for a domain from MongoDB
 */
export const getScanHistory = async (domain: string, limit = 10): Promise<ScanHistoryResponse> => {
  try {
    const response = await api.get('/api/scan_history', { params: { domain, limit } });
    return response.data;
  } catch (error) {
    console.error('Error getting scan history:', error);
    throw error;
  }
};

export default api;