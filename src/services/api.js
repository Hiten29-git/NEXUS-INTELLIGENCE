import axios from 'axios';

const STORAGE_KEY = 'nexus_server_url';
const DEFAULT_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

/**
 * Normalize a user-provided server URL into a valid API base URL.
 *
 * Examples:
 *   192.168.1.50:8000
 *   -> http://192.168.1.50:8000/api/v1
 *
 *   http://localhost:8000
 *   -> http://localhost:8000/api/v1
 *
 *   /api/v1
 *   -> /api/v1
 */
export function normalizeServerUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return DEFAULT_URL;
  }

  let trimmed = rawUrl.trim();

  if (!trimmed) {
    return DEFAULT_URL;
  }

  // Keep relative API paths relative.
  if (trimmed.startsWith('/')) {
    return trimmed.replace(/\/+$/, '') || '/';
  }

  // Add http:// when protocol is missing.
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `http://${trimmed}`;
  }

  // Remove trailing slashes.
  trimmed = trimmed.replace(/\/+$/, '');

  // Add /api/v1 if the user supplied only the server URL.
  if (!/\/api\/v1$/i.test(trimmed)) {
    trimmed = `${trimmed}/api/v1`;
  }

  return trimmed;
}

/**
 * Get the active NEXUS backend URL.
 *
 * Priority:
 *   1. localStorage
 *   2. VITE_API_BASE_URL
 *   3. /api/v1
 */
export function getServerBaseUrl() {
  const saved = localStorage.getItem(STORAGE_KEY);

  if (saved) {
    return normalizeServerUrl(saved);
  }

  return normalizeServerUrl(DEFAULT_URL);
}

/**
 * Set the NEXUS backend URL.
 */
export function setServerBaseUrl(newUrl) {
  const normalized = normalizeServerUrl(newUrl);

  localStorage.setItem(STORAGE_KEY, normalized);

  apiClient.defaults.baseURL = normalized;

  return normalized;
}

/**
 * Test connection to a backend server.
 */
export async function testServerConnection(url) {
  const targetUrl = normalizeServerUrl(url);
  const startTime = Date.now();

  try {
    const testClient = axios.create({
      baseURL: targetUrl,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    let response;

    try {
      response = await testClient.get('/health');
    } catch {
      response = await testClient.get('/metrics');
    }

    const latency = Date.now() - startTime;

    return {
      success: true,
      latency,
      url: targetUrl,
      status: response.status,
      data: response.data
    };
  } catch (err) {
    return {
      success: false,
      url: targetUrl,
      error:
        err?.response?.data?.message ||
        err?.response?.data?.detail ||
        err?.message ||
        'Connection timed out'
    };
  }
}

/**
 * Axios client used by the NEXUS frontend.
 */
export const apiClient = axios.create({
  baseURL: getServerBaseUrl(),
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-Nexus-System': 'NEXUS-Engine'
  }
});

/**
 * Keep Axios URL synchronized if the server URL changes.
 */
export function refreshApiClientBaseUrl() {
  apiClient.defaults.baseURL = getServerBaseUrl();

  return apiClient.defaults.baseURL;
}

/**
 * Real REST API Service Layer for NEXUS.
 */
export const nexusApi = {
  // Server configuration
  getServerBaseUrl,
  setServerBaseUrl,
  testServerConnection,
  normalizeServerUrl,
  refreshApiClientBaseUrl,

  // ---------------------------------------------------------
  // HEALTH
  // ---------------------------------------------------------

  async checkHealth() {
    return apiClient.get('/health');
  },

  // ---------------------------------------------------------
  // METRICS
  // ---------------------------------------------------------

  async getMetrics() {
    return apiClient.get('/metrics');
  },

  // ---------------------------------------------------------
  // GRAPH
  // ---------------------------------------------------------

  async getGraphTopology() {
    return apiClient.get('/graph/topology');
  },

  async rebuildGraph() {
    return apiClient.post('/graph/rebuild');
  },

  // ---------------------------------------------------------
  // ALERTS
  // ---------------------------------------------------------

  async getAlerts() {
    return apiClient.get('/alerts');
  },

  // ---------------------------------------------------------
  // ASSETS
  // ---------------------------------------------------------

  async getAssets() {
    return apiClient.get('/assets');
  },

  // ---------------------------------------------------------
  // ATTACK CHAINS
  // ---------------------------------------------------------

  async getAttackChains() {
    return apiClient.get('/attack-chains');
  },

  // ---------------------------------------------------------
  // INTELLIGENCE
  // ---------------------------------------------------------

  async getIntelligence() {
    return apiClient.get('/intelligence');
  },

  // ---------------------------------------------------------
  // BLAST RADIUS / WHAT-IF SIMULATION
  // ---------------------------------------------------------

  async getBlastRadius(startNode, maxHops = 3) {
    return apiClient.get('/blast-radius', {
      params: {
        start_node: startNode,
        max_hops: maxHops
      }
    });
  },

  // ---------------------------------------------------------
  // REMEDIATION
  // ---------------------------------------------------------

  async simulateRemediation(nodeId) {
    return apiClient.post('/remediation/simulate', {
      nodeId
    });
  }
};

/**
 * Automatically keep Axios synchronized with localStorage
 * when the browser tab becomes active again.
 */
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key === STORAGE_KEY) {
      refreshApiClientBaseUrl();
    }
  });
}

export default apiClient;
