import axios from 'axios';

const STORAGE_KEY = 'nexus_server_url';
const DEFAULT_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

/**
 * Normalizes user-input IP/URL into a valid HTTP endpoint
 * Example: '192.168.1.50:8000' -> 'http://192.168.1.50:8000/api/v1'
 */
export function normalizeServerUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return DEFAULT_URL;
  let trimmed = rawUrl.trim();
  
  // Prepend http:// if protocol is missing
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `http://${trimmed}`;
  }
  
  // Remove trailing slashes
  trimmed = trimmed.replace(/\/+$/, '');

  // If path doesn't contain /api/v1 or /api, append /api/v1
  if (!/\/api(\/v\d+)?$/i.test(trimmed)) {
    trimmed = `${trimmed}/api/v1`;
  }

  return trimmed;
}

/**
 * Gets the active server base URL (localStorage > .env > default)
 */
export function getServerBaseUrl() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) return saved;
  return normalizeServerUrl(DEFAULT_URL);
}

// Create configured Axios instance
export const apiClient = axios.create({
  baseURL: getServerBaseUrl(),
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-Nexus-System': 'NEXUS-Engine'
  }
});

/**
 * Sets a new server base URL and notifies the application
 */
export function setServerBaseUrl(newUrl) {
  const normalized = normalizeServerUrl(newUrl);
  localStorage.setItem(STORAGE_KEY, normalized);
  apiClient.defaults.baseURL = normalized;
  window.dispatchEvent(new CustomEvent('nexus_server_url_changed', { detail: normalized }));
  return normalized;
}

/**
 * Tests connection to a given server URL before saving
 */
export async function testServerConnection(url) {
  const targetUrl = normalizeServerUrl(url);
  const startTime = Date.now();
  try {
    const testClient = axios.create({
      baseURL: targetUrl,
      timeout: 5000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    // Try /health probe first, then fallback to /metrics
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
      error: err.response?.data?.message || err.message || 'Connection timed out'
    };
  }
}

/**
 * Real REST API Service Layer for NEXUS
 */
export const nexusApi = {
  getServerBaseUrl,
  setServerBaseUrl,
  testServerConnection,
  normalizeServerUrl,

  async checkHealth() {
    return apiClient.get('/health');
  },

  async getMetrics() {
    return apiClient.get('/metrics');
  },

  async getGraphTopology() {
    return apiClient.get('/graph/topology');
  },

  async getAlerts() {
    return apiClient.get('/alerts');
  },

  async getAssets() {
    return apiClient.get('/assets');
  },

  async getAttackChains() {
    return apiClient.get('/attack-chains');
  },

  async simulateRemediation(nodeId) {
    return apiClient.post('/remediation/simulate', { nodeId });
  }
};

export default apiClient;
