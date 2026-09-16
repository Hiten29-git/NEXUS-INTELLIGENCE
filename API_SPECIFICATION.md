# NEXUS Intelligence - Backend REST API Specification

This document details the REST API endpoints and JSON response schemas expected by the **NEXUS Intelligence** frontend dashboard.

Base URL: `http://localhost:8000/api/v1` (configured via `VITE_API_BASE_URL` in `.env`)

---

## 1. Health Probe
- **Endpoint**: `GET /health`
- **Description**: Probes backend service and database/graph status.
- **Success Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "engine": "NEXUS-Intelligence-Engine"
}
```

---

## 2. System KPI Metrics
- **Endpoint**: `GET /metrics`
- **Description**: Executive dashboard posture scores and high-level telemetry.
- **Success Response (200 OK)**:
```json
{
  "securityPostureScore": 72,
  "activeAttackPaths": 3,
  "compromisedNodes": 2,
  "criticalVulnerabilities": 8,
  "totalAssets": 24,
  "meanTimeToRemediate": "18m",
  "threatLevel": "HIGH",
  "blockedAttempts24h": 1420
}
```

---

## 3. Attack Graph Topology
- **Endpoint**: `GET /graph/topology`
- **Description**: Cytoscape.js compatible graph element list containing nodes (hosts, firewalls, threat actors) and directed attack edges.
- **Success Response (200 OK)**:
```json
[
  {
    "data": {
      "id": "node-attacker",
      "label": "Threat Actor\n(APT29)",
      "type": "attacker",
      "ip": "198.51.100.44",
      "risk": 10.0,
      "status": "active"
    }
  },
  {
    "data": {
      "id": "node-firewall",
      "label": "Perimeter\nFirewall",
      "type": "firewall",
      "ip": "198.51.100.1",
      "risk": 2.1,
      "status": "healthy"
    }
  },
  {
    "data": {
      "id": "edge-1",
      "source": "node-attacker",
      "target": "node-firewall",
      "type": "exploit",
      "label": "Port Scan / Recon",
      "critical": true
    }
  }
]
```

---

## 4. Live Security Alerts
- **Endpoint**: `GET /alerts`
- **Description**: Stream of detected security incidents mapped to MITRE ATT&CK techniques.
- **Success Response (200 OK)**:
```json
[
  {
    "id": "ALT-9041",
    "title": "Log4j RCE Injection Detected",
    "severity": "CRITICAL",
    "target": "DMZ-WEB-01 (10.0.1.15)",
    "source": "198.51.100.44",
    "timestamp": "2 mins ago",
    "mitre": "T1190 - Initial Access",
    "status": "Active"
  }
]
```

---

## 5. Enterprise Asset Inventory
- **Endpoint**: `GET /assets`
- **Description**: Detailed host inventory, criticality levels, open ports, and discovered CVEs.
- **Success Response (200 OK)**:
```json
[
  {
    "id": "AST-01",
    "hostname": "DMZ-WEB-01",
    "ip": "10.0.1.15",
    "role": "Public Web Portal (Tomcat)",
    "os": "Ubuntu 22.04 LTS",
    "status": "COMPROMISED",
    "criticality": "HIGH",
    "riskScore": 9.4,
    "vulnerabilities": [
      { "cve": "CVE-2021-44228", "name": "Log4Shell RCE", "cvss": 10.0, "severity": "CRITICAL" }
    ],
    "openPorts": [80, 443, 8080],
    "blastRadius": 4
  }
]
```

---

## 6. Primary Active Attack Chains
- **Endpoint**: `GET /attack-chains`
- **Description**: Step-by-step killchain paths from initial compromise to target assets.
- **Success Response (200 OK)**:
```json
[
  {
    "id": "CHAIN-01",
    "title": "Initial Breach to Domain Controller Takeover",
    "severity": "CRITICAL",
    "likelihood": "98%",
    "cvssScore": 9.8,
    "steps": [
      "External Reconnaissance & Port Scanning (198.51.100.44)",
      "Exploitation of Log4j (CVE-2021-44228) on DMZ-WEB-01",
      "Lateral Movement via SMB (T1021.002) to Admin Workstation IT-04",
      "Credential Dumping via DCSync / Mimikatz (T1003.006)",
      "Full Domain Compromise on Primary Domain Controller DC-01"
    ],
    "mitigation": "Isolate DMZ-WEB-01 immediately and apply Log4j >= 2.17.1 patch to sever incoming exploit path."
  }
]
```

---

## 7. Remediation Simulation
- **Endpoint**: `POST /remediation/simulate`
- **Request Body**:
```json
{
  "nodeId": "node-dmz-web"
}
```
- **Success Response (200 OK)**:
```json
{
  "isolatedNodeId": "node-dmz-web",
  "newPostureScore": 86,
  "mitigatedAttackPaths": 2,
  "message": "Node [node-dmz-web] quarantined. Attack vectors successfully severed.",
  "elements": [ ... ]
}
```
