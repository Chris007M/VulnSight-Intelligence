# VulnSight — Vulnerability Analysis & Risk Intelligence Platform

VulnSight is a high-performance vulnerability assessment and security risk intelligence platform designed to ingest network scan reports (Nmap XML), correlate open ports/services with known Common Vulnerabilities and Exposures (CVEs), calculate standardized CVSS risk scores, and present interactive analytics via a glassmorphic dashboard.

---

## Key Features

- **Ingestion Engine**: Seamless parsing of Nmap XML scan reports supporting single and multi-host discovery.
- **CVE Correlation**: Automated lookup of service-specific vulnerabilities with CVSS 3.1 base scoring.
- **Risk Analyzer**: Dynamic weighting algorithm calculating host-level and overall system security posture.
- **Multi-Factor Auth Flow**: Email-based passcodes with automatic local development fallback for offline testing.
- **Interactive Security Dashboard**: Real-time visualization of risk distributions (pie charts) and vulnerability trends (line charts).
- **Report Generator**: Automatic serialization and persistence of audit reports to disk (`/reports`).
- **Container Ready**: Complete Docker & Docker Compose setup for production deployment.

---

## Directory Structure

```
vulnsight/
│
├── backend/
│   ├── server.js              # Express app entrypoint & static asset server
│   ├── routes/
│   │   ├── upload.js          # Nmap XML upload & analysis pipeline
│   │   └── auth.js            # Authentication passcode generation & verification
│   ├── services/
│   │   ├── xmlParser.js       # Nmap XML parser module (xml2js)
│   │   ├── riskAnalyzer.js    # Rule matching & CVE correlation engine
│   │   ├── cveLookup.js       # CVE database lookup service
│   │   └── reportGenerator.js # Report builder & disk serializer
│   ├── utils/
│   │   └── scoring.js         # CVSS weighting & severity calculation
│   └── data/
│       └── riskRules.json     # Curated network service risk definitions
│
├── frontend/
│   ├── index.html             # Glassmorphic single-page app interface
│   ├── dashboard.js           # Auth handlers, dropzone drag-and-drop, UI renderer
│   ├── charts.js              # Chart.js helper visualizations (pie/line)
│   └── styles.css             # CSS design system tokens & glassmorphic styling
│
├── docs/
│   ├── README.md              # Project documentation & overview
│   ├── DEPLOYMENT.md          # Production deployment & server configuration guide
│   └── API.md                 # REST API reference specifications
│
├── docker-compose.yml         # Container orchestration manifest
├── Dockerfile                 # Node.js production Docker build definition
├── reports/                   # Persisted JSON audit reports
├── sample-scan.xml            # Sample Nmap XML scan file for testing
└── package.json               # Dependencies & execution scripts
```

---

## Quickstart Guide

### Prerequisites
- Node.js v18.0.0 or higher
- npm v9.0.0 or higher

### Local Development Setup

1. **Clone & Install Dependencies**:
   ```bash
   npm install
   ```

2. **Launch Development Server**:
   ```bash
   npm start
   ```

3. **Access VulnSight Interface**:
   Open your browser at `http://localhost:3000`.

4. **Testing Authentication**:
   - Enter any email address (e.g., `admin@vulnsight.local`).
   - In local development mode without SMTP credentials set, the system displays the generated 6-digit passcode directly in an alert box.
   - Enter the passcode to access the dashboard.

5. **Uploading a Scan**:
   - Drag & drop `sample-scan.xml` into the ingestion dropzone or click to select the file.
   - Observe live metric updates, CVSS calculations, vulnerability breakdown charts, and host remediation details.

---

## Environment Variables

| Variable | Description | Default | Required in Production |
|---|---|---|---|
| `PORT` | HTTP server port | `3000` | No |
| `SMTP_USER` | Gmail/SMTP username for auth emails | `undefined` | Yes (for live email delivery) |
| `SMTP_PASS` | Gmail/SMTP password or app key | `undefined` | Yes (for live email delivery) |
| `NODE_ENV` | Environment string (`development`/`production`) | `development` | Recommended |


---

## License
MIT License. Developed for VulnSight Security Platform.
----

## Author
- Name: Christian MURINDANGABO  
- Email: bechris007@gmail.com   
- Phone: 0788575995  
- GitHub: [@Chris007M](https://github.com/Chris007M)
