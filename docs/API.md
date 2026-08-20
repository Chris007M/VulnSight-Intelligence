# VulnSight — REST API Documentation

This document outlines the API endpoints exposed by the VulnSight backend server.

---

## Base URL
```
http://localhost:3000
```

---

## Authentication Endpoints

### 1. Request Passcode
Generates a 6-digit authentication passcode and sends it via email (or logs it to dev console/response if SMTP is unconfigured).

- **Endpoint**: `/auth/send-code`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`

#### Request Body
```json
{
  "email": "admin@organization.com"
}
```

#### Response `200 OK` (Dev Mode Fallback)
```json
{
  "success": true,
  "devMode": true,
  "devCode": "847291",
  "message": "Verification code generated! (Dev mode code: 847291)"
}
```

#### Response `400 Bad Request`
```json
{
  "error": "Valid email address is required"
}
```

---

### 2. Verify Passcode
Verifies the provided 6-digit authentication code for an email address.

- **Endpoint**: `/auth/verify-code`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`

#### Request Body
```json
{
  "email": "admin@organization.com",
  "code": "847291"
}
```

#### Response `200 OK`
```json
{
  "success": true,
  "message": "Authentication successful"
}
```

#### Response `401 Unauthorized`
```json
{
  "error": "Invalid or expired verification code"
}
```

---

## Scan Ingestion & Analysis Endpoints

### 3. Upload Nmap Scan File
Ingests an Nmap XML scan file (`.xml`), parses hosts and ports, queries known CVE databases, computes CVSS scores, saves an audit report, and returns report analytics.

- **Endpoint**: `/upload`
- **Method**: `POST`
- **Headers**: `Content-Type: multipart/form-data`

#### Form Data Parameters
| Field Name | Type | Description | Required |
|---|---|---|---|
| `scanFile` | File (`.xml`) | Nmap XML scan output file | Yes |

#### Response `200 OK`
```json
{
  "success": true,
  "filename": "sample-scan.xml",
  "report": {
    "reportId": "report-1700000000000",
    "timestamp": "2026-08-19T18:00:00.000Z",
    "summary": {
      "totalHosts": 3,
      "totalRisks": 8,
      "critical": 3,
      "high": 3,
      "medium": 2,
      "low": 0,
      "overallCvssScore": 9.2
    },
    "details": [
      {
        "ip": "192.168.1.10",
        "hostname": "gateway-srv.local",
        "cvssScore": 7.8,
        "severity": "High",
        "risks": [
          {
            "port": "21",
            "protocol": "tcp",
            "service": "ftp",
            "product": "vsftpd",
            "version": "3.0.3",
            "risk": "High",
            "cvss": 7.8,
            "cves": [
              {
                "id": "CVE-2021-3156",
                "severity": "High",
                "cvss": 7.8,
                "description": "VSFTPD / ProFTPD unauthenticated remote buffer overflow."
              }
            ],
            "recommendation": "Disable cleartext FTP or enforce encrypted SFTP/FTPS"
          }
        ]
      }
    ]
  }
}
```

#### Response `400 Bad Request`
```json
{
  "error": "No scan file uploaded. Please select an Nmap XML file."
}
```

---

## Report Retrieval Endpoints

### 4. Fetch Historical Audit Reports
Retrieves all serialized JSON audit reports stored on the server disk.

- **Endpoint**: `/api/reports`
- **Method**: `GET`

#### Response `200 OK`
```json
{
  "reports": [
    {
      "reportId": "report-1700000000000",
      "timestamp": "2026-08-19T18:00:00.000Z",
      "summary": {
        "totalHosts": 3,
        "totalRisks": 8,
        "critical": 3,
        "high": 3,
        "medium": 2,
        "low": 0,
        "overallCvssScore": 9.2
      },
      "details": []
    }
  ]
}
```
