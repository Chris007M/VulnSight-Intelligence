# VulnSight — Production Deployment Guide

This guide details step-by-step procedures for deploying VulnSight in enterprise and production environments using Docker, Docker Compose, systemd, and Nginx reverse proxies with SSL/TLS encryption.

---

## 1. Docker Deployment (Recommended)

Docker provides an isolated, reliable environment for VulnSight with minimal host dependencies.

### Prerequisites
- Docker Engine 20.10+
- Docker Compose v2.0+

### Option A: Using Docker Compose

1. **Configure Environment Variables**:
   Create a `.env` file in the root workspace directory:
   ```env
   PORT=3000
   NODE_ENV=production
   SMTP_USER=security-alerts@yourdomain.com
   SMTP_PASS=your-encrypted-app-password
   ```

2. **Build and Run Containers**:
   ```bash
   docker-compose up -d --build
   ```

3. **Verify Deployment**:
   Check container logs and health:
   ```bash
   docker-compose ps
   docker-compose logs -f vulnsight
   ```

4. **Access the Service**:
   The service is published on `http://localhost:3000` (or host IP).

---

### Option B: Building & Running Standalone Docker Container

1. **Build Container Image**:
   ```bash
   docker build -t vulnsight:latest .
   ```

2. **Run Container**:
   ```bash
   docker run -d \
     --name vulnsight-app \
     -p 3000:3000 \
     -e NODE_ENV=production \
     -e SMTP_USER="security-alerts@yourdomain.com" \
     -e SMTP_PASS="your-app-password" \
     -v $(pwd)/reports:/app/reports \
     --restart unless-stopped \
     vulnsight:latest
   ```

---

## 2. Standard Linux Deployment (systemd)

For bare-metal Linux servers or virtual machines running Ubuntu / Debian / RHEL:

1. **Prepare Application Folder**:
   ```bash
   sudo mkdir -p /var/www/vulnsight
   sudo chown -R $USER:$USER /var/www/vulnsight
   cp -r . /var/www/vulnsight/
   cd /var/www/vulnsight
   npm install --production
   ```

2. **Create systemd Service Unit**:
   Create `/etc/systemd/system/vulnsight.service`:
   ```ini
   [Unit]
   Description=VulnSight Vulnerability Analysis Service
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/var/www/vulnsight
   ExecStart=/usr/bin/node backend/server.js
   Restart=always
   RestartSec=5
   Environment=NODE_ENV=production
   Environment=PORT=3000
   Environment=SMTP_USER=security-alerts@yourdomain.com
   Environment=SMTP_PASS=your-app-password

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable & Start Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable vulnsight
   sudo systemctl start vulnsight
   sudo systemctl status vulnsight
   ```

---

## 3. Nginx Reverse Proxy & SSL Configuration

To expose VulnSight securely over HTTPS (Port 443) using Let's Encrypt:

1. **Install Nginx & Certbot**:
   ```bash
   sudo apt update
   sudo apt install nginx certbot python3-certbot-nginx -y
   ```

2. **Create Nginx Site Configuration**:
   Create `/etc/nginx/sites-available/vulnsight`:
   ```nginx
   server {
       listen 80;
       server_name vulnsight.yourdomain.com;

       location / {
           proxy_pass http://127.0.0.1:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           
           # Upload limit for large Nmap XML scans
           client_max_body_size 50M;
       }
   }
   ```

3. **Enable Site & Obtain SSL Certificate**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/vulnsight /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   sudo certbot --nginx -d vulnsight.yourdomain.com
   ```

---

## 4. Security Hardening & Maintenance

- **Report Backup**: Regularly back up the `/app/reports` directory where audit reports are stored.
- **Firewall Rules**: Block incoming traffic on port 3000 from public internet; only allow access via local interface or Nginx proxy.
- **Node Permissions**: Run Node.js process under unprivileged service user (`www-data` or node user).
