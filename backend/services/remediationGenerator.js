/**
 * remediationGenerator.js — VulnSight Automated Hardening Script Generator
 * 
 * Generates downloadable hardening code tailored to specific target hosts in 3 formats:
 * - Bash (.sh)
 * - Ansible Playbook (.yml)
 * - PowerShell (.ps1)
 */

function generateRemediationScript(hostIp, risks, format = 'bash') {
    const timestamp = new Date().toISOString();
    const fmt = format.toLowerCase().trim();

    if (fmt === 'ansible') {
        return generateAnsiblePlaybook(hostIp, risks, timestamp);
    } else if (fmt === 'powershell' || fmt === 'ps1') {
        return generatePowerShellScript(hostIp, risks, timestamp);
    } else {
        return generateBashScript(hostIp, risks, timestamp);
    }
}

function generateBashScript(hostIp, risks, timestamp) {
    let script = `#!/usr/bin/env bash
# ==============================================================================
# VulnSight Hardening & Remediation Script
# Target Host: ${hostIp}
# Generated: ${timestamp}
# ==============================================================================
set -euo pipefail

echo "[+] Starting VulnSight security hardening for host: ${hostIp}"
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo)."
  exit 1
fi

`;

    risks.forEach(r => {
        const port = r.port;
        const proto = r.protocol || 'tcp';
        const service = (r.service || '').toLowerCase();

        script += `# --- Fixing ${r.risk || 'Risk'} on Port ${port}/${proto} (${r.service}) ---\n`;

        if (service === 'telnet') {
            script += `echo "[+] Disabling Telnet daemon and blocking port ${port}..."\n`;
            script += `systemctl stop inetd 2>/dev/null || true\n`;
            script += `systemctl disable telnet.socket 2>/dev/null || true\n`;
            script += `ufw deny ${port}/${proto} || iptables -A INPUT -p ${proto} --dport ${port} -j DROP\n\n`;
        } else if (service === 'ftp') {
            script += `echo "[+] Securing FTP daemon on port ${port}..."\n`;
            script += `systemctl stop vsftpd 2>/dev/null || systemctl stop proftpd 2>/dev/null || true\n`;
            script += `ufw deny ${port}/${proto} || iptables -A INPUT -p ${proto} --dport ${port} -j DROP\n\n`;
        } else if (service === 'ms-wbt-server' || service === 'rdp') {
            script += `echo "[+] Restricting RDP network access on port ${port}..."\n`;
            script += `iptables -A INPUT -p ${proto} --dport ${port} -s 10.0.0.0/8 -j ACCEPT\n`;
            script += `iptables -A INPUT -p ${proto} --dport ${port} -j DROP\n\n`;
        } else {
            script += `echo "[+] Hardening rule applied for ${r.service} on port ${port}..."\n`;
            script += `# Recommendation: ${r.recommendation}\n`;
            script += `iptables -A INPUT -p ${proto} --dport ${port} -m state --state NEW -j LOG --log-prefix "VS-AUDIT: "\n\n`;
        }
    });

    script += `echo "[+] VulnSight Hardening execution complete for ${hostIp}."\n`;
    return script;
}

function generateAnsiblePlaybook(hostIp, risks, timestamp) {
    let yaml = `---
# ==============================================================================
# VulnSight Ansible Remediation Playbook
# Target Host: ${hostIp}
# Generated: ${timestamp}
# ==============================================================================
- name: Apply VulnSight Security Hardening to ${hostIp}
  hosts: "${hostIp}"
  become: yes
  tasks:
`;

    risks.forEach((r, idx) => {
        const port = r.port;
        const proto = r.protocol || 'tcp';
        const service = (r.service || '').toLowerCase();

        yaml += `
    - name: "Task ${idx + 1}: Secure ${r.service} on port ${port}/${proto} (${r.risk} Risk)"
      ansible.builtin.iptables:
        chain: INPUT
        protocol: "${proto}"
        destination_port: "${port}"
        jump: DROP
        comment: "VulnSight Automated Block - ${r.risk}"
`;

        if (service === 'telnet') {
            yaml += `
    - name: "Disable Telnet Service"
      ansible.builtin.service:
        name: telnet
        state: stopped
        enabled: no
      ignore_errors: yes
`;
        }
    });

    return yaml;
}

function generatePowerShellScript(hostIp, risks, timestamp) {
    let ps = `# ==============================================================================
# VulnSight Windows PowerShell Security Hardening
# Target Host: ${hostIp}
# Generated: ${timestamp}
# ==============================================================================

# Ensure Running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed as Administrator."
    Exit
}

Write-Host "[+] Initializing VulnSight Hardening for ${hostIp}..." -ForegroundColor Cyan

`;

    risks.forEach(r => {
        const port = r.port;
        const proto = (r.protocol || 'TCP').toUpperCase();
        const service = (r.service || '').toLowerCase();

        ps += `# --- Hardening ${r.service} on Port ${port} (${r.risk}) ---\n`;
        ps += `Write-Host "[+] Creating Firewall Block Rule for ${r.service} (Port ${port})..."\n`;
        ps += `New-NetFirewallRule -DisplayName "VulnSight-Block-${r.service}-${port}" -Direction Inbound -LocalPort ${port} -Protocol ${proto} -Action Block -ErrorAction SilentlyContinue\n`;

        if (service === 'telnet') {
            ps += `Stop-Service -Name "TlntSvr" -ErrorAction SilentlyContinue\n`;
            ps += `Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue\n`;
        } else if (service === 'microsoft-ds') {
            ps += `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue\n`;
        }
        ps += `\n`;
    });

    ps += `Write-Host "[+] VulnSight Hardening Completed Successfully." -ForegroundColor Green\n`;
    return ps;
}

module.exports = { generateRemediationScript };
