/**
 * complianceMapper.js — VulnSight Compliance Framework Engine
 * 
 * Maps scan vulnerability findings and service exposures to major cybersecurity compliance standards:
 * - PCI-DSS v4.0
 * - NIST SP 800-53 Rev 5
 * - ISO/IEC 27001:2022
 * - CIS Controls v8
 */

function calculateCompliance(scanResults) {
    let totalRiskPoints = 0;
    let pciViolations = 0;
    let nistViolations = 0;
    let isoViolations = 0;
    let cisViolations = 0;

    const breakdown = {
        pciDss: { passed: true, score: 100, rulesTriggered: [] },
        nist: { passed: true, score: 100, rulesTriggered: [] },
        iso27001: { passed: true, score: 100, rulesTriggered: [] },
        cisControls: { passed: true, score: 100, rulesTriggered: [] }
    };

    scanResults.forEach(host => {
        if (!host.risks) return;

        host.risks.forEach(risk => {
            const sev = (risk.risk || 'Low').toLowerCase();
            const service = (risk.service || '').toLowerCase();
            const cvss = risk.cvss || 0;

            // PCI-DSS 4.0 Checks
            if (service === 'telnet' || service === 'ftp' || service === 'http') {
                pciViolations += 15;
                breakdown.pciDss.rulesTriggered.push(`Req 2.2.4: Unencrypted transmission service (${risk.service}) exposed on ${host.ip}:${risk.port}`);
            }
            if (sev === 'critical' || sev === 'high') {
                pciViolations += 20;
                breakdown.pciDss.rulesTriggered.push(`Req 6.3.1: High/Critical severity vulnerability (CVSS ${cvss}) detected on ${host.ip}:${risk.port}`);
            }

            // NIST SP 800-53 Checks
            if (sev === 'critical' || sev === 'high') {
                nistViolations += 18;
                breakdown.nist.rulesTriggered.push(`SI-2 (Flaw Remediation): Unpatched critical vulnerability on ${host.ip}:${risk.port}`);
            }
            if (service === 'ms-wbt-server' || service === 'microsoft-ds' || service === 'telnet') {
                nistViolations += 12;
                breakdown.nist.rulesTriggered.push(`CM-7 (Least Functionality): Insecure default service exposed on ${host.ip}:${risk.port}`);
            }

            // ISO 27001:2022 Checks
            if (sev === 'critical' || sev === 'high') {
                isoViolations += 15;
                breakdown.iso27001.rulesTriggered.push(`Control A.8.8 (Technical Vulnerability Management): Critical vulnerability on ${host.ip}:${risk.port}`);
            }
            if (service === 'ftp' || service === 'telnet') {
                isoViolations += 10;
                breakdown.iso27001.rulesTriggered.push(`Control A.8.20 (Network Security): Cleartext management protocol on ${host.ip}:${risk.port}`);
            }

            // CIS Controls v8 Checks
            if (sev === 'critical' || sev === 'high') {
                cisViolations += 16;
                breakdown.cisControls.rulesTriggered.push(`Control 7.4: Remediate High Severity Vulnerabilities on host ${host.ip}`);
            }
            if (service === 'telnet' || service === 'http') {
                cisViolations += 10;
                breakdown.cisControls.rulesTriggered.push(`Control 4.1: Ensure Secure Network Access Protocols on host ${host.ip}`);
            }
        });
    });

    // Compute compliance readiness percentage scores
    breakdown.pciDss.score = Math.max(0, Math.min(100, 100 - pciViolations));
    breakdown.pciDss.passed = breakdown.pciDss.score >= 80;

    breakdown.nist.score = Math.max(0, Math.min(100, 100 - nistViolations));
    breakdown.nist.passed = breakdown.nist.score >= 75;

    breakdown.iso27001.score = Math.max(0, Math.min(100, 100 - isoViolations));
    breakdown.iso27001.passed = breakdown.iso27001.score >= 80;

    breakdown.cisControls.score = Math.max(0, Math.min(100, 100 - cisViolations));
    breakdown.cisControls.passed = breakdown.cisControls.score >= 75;

    // Deduplicate rule messages
    for (const key of Object.keys(breakdown)) {
        breakdown[key].rulesTriggered = [...new Set(breakdown[key].rulesTriggered)];
    }

    return breakdown;
}

module.exports = { calculateCompliance };
