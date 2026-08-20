const fs = require('fs');
const path = require('path');
const { calculateOverallScore } = require('../utils/scoring');
const { calculateCompliance } = require('./complianceMapper');

function generateReport(results) {
    const reportId = `report-${Date.now()}`;
    const timestamp = new Date().toISOString();

    let totalRisks = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    const allRiskItems = [];

    results.forEach(host => {
        if (host.risks) {
            host.risks.forEach(r => {
                totalRisks++;
                allRiskItems.push(r);
                const level = (r.risk || '').toLowerCase();
                if (level === 'critical') criticalCount++;
                else if (level === 'high') highCount++;
                else if (level === 'medium') mediumCount++;
                else lowCount++;
            });
        }
    });

    const systemCvssScore = calculateOverallScore(allRiskItems);
    const complianceData = calculateCompliance(results);

    const report = {
        reportId,
        timestamp,
        summary: {
            totalHosts: results.length,
            totalRisks,
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: lowCount,
            overallCvssScore: systemCvssScore
        },
        compliance: complianceData,
        details: results
    };

    // Save report to disk in reports/ directory
    try {
        const reportsDir = path.join(__dirname, '../../reports');
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }
        const filePath = path.join(reportsDir, `${reportId}.json`);
        fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');
    } catch (err) {
        console.error('Failed to write report to disk:', err.message);
    }

    return report;
}

module.exports = generateReport;
