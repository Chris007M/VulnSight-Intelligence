const rules = require('../data/riskRules.json');
const cveLookup = require('./cveLookup');
const { cvssScore, calculateOverallScore, getSeverityFromScore } = require('../utils/scoring');

async function analyze(parsedData) {
    return await Promise.all(parsedData.map(async host => {
        const openPorts = host.ports.filter(p => p.state === 'open' || p.state === 'unknown' || !p.state);
        const portsToAnalyze = openPorts.length > 0 ? openPorts : host.ports;

        const risks = await Promise.all(portsToAnalyze.map(async port => {
            const serviceLower = (port.service || '').toLowerCase();
            const rule = rules.find(r => r.service.toLowerCase() === serviceLower);
            const cves = await cveLookup(port.service);

            const ruleSeverity = rule ? rule.risk : 'Low';
            const highestCveCvss = cves.length > 0 ? Math.max(...cves.map(c => c.cvss || cvssScore(c.severity))) : cvssScore(ruleSeverity);

            const finalRiskLevel = highestCveCvss >= 9.0 ? 'Critical' :
                                   highestCveCvss >= 7.0 ? 'High' :
                                   highestCveCvss >= 4.0 ? 'Medium' : 'Low';

            return {
                port: port.port,
                protocol: port.protocol || 'tcp',
                service: port.service,
                product: port.product || '',
                version: port.version || '',
                risk: finalRiskLevel,
                cvss: highestCveCvss,
                cves: cves,
                recommendation: rule ? rule.recommendation : `Inspect service ${port.service} configuration and apply security patches.`
            };
        }));

        const hostCvssScore = calculateOverallScore(risks);
        const hostSeverity = getSeverityFromScore(hostCvssScore);

        return {
            ip: host.ip,
            hostname: host.hostname || '',
            cvssScore: hostCvssScore,
            severity: hostSeverity,
            risks: risks
        };
    }));
}

module.exports = analyze;

