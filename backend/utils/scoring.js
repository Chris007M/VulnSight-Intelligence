function cvssScore(severity) {
    if (typeof severity === 'number') return severity;
    switch (String(severity).toLowerCase()) {
        case 'critical': return 9.5;
        case 'high': return 7.5;
        case 'medium': return 5.0;
        case 'low': return 2.5;
        default: return 1.0;
    }
}

function calculateOverallScore(risks) {
    if (!risks || risks.length === 0) return 0.0;
    const scores = risks.map(r => cvssScore(r.risk || r.severity));
    const maxScore = Math.max(...scores);
    const avgScore = scores.reduce((acc, curr) => acc + curr, 0) / scores.length;
    // Weighted formula: 70% highest vulnerability + 30% average vulnerability density
    const overall = (maxScore * 0.7) + (avgScore * 0.3);
    return Math.min(10.0, parseFloat(overall.toFixed(1)));
}

function getSeverityFromScore(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score > 0) return 'Low';
    return 'Info';
}

module.exports = {
    cvssScore,
    calculateOverallScore,
    getSeverityFromScore
};

