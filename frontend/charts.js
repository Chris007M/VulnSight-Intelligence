// charts.js - Helper functions for rendering Chart.js visualizations in VulnSight

let riskPieChartInstance = null;
let threatLineChartInstance = null;

function renderRiskDistributionChart(ctx, data) {
    if (riskPieChartInstance) {
        riskPieChartInstance.destroy();
    }

    riskPieChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: data,
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
                borderColor: '#0b0f19',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        font: { family: 'Inter', size: 12 },
                        padding: 16
                    }
                },
                title: {
                    display: true,
                    text: 'Vulnerability Breakdown by Severity',
                    color: '#f3f4f6',
                    font: { family: 'Inter', size: 14, weight: '600' }
                }
            },
            cutout: '65%'
        }
    });

    return riskPieChartInstance;
}

function renderThreatTrendChart(ctx, labels, values) {
    if (threatLineChartInstance) {
        threatLineChartInstance.destroy();
    }

    threatLineChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Count',
                data: values,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: 'Scan Vulnerability History',
                    color: '#f3f4f6',
                    font: { family: 'Inter', size: 14, weight: '600' }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#9ca3af' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                },
                y: {
                    ticks: { color: '#9ca3af', precision: 0 },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                }
            }
        }
    });

    return threatLineChartInstance;
}

