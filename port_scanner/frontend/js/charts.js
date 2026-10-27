/**
 * Chart.js Visualization Module for Explainable AI & Port Intelligence
 */

const chartInstances = {};

function destroyChartIfExists(key) {
    if (chartInstances[key]) {
        chartInstances[key].destroy();
        delete chartInstances[key];
    }
}

/**
 * Renders the circular network risk score gauge (0 to 100)
 */
function renderRiskScoreGauge(canvasId, score, tier) {
    destroyChartIfExists(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    // Determine gauge color based on score
    let gaugeColor = '#10b981'; // Safe
    if (score > 80) gaugeColor = '#ef4444'; // Critical
    else if (score > 60) gaugeColor = '#f97316'; // High
    else if (score > 40) gaugeColor = '#f59e0b'; // Medium
    else if (score > 20) gaugeColor = '#38bdf8'; // Low

    const remainder = Math.max(0, 100 - score);

    chartInstances[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, remainder],
                backgroundColor: [gaugeColor, 'rgba(255, 255, 255, 0.08)'],
                borderWidth: 0,
                circumference: 240,
                rotation: 240,
                cutout: '80%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            },
            animation: {
                animateRotate: true,
                duration: 1200
            }
        }
    });

    // Update center text display
    const scoreNumEl = document.getElementById('gauge-score-value');
    const scoreTierEl = document.getElementById('gauge-tier-value');
    if (scoreNumEl) scoreNumEl.textContent = `${Math.round(score)}`;
    if (scoreTierEl) {
        scoreTierEl.textContent = `${tier.toUpperCase()} RISK`;
        scoreTierEl.style.color = gaugeColor;
        scoreTierEl.style.backgroundColor = `${gaugeColor}22`;
        scoreTierEl.style.border = `1px solid ${gaugeColor}44`;
    }
}

/**
 * Renders the Port Risk Breakdown Doughnut Chart
 */
function renderRiskDistributionChart(canvasId, counts) {
    destroyChartIfExists(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const labels = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
    const data = [
        counts.Safe || 0,
        counts.Low || 0,
        counts.Medium || 0,
        counts.High || 0,
        counts.Critical || 0
    ];

    chartInstances[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#10b981', // Safe
                    '#38bdf8', // Low
                    '#f59e0b', // Medium
                    '#f97316', // High
                    '#ef4444'  // Critical
                ],
                borderColor: '#0f172a',
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
                        color: '#94a3b8',
                        font: { size: 11, family: 'Inter' },
                        boxWidth: 12,
                        padding: 12
                    }
                }
            }
        }
    });
}

/**
 * Renders Global Feature Importance (Random Forest feature attributions)
 */
function renderGlobalFeatureImportanceChart(canvasId, featuresList) {
    destroyChartIfExists(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const labels = featuresList.map(f => f.feature);
    const data = featuresList.map(f => f.importance_pct);

    chartInstances[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Relative Feature Contribution (%)',
                data: data,
                backgroundColor: 'rgba(0, 240, 255, 0.75)',
                borderColor: '#00f0ff',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255, 255, 255, 0.06)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e2e8f0', font: { family: 'Inter', size: 11, weight: '500' } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (context) => ` Importance: ${context.raw}%`
                    }
                }
            }
        }
    });
}

/**
 * Renders Local Feature Contribution for a specific port instance (Waterfall / Diverging Bar)
 */
function renderLocalXAIWaterfall(canvasId, localContribs) {
    destroyChartIfExists(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const labels = localContribs.map(c => c.feature);
    const values = localContribs.map(c => c.impact);
    const colors = values.map(v => v >= 0 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(16, 185, 129, 0.8)');
    const borderColors = values.map(v => v >= 0 ? '#ef4444' : '#10b981');

    chartInstances[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk Impact (%)',
                data: values,
                backgroundColor: colors,
                borderColor: borderColors,
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.06)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e2e8f0', font: { family: 'Inter', size: 11 } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (context) => {
                            const val = context.raw;
                            return val >= 0 ? ` +${val}% (Increases Risk)` : ` ${val}% (Reduces Risk)`;
                        }
                    }
                }
            }
        }
    });
}
