/**
 * Dashboard & User Interface State Management Module
 * Supports mobile navigation, responsive tables, XAI drawer, vulnerability matrix, and PDF generation.
 */

const Dashboard = {
    currentPorts: [],
    selectedPort: null,
    globalXaiData: null,

    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.setupMobileMenu();
        
        // Initial health & global data fetch
        Analyzer.checkHealth();
        this.loadGlobalXai();
        this.loadHistoricalScans();
        this.loadStatistics();

        // Run default demo scan on load for instant visualization
        Analyzer.runScan('192.168.1.10', 'demo', 'enterprise');
    },

    setupNavigation() {
        const navButtons = document.querySelectorAll('.nav-item button');
        navButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetTab = btn.getAttribute('data-tab');
                this.switchTab(targetTab);
                
                // Close mobile menu if open
                document.getElementById('sidebar')?.classList.remove('open');
            });
        });
    },

    switchTab(tabId) {
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

        const activeSection = document.getElementById(`tab-${tabId}`);
        const activeNavBtn = document.querySelector(`[data-tab="${tabId}"]`)?.parentElement;

        if (activeSection) activeSection.classList.add('active');
        if (activeNavBtn) activeNavBtn.classList.add('active');

        // Trigger chart resizes if switching to chart tabs
        if (tabId === 'xai' && this.globalXaiData) {
            renderGlobalFeatureImportanceChart('global-xai-chart', this.globalXaiData);
            if (this.selectedPort) {
                this.renderXaiStudio(this.selectedPort);
            }
        } else if (tabId === 'reports' && Analyzer.currentScan) {
            this.generateReportView(Analyzer.currentScan);
        } else if (tabId === 'vulnerability') {
            this.renderVulnerabilityCards(this.currentPorts);
        }
    },

    setupMobileMenu() {
        const toggleBtn = document.getElementById('mobile-nav-toggle');
        const sidebar = document.getElementById('sidebar');
        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener('click', () => {
                sidebar.classList.toggle('open');
            });
        }
    },

    setupEventListeners() {
        // Start Analysis Button
        const startBtn = document.getElementById('btn-start-scan');
        if (startBtn) {
            startBtn.addEventListener('click', () => {
                const target = document.getElementById('target-input')?.value.trim() || '192.168.1.10';
                const scanType = document.getElementById('scan-type-select')?.value || 'demo';
                const preset = document.getElementById('preset-select')?.value || 'enterprise';
                Analyzer.runScan(target, scanType, preset);
            });
        }

        // Demo Scan Button
        const demoBtn = document.getElementById('btn-demo-scan');
        if (demoBtn) {
            demoBtn.addEventListener('click', () => {
                const preset = document.getElementById('preset-select')?.value || 'enterprise';
                Analyzer.runScan('192.168.1.10', 'demo', preset);
            });
        }

        // Search & Filter in Port Intelligence Table
        const searchInput = document.getElementById('port-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterPortsTable(e.target.value);
            });
        }

        const filterSelect = document.getElementById('risk-filter-select');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                this.filterPortsByRisk(e.target.value);
            });
        }

        // Preset selector auto-update target input
        const presetSelect = document.getElementById('preset-select');
        if (presetSelect) {
            presetSelect.addEventListener('change', (e) => {
                const map = {
                    enterprise: '192.168.1.10',
                    scada: '10.0.4.55',
                    cloud: '172.24.0.12',
                    hardened: '10.10.10.1'
                };
                const targetInput = document.getElementById('target-input');
                if (targetInput && map[e.target.value]) {
                    targetInput.value = map[e.target.value];
                }
            });
        }

        // PDF Export Button
        const exportPdfBtn = document.getElementById('btn-export-pdf');
        if (exportPdfBtn) {
            exportPdfBtn.addEventListener('click', () => {
                this.exportReportAsPdf();
            });
        }
    },

    /**
     * Renders scan outcomes across all views
     */
    renderScanResults(scan) {
        if (!scan) return;
        this.currentPorts = scan.ports || [];

        // 1. Update Metrics Cards
        document.getElementById('metric-total-ports').textContent = scan.total_ports || 0;
        document.getElementById('metric-open-ports').textContent = scan.open_ports || 0;
        document.getElementById('metric-vuln-ports').textContent = scan.vulnerable_ports || 0;
        document.getElementById('metric-critical-ports').textContent = scan.critical_risks || 0;

        // 2. Render Gauge
        renderRiskScoreGauge('risk-gauge-canvas', scan.risk_score, scan.risk_tier);

        // 3. Render Distribution Chart
        const riskCounts = { Safe: 0, Low: 0, Medium: 0, High: 0, Critical: 0 };
        this.currentPorts.forEach(p => {
            if (riskCounts[p.risk_level] !== undefined) riskCounts[p.risk_level]++;
        });
        renderRiskDistributionChart('risk-distribution-chart', riskCounts);

        // 4. Render Port Intelligence Tables
        this.renderPortsTable(this.currentPorts);

        // 5. Render Vulnerability Cards
        this.renderVulnerabilityCards(this.currentPorts);

        // 6. Setup XAI with the most critical port
        if (this.currentPorts.length > 0) {
            const sortedByRisk = [...this.currentPorts].sort((a, b) => {
                const weight = { Critical: 5, High: 4, Medium: 3, Low: 2, Safe: 1 };
                return (weight[b.risk_level] || 0) - (weight[a.risk_level] || 0);
            });
            this.selectedPort = sortedByRisk[0];
            this.renderXaiStudio(this.selectedPort);
            this.renderXaiDropdown();
        }

        // 7. Update Target and Status Badges
        const currentTargetBadge = document.getElementById('header-current-target');
        if (currentTargetBadge) {
            currentTargetBadge.textContent = scan.target;
        }
    },

    /**
     * Populates the Port Intelligence Data Table
     */
    renderPortsTable(ports) {
        const tbodies = [
            document.getElementById('ports-table-body'),
            document.getElementById('ports-table-body-full')
        ];

        tbodies.forEach(tbody => {
            if (!tbody) return;
            tbody.innerHTML = '';

            if (!ports || ports.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:24px;">No ports match the selected criteria.</td></tr>`;
                return;
            }

            ports.forEach(port => {
                const tr = document.createElement('tr');
                const confPct = Math.round((port.confidence || 0.9) * 100);

                tr.innerHTML = `
                    <td><span class="port-badge">${port.port}</span></td>
                    <td><span style="font-family:var(--font-mono);font-size:12px;">${port.protocol}</span></td>
                    <td><strong>${port.service}</strong></td>
                    <td><span style="color:${port.state === 'Open' ? '#10b981' : '#94a3b8'};">${port.state}</span></td>
                    <td style="color:#94a3b8;font-size:12px;">${port.version || 'Standard'}</td>
                    <td><span class="badge-risk ${port.risk_level}">${port.risk_level}</span></td>
                    <td>
                        <div class="confidence-bar">
                            <div class="progress-track"><div class="progress-fill" style="width:${confPct}%;"></div></div>
                            <span style="font-family:var(--font-mono);font-size:11px;">${confPct}%</span>
                        </div>
                    </td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="Dashboard.inspectPort(${port.port})">
                            <i class="fas fa-microchip"></i> Explain XAI
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        });
    },

    filterPortsTable(query) {
        const q = query.toLowerCase();
        const filtered = this.currentPorts.filter(p => 
            p.port.toString().includes(q) ||
            p.service.toLowerCase().includes(q) ||
            (p.version && p.version.toLowerCase().includes(q)) ||
            p.risk_level.toLowerCase().includes(q)
        );
        this.renderPortsTable(filtered);
    },

    filterPortsByRisk(riskLevel) {
        if (!riskLevel || riskLevel === 'All') {
            this.renderPortsTable(this.currentPorts);
        } else {
            const filtered = this.currentPorts.filter(p => p.risk_level.toLowerCase() === riskLevel.toLowerCase());
            this.renderPortsTable(filtered);
        }
    },

    /**
     * Renders rich interactive vulnerability & hardening cards
     */
    renderVulnerabilityCards(ports) {
        const container = document.getElementById('vulnerability-cards-container');
        if (!container) return;
        container.innerHTML = '';

        if (!ports || ports.length === 0) {
            container.innerHTML = `<div style="color:#94a3b8;padding:20px;">No vulnerability data available.</div>`;
            return;
        }

        ports.forEach(p => {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.borderLeft = `4px solid ${
                p.risk_level === 'Critical' ? '#ef4444' :
                p.risk_level === 'High' ? '#f97316' :
                p.risk_level === 'Medium' ? '#f59e0b' :
                p.risk_level === 'Low' ? '#38bdf8' : '#10b981'
            }`;

            const recsList = (p.recommendations || []).map(r => `
                <li style="margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;">
                    <i class="fas fa-shield-alt" style="color:var(--accent-cyan);margin-top:3px;"></i>
                    <span>${r}</span>
                </li>
            `).join('');

            card.innerHTML = `
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <div>
                        <strong style="font-size:15px;color:#fff;">Port ${p.port} (${p.service})</strong>
                        <div style="font-size:11px;color:#94a3b8;">${p.protocol} &bull; ${p.version || 'Standard'}</div>
                    </div>
                    <span class="badge-risk ${p.risk_level}">${p.risk_level}</span>
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;background:rgba(10,15,29,0.7);padding:10px;border-radius:6px;margin-bottom:12px;font-size:11px;">
                    <div>CVSS Score: <strong style="color:var(--accent-amber);">${p.cvss_score || '0.0'}/10</strong></div>
                    <div>Confidence: <strong style="color:var(--accent-blue);">${Math.round(p.confidence * 100)}%</strong></div>
                    <div>Transport: <strong>${p.encryption_detected ? 'TLS Protected' : 'Cleartext'}</strong></div>
                    <div>Exposure: <strong>${p.exposure_level || 'External'}</strong></div>
                </div>

                <div style="font-size:12px;color:#e2e8f0;margin-bottom:12px;line-height:1.5;">
                    <em>${p.xai?.ai_explanation || ''}</em>
                </div>

                <div style="border-top:1px solid rgba(56,189,248,0.1);padding-top:10px;">
                    <div style="font-size:11px;font-weight:700;color:var(--accent-cyan);text-transform:uppercase;margin-bottom:8px;">
                        <i class="fas fa-wrench"></i> Hardening Actions:
                    </div>
                    <ul style="list-style:none;">${recsList}</ul>
                </div>
            `;
            container.appendChild(card);
        });
    },

    /**
     * Inspects a single port and opens the detailed modal drawer
     */
    inspectPort(portNumber) {
        const port = this.currentPorts.find(p => p.port === portNumber);
        if (!port) return;

        this.selectedPort = port;
        const modal = document.getElementById('port-inspect-modal');
        const modalTitle = document.getElementById('modal-port-title');
        const modalContent = document.getElementById('modal-port-body');

        if (modalTitle) modalTitle.innerHTML = `<i class="fas fa-shield-virus"></i> Vulnerability Deep-Dive: Port ${port.port} (${port.service})`;

        if (modalContent) {
            const reasonsHtml = (port.xai?.reasons || []).map(r => `
                <li style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                    <i class="fas fa-check-circle" style="color:var(--accent-emerald);"></i>
                    <span>${r.text}</span>
                </li>
            `).join('');

            const recsHtml = (port.recommendations || []).map(rec => `
                <li style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px;">
                    <i class="fas fa-shield-alt" style="color:var(--accent-cyan);margin-top:4px;"></i>
                    <span>${rec}</span>
                </li>
            `).join('');

            modalContent.innerHTML = `
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:12px;margin-bottom:16px;">
                    <div style="background:rgba(10,15,29,0.7);padding:10px;border-radius:6px;">
                        <div style="font-size:11px;color:#94a3b8;">RISK LEVEL</div>
                        <div style="margin-top:4px;"><span class="badge-risk ${port.risk_level}">${port.risk_level}</span></div>
                    </div>
                    <div style="background:rgba(10,15,29,0.7);padding:10px;border-radius:6px;">
                        <div style="font-size:11px;color:#94a3b8;">CONFIDENCE</div>
                        <div style="font-size:16px;font-weight:700;color:#fff;font-family:var(--font-mono);margin-top:4px;">${Math.round(port.confidence * 100)}%</div>
                    </div>
                    <div style="background:rgba(10,15,29,0.7);padding:10px;border-radius:6px;">
                        <div style="font-size:11px;color:#94a3b8;">CVSS BASELINE</div>
                        <div style="font-size:16px;font-weight:700;color:var(--accent-amber);font-family:var(--font-mono);margin-top:4px;">${port.cvss_score || 'N/A'}/10.0</div>
                    </div>
                    <div style="background:rgba(10,15,29,0.7);padding:10px;border-radius:6px;">
                        <div style="font-size:11px;color:#94a3b8;">ENCRYPTION</div>
                        <div style="font-size:14px;font-weight:600;color:${port.encryption_detected ? '#10b981' : '#ef4444'};margin-top:4px;">
                            ${port.encryption_detected ? 'TLS Protected' : 'Cleartext Detected'}
                        </div>
                    </div>
                </div>

                <div class="xai-card" style="margin-bottom:16px;">
                    <div class="xai-badge"><i class="fas fa-brain"></i> Explainable AI Justification</div>
                    <ul class="xai-reasons-list">${reasonsHtml}</ul>
                    <div class="xai-quote-box">
                        "${port.xai?.ai_explanation || ''}"
                    </div>
                </div>

                <div style="background:rgba(10,15,29,0.7);padding:16px;border-radius:8px;border:1px solid rgba(56,189,248,0.15);">
                    <h4 style="font-size:13px;color:var(--accent-cyan);text-transform:uppercase;margin-bottom:12px;">
                        <i class="fas fa-tools"></i> Recommended Defensive Actions
                    </h4>
                    <ul style="list-style:none;font-size:13px;color:#cbd5e1;">${recsHtml}</ul>
                </div>
            `;
        }

        if (modal) modal.classList.add('active');
    },

    closeModal() {
        const modal = document.getElementById('port-inspect-modal');
        if (modal) modal.classList.remove('active');
    },

    /**
     * Renders the Explainable AI Studio view for a port
     */
    renderXaiStudio(port) {
        if (!port) return;

        const portHeader = document.getElementById('xai-selected-port-title');
        const portReasons = document.getElementById('xai-selected-reasons');
        const portQuote = document.getElementById('xai-selected-quote');

        if (portHeader) {
            portHeader.innerHTML = `
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span>Port: <strong style="color:var(--accent-cyan);">${port.port}</strong></span>
                    <span>Service: <strong>${port.service}</strong></span>
                    <span>Protocol: <strong>${port.protocol}</strong></span>
                    <span class="badge-risk ${port.risk_level}">${port.risk_level}</span>
                    <span style="font-family:var(--font-mono);font-size:13px;color:var(--accent-blue);">Confidence: ${Math.round(port.confidence * 100)}%</span>
                </div>
            `;
        }

        if (portReasons && port.xai?.reasons) {
            portReasons.innerHTML = port.xai.reasons.map(r => `
                <li style="display:flex;align-items:center;gap:10px;">
                    <i class="fas fa-check-circle" style="color:var(--accent-emerald);"></i>
                    <span>${r.text}</span>
                </li>
            `).join('');
        }

        if (portQuote && port.xai?.ai_explanation) {
            portQuote.textContent = `“${port.xai.ai_explanation}”`;
        }

        // Render Local Waterfall Chart
        if (port.xai?.local_contributions) {
            renderLocalXAIWaterfall('local-xai-chart', port.xai.local_contributions);
        }
    },

    renderXaiDropdown() {
        const select = document.getElementById('xai-port-select');
        if (!select) return;
        select.innerHTML = '';

        this.currentPorts.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.port;
            opt.textContent = `Port ${p.port} - ${p.service} (${p.risk_level})`;
            if (this.selectedPort && this.selectedPort.port === p.port) {
                opt.selected = true;
            }
            select.appendChild(opt);
        });

        select.onchange = (e) => {
            const portNum = parseInt(e.target.value);
            const port = this.currentPorts.find(p => p.port === portNum);
            if (port) {
                this.selectedPort = port;
                this.renderXaiStudio(port);
            }
        };
    },

    /**
     * Loads Global Feature Importance metrics
     */
    async loadGlobalXai() {
        try {
            const res = await fetch(`${API_BASE_URL}/api/xai-global`);
            const data = await res.json();
            if (data.success) {
                this.globalXaiData = data.data;
                renderGlobalFeatureImportanceChart('global-xai-chart', this.globalXaiData);
            }
        } catch (err) {
            console.error('Error fetching global XAI:', err);
        }
    },

    /**
     * Loads past scan sessions
     */
    async loadHistoricalScans() {
        try {
            const res = await fetch(`${API_BASE_URL}/api/scans?limit=6`);
            const data = await res.json();
            const listEl = document.getElementById('historical-scans-list');
            if (listEl && data.success) {
                listEl.innerHTML = '';
                data.scans.forEach(s => {
                    const item = document.createElement('div');
                    item.className = 'activity-item';
                    item.style.cursor = 'pointer';
                    item.innerHTML = `
                        <div style="display:flex;justify-content:space-between;width:100%;align-items:center;">
                            <div>
                                <strong style="color:#fff;">${s.target}</strong>
                                <div style="font-size:11px;color:#94a3b8;">${s.timestamp}</div>
                            </div>
                            <div>
                                <span class="badge-risk ${s.risk_tier}">${s.risk_score}/100</span>
                            </div>
                        </div>
                    `;
                    item.onclick = async () => {
                        const fullRes = await fetch(`${API_BASE_URL}/api/results/${s.id}`);
                        const fullData = await fullRes.json();
                        if (fullData.success) {
                            Analyzer.currentScan = fullData.data;
                            Dashboard.renderScanResults(fullData.data);
                        }
                    };
                    listEl.appendChild(item);
                });
            }
        } catch (err) {
            console.error('Error loading scans history:', err);
        }
    },

    /**
     * Loads aggregated global stats
     */
    async loadStatistics() {
        try {
            const res = await fetch(`${API_BASE_URL}/api/statistics`);
            const data = await res.json();
            if (data.success) {
                const el = document.getElementById('stat-total-scans');
                if (el) el.textContent = data.data.total_scans || 0;
            }
        } catch (err) {
            console.error('Error loading statistics:', err);
        }
    },

    /**
     * Generates printable / PDF report view
     */
    generateReportView(scan) {
        const container = document.getElementById('report-container');
        if (!container || !scan) return;

        const portsRows = (scan.ports || []).map(p => `
            <tr>
                <td>${p.port}</td>
                <td>${p.protocol}</td>
                <td>${p.service}</td>
                <td>${p.version || 'Standard'}</td>
                <td><strong>${p.risk_level}</strong></td>
                <td>${Math.round(p.confidence * 100)}%</td>
                <td>${p.cvss_score || '0.0'}</td>
            </tr>
        `).join('');

        const explanationsHtml = (scan.ports || []).filter(p => p.risk_level === 'High' || p.risk_level === 'Critical').map(p => `
            <div style="margin-bottom:14px;padding:12px;background:#f8fafc;border-left:4px solid #ef4444;border-radius:4px;">
                <strong>Port ${p.port} (${p.service}) - Risk: ${p.risk_level} (${Math.round(p.confidence * 100)}% confidence)</strong>
                <p style="margin-top:4px;font-size:12px;color:#334155;">${p.xai?.ai_explanation || ''}</p>
                <div style="margin-top:6px;font-size:11px;color:#64748b;">
                    <strong>Mitigations:</strong> ${(p.recommendations || []).join(' | ')}
                </div>
            </div>
        `).join('');

        container.innerHTML = `
            <div class="report-view" id="printable-report">
                <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #0f172a;padding-bottom:16px;margin-bottom:20px;">
                    <div>
                        <h1 style="font-size:22px;font-weight:800;color:#0f172a;margin-bottom:4px;">Network Vulnerability & Port Intelligence Audit Report</h1>
                        <p style="font-size:13px;color:#64748b;">Explainable AI Defensive Assessment Framework</p>
                    </div>
                    <div style="text-align:right;">
                        <span style="font-size:12px;color:#64748b;">Generated on:</span>
                        <div style="font-size:13px;font-weight:700;color:#0f172a;">${scan.timestamp}</div>
                    </div>
                </div>

                <div class="report-meta-grid">
                    <div>
                        <div style="font-size:11px;color:#64748b;font-weight:700;">AUDIT TARGET</div>
                        <div style="font-size:14px;font-weight:700;color:#0f172a;margin-top:4px;">${scan.target}</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748b;font-weight:700;">OVERALL RISK SCORE</div>
                        <div style="font-size:16px;font-weight:800;color:#ef4444;margin-top:4px;">${scan.risk_score}/100 (${scan.risk_tier})</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748b;font-weight:700;">PORTS ANALYZED</div>
                        <div style="font-size:14px;font-weight:700;color:#0f172a;margin-top:4px;">${scan.total_ports} (${scan.open_ports} Open)</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748b;font-weight:700;">VULNERABLE / CRITICAL</div>
                        <div style="font-size:14px;font-weight:700;color:#dc2626;margin-top:4px;">${scan.vulnerable_ports} / ${scan.critical_risks}</div>
                    </div>
                </div>

                <h2 style="font-size:16px;font-weight:700;color:#0f172a;margin-top:24px;margin-bottom:10px;">1. Port Intelligence Assessment Matrix</h2>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Proto</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Risk Level</th>
                            <th>Confidence</th>
                            <th>CVSS</th>
                        </tr>
                    </thead>
                    <tbody>${portsRows}</tbody>
                </table>

                <h2 style="font-size:16px;font-weight:700;color:#0f172a;margin-top:24px;margin-bottom:10px;">2. Explainable AI Risk Attributions & Findings</h2>
                ${explanationsHtml || '<p style="color:#64748b;font-size:13px;">No critical or high risk vulnerabilities detected.</p>'}

                <h2 style="font-size:16px;font-weight:700;color:#0f172a;margin-top:24px;margin-bottom:10px;">3. Executive Security Recommendations</h2>
                <ol style="margin-left:20px;font-size:13px;color:#334155;line-height:1.7;">
                    <li>Immediately isolate or restrict public ingress access to critical database and remote admin ports (MySQL 3306, Redis 6379, Telnet 23).</li>
                    <li>Enforce transport-layer encryption (TLS 1.3 / SSH v2) across all legacy HTTP and FTP services.</li>
                    <li>Apply vendor security patches to remediate out-of-date service daemon versions.</li>
                    <li>Maintain automated real-time port intelligence monitoring and zero-trust perimeter policies.</li>
                </ol>
            </div>
        `;
    },

    exportReportAsPdf() {
        const element = document.getElementById('printable-report');
        if (!element) {
            alert('Please perform an analysis first to generate a report.');
            return;
        }

        // Use window.print or html2pdf
        if (window.html2pdf) {
            const opt = {
                margin: 10,
                filename: `Network_Security_Report_${Date.now()}.pdf`,
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 2 },
                jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };
            html2pdf().set(opt).from(element).save();
        } else {
            window.print();
        }
    }
};

// Initialize Dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    Dashboard.init();
});
