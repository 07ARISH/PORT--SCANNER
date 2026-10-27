/**
 * Port Intelligence & Analysis API Controller with Live Activity Feed
 */

const API_BASE_URL = window.location.origin;

const Analyzer = {
    currentScan: null,
    isScanning: false,

    /**
     * Checks backend system health
     */
    async checkHealth() {
        try {
            const res = await fetch(`${API_BASE_URL}/api/health`);
            const data = await res.json();
            const statusBadge = document.getElementById('system-status-indicator');
            if (statusBadge) {
                statusBadge.innerHTML = `<span class="pulse-dot"></span> AI Engine: ${data.model_status}`;
            }
            return data;
        } catch (err) {
            console.error('Backend health check failed:', err);
            const statusBadge = document.getElementById('system-status-indicator');
            if (statusBadge) {
                statusBadge.innerHTML = `<span class="pulse-dot" style="background:#ef4444;box-shadow:0 0 10px #ef4444;"></span> Server Offline`;
            }
        }
    },

    /**
     * Executes target analysis via REST API
     */
    async runScan(target, mode = 'demo', preset = 'enterprise') {
        if (this.isScanning) return;
        this.isScanning = true;

        this.setScanButtonState(true);
        this.clearActivityFeed();
        this.logActivity(`[INIT] Initializing ${mode.toUpperCase()} port intelligence probe on target: ${target}`, 'cyan');

        try {
            // Simulated live feed steps
            await this.simulateScanFeed(preset);

            const res = await fetch(`${API_BASE_URL}/api/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, mode, preset })
            });

            if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`);

            const responseData = await res.json();
            if (!responseData.success) throw new Error(responseData.error || 'Scan failed');

            this.currentScan = responseData.data;
            this.logActivity(`[COMPLETE] Scan finished. ${this.currentScan.total_ports} ports analyzed. Risk Score: ${this.currentScan.risk_score}/100 (${this.currentScan.risk_tier})`, 'safe');

            // Update UI components
            Dashboard.renderScanResults(this.currentScan);
            Dashboard.loadHistoricalScans();
            Dashboard.loadStatistics();

        } catch (err) {
            console.error('Scan error:', err);
            this.logActivity(`[ERROR] Scan execution failed: ${err.message}`, 'crit');
            alert(`Analysis Failed: ${err.message}`);
        } finally {
            this.isScanning = false;
            this.setScanButtonState(false);
        }
    },

    /**
     * Simulates real-time live activity feed steps
     */
    async simulateScanFeed(preset) {
        const events = [
            { msg: 'Resolving network target host and route interfaces...', delay: 250, type: 'cyan' },
            { msg: 'Probing standard TCP/UDP service listening ports...', delay: 400, type: 'cyan' },
            { msg: 'Port 80/TCP active: Inspecting Apache/Nginx header fingerprints...', delay: 300, type: 'warn' },
            { msg: 'Port 3306/TCP detected: Extracting DB banner & authentication protocol...', delay: 350, type: 'crit' },
            { msg: 'Vectorizing telemetry features into Random Forest ML Classifier...', delay: 300, type: 'cyan' },
            { msg: 'Calculating multi-class probability distributions & confidence metrics...', delay: 250, type: 'cyan' },
            { msg: 'XAI Engine: Generating local feature attributions and risk justifications...', delay: 300, type: 'safe' },
            { msg: 'Synthesizing defensive hardening and firewall mitigation rules...', delay: 200, type: 'safe' }
        ];

        for (const ev of events) {
            await new Promise(r => setTimeout(r, ev.delay));
            this.logActivity(ev.msg, ev.type);
        }
    },

    /**
     * Appends an event to the Live Activity Feed ticker
     */
    logActivity(text, type = 'cyan') {
        const feed = document.getElementById('live-activity-feed');
        if (!feed) return;

        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];

        const item = document.createElement('div');
        let typeClass = '';
        if (type === 'crit') typeClass = 'crit';
        else if (type === 'warn') typeClass = 'warn';
        else if (type === 'safe') typeClass = 'safe';

        item.className = `activity-item ${typeClass}`;
        item.innerHTML = `
            <span class="activity-time">${timeStr}</span>
            <span class="activity-text">${text}</span>
        `;

        feed.insertBefore(item, feed.firstChild);

        // Keep maximum 30 entries
        while (feed.children.length > 30) {
            feed.removeChild(feed.lastChild);
        }
    },

    clearActivityFeed() {
        const feed = document.getElementById('live-activity-feed');
        if (feed) feed.innerHTML = '';
    },

    setScanButtonState(isLoading) {
        const startBtn = document.getElementById('btn-start-scan');
        const demoBtn = document.getElementById('btn-demo-scan');

        if (startBtn) {
            startBtn.disabled = isLoading;
            startBtn.innerHTML = isLoading ? '<i class="fas fa-spinner fa-spin"></i> Analyzing...' : '<i class="fas fa-play"></i> Start Analysis';
        }
        if (demoBtn) {
            demoBtn.disabled = isLoading;
        }
    }
};
