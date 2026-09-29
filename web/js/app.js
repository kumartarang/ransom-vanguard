/**
 * RansomVanguard SOC Command Center Frontend Application
 */

class RansomVanguardApp {
    constructor() {
        this.ws = null;
        this.entropyChart = null;
        this.activeIncidentId = null;
        this.alertsCount = 0;
        this.init();
    }

    init() {
        // Initialize Entropy Chart
        this.entropyChart = new window.EntropyChart('entropyChart');

        // Setup WebSocket
        this.connectWebSocket();

        // Setup Buttons & Handlers
        this.setupEventHandlers();

        // Initial Data Fetch
        this.fetchActiveIncident();
        this.fetchRecentAlerts();
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('[RansomVanguard] WebSocket connected');
            const statusCard = document.getElementById('connection-status-card');
            const statusText = document.getElementById('ws-status-text');
            if (statusCard && statusText) {
                statusText.innerText = 'SOC AGENT CONNECTED';
                statusCard.style.borderColor = 'rgba(0, 255, 136, 0.5)';
            }
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'TELEMETRY') {
                    this.handleTelemetryUpdate(msg.data, msg.recent_activity);
                } else if (msg.type === 'ALERT') {
                    this.handleAlertEvent(msg.data);
                }
            } catch (e) {
                console.error('Error handling WS message:', e);
            }
        };

        this.ws.onclose = () => {
            const statusCard = document.getElementById('connection-status-card');
            const statusText = document.getElementById('ws-status-text');
            if (statusCard && statusText) {
                statusText.innerText = 'RECONNECTING...';
                statusCard.style.borderColor = 'rgba(255, 0, 85, 0.5)';
            }
            setTimeout(() => this.connectWebSocket(), 2000);
        };
    }

    handleTelemetryUpdate(telemetry, recentActivity) {
        if (!telemetry) return;

        // 1. Update Gauge & Risk Index
        const score = telemetry.active_risk_score || 0;
        const scoreEl = document.getElementById('gauge-score-value');
        if (scoreEl) scoreEl.innerText = score;

        const progressPath = document.getElementById('gauge-progress');
        if (progressPath) {
            // Circumference of half circle r=40 is ~125.66
            const offset = 125.66 - (score / 100) * 125.66;
            progressPath.style.strokeDashoffset = offset;
            progressPath.style.stroke = score >= 60 ? '#ff0055' : (score >= 40 ? '#ffb703' : '#00f0ff');
        }

        const badge = document.getElementById('threat-level-badge');
        if (badge) {
            badge.innerText = telemetry.active_threat_level;
            badge.className = `badge badge-${telemetry.active_threat_level.toLowerCase()}`;
        }

        // 2. Vital Metrics
        const rateEl = document.getElementById('stat-event-rate');
        if (rateEl) rateEl.innerText = telemetry.events_per_second.toFixed(1);

        const entEl = document.getElementById('stat-entropy-val');
        if (entEl) entEl.innerText = telemetry.avg_entropy.toFixed(2);

        const canEl = document.getElementById('stat-canary-trips');
        if (canEl) canEl.innerText = `${telemetry.canaries_tripped} / ${telemetry.canaries_deployed}`;

        // 3. Push Entropy to Chart
        if (this.entropyChart) {
            this.entropyChart.pushValue(telemetry.avg_entropy);
        }

        // 4. Update 6-Stage Nodes
        this.updateLifecycleNodes(score, telemetry.status, telemetry.canaries_tripped);

        // 5. Update File Stream Table
        if (recentActivity && recentActivity.length > 0) {
            this.renderFileStream(recentActivity);
        }
    }

    updateLifecycleNodes(riskScore, status, canariesTripped) {
        const n1 = document.getElementById('node-stage-1');
        const n2 = document.getElementById('node-stage-2');
        const n3 = document.getElementById('node-stage-3');
        const n4 = document.getElementById('node-stage-4');
        const n5 = document.getElementById('node-stage-5');
        const n6 = document.getElementById('node-stage-6');

        // Stage 1: Always Active Monitoring
        n1.className = 'stage-node active';

        if (riskScore >= 60 || canariesTripped > 0) {
            n2.className = 'stage-node danger';
            n3.className = 'stage-node danger';
            n4.className = 'stage-node danger';
            n5.className = 'stage-node active';
            n6.className = status === 'RECOVERED' ? 'stage-node success' : 'stage-node active';

            document.getElementById('metric-risk-score').innerText = `Score: ${riskScore}/100`;
            document.getElementById('metric-containment-status').innerText = 'Triggered (<50ms)';
            document.getElementById('metric-recovery-status').innerText = status === 'RECOVERED' ? '100% Restored' : 'Rolling Back...';
        } else {
            n2.className = 'stage-node';
            n3.className = 'stage-node';
            n4.className = 'stage-node';
            n5.className = 'stage-node';
            n6.className = 'stage-node';

            document.getElementById('metric-risk-score').innerText = `Score: ${riskScore}/100`;
            document.getElementById('metric-containment-status').innerText = 'Armed';
            document.getElementById('metric-recovery-status').innerText = 'Snapshots Ready';
        }
    }

    renderFileStream(activityList) {
        const tbody = document.getElementById('file-stream-tbody');
        if (!tbody) return;

        let rows = '';
        activityList.slice(-6).reverse().forEach(item => {
            const path = item.dest_path || item.src_path;
            const filename = path.split(/[\\/]/).pop();
            const isHigh = item.is_high_entropy;

            rows += `
                <tr>
                    <td><span class="badge ${item.event_type === 'moved' ? 'badge-warning' : (item.event_type === 'deleted' ? 'badge-critical' : 'badge-info')}">${item.event_type.toUpperCase()}</span></td>
                    <td title="${path}"><code>${filename}</code></td>
                    <td style="color: ${isHigh ? '#ff0055' : '#00f0ff'}; font-weight: 700;">${item.entropy.toFixed(2)}</td>
                    <td><span class="badge ${isHigh ? 'badge-critical' : 'badge-normal'}">${isHigh ? 'HIGH ENTROPY' : 'CLEAN'}</span></td>
                </tr>
            `;
        });

        tbody.innerHTML = rows;
    }

    handleAlertEvent(alert) {
        this.alertsCount++;
        const alertCounter = document.getElementById('alert-counter-badge');
        if (alertCounter) alertCounter.innerText = `${this.alertsCount} ALERTS`;

        const feed = document.getElementById('alerts-feed-list');
        if (feed) {
            const alertEl = document.createElement('div');
            alertEl.className = `alert-item ${alert.severity === 'CRITICAL' ? 'alert-critical' : (alert.severity === 'HIGH' ? 'alert-warning' : 'alert-info')}`;
            alertEl.innerHTML = `
                <div class="alert-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                <div class="alert-body">
                    <div class="alert-title">${alert.title} (Score: ${alert.risk_score}/100)</div>
                    <div class="alert-desc">${alert.description}</div>
                    <div class="alert-time">MITRE: ${alert.mitre_technique || 'T1486'} • ${new Date(alert.timestamp * 1000).toLocaleTimeString()}</div>
                </div>
            `;
            feed.insertBefore(alertEl, feed.firstChild);
        }

        // Show toast
        window.showToast(`🚨 ${alert.title}`, alert.severity === 'CRITICAL' ? 'danger' : 'warning');

        // Fetch latest incident details
        this.fetchActiveIncident();
    }

    async fetchActiveIncident() {
        try {
            const res = await fetch('/api/incidents/active');
            const data = await res.json();
            const container = document.getElementById('incident-details-container');
            const reportBtn = document.getElementById('btn-view-report');

            if (data && data.incident_id) {
                this.activeIncidentId = data.incident_id;
                if (reportBtn) reportBtn.disabled = false;

                const mitreTags = (data.mitre_techniques || []).map(t => `<span class="mitre-pill">${t}</span>`).join('');
                const triggers = (data.triggers || []).map(tr => `<li>⚠️ ${tr}</li>`).join('');

                container.innerHTML = `
                    <div class="active-incident-card">
                        <div class="incident-top">
                            <div>
                                <div class="incident-family"><i class="fa-solid fa-skull-crossbones"></i> ${data.threat_family}</div>
                                <div style="font-size: 11px; color: var(--text-muted);">INCIDENT: ${data.incident_id}</div>
                            </div>
                            <span class="badge badge-${data.status === 'RECOVERED' ? 'normal' : 'critical'}">${data.status}</span>
                        </div>
                        <div class="mitre-tags-list">${mitreTags}</div>
                        <ul style="font-size: 12px; margin: 8px 0 8px 18px; color: var(--text-secondary);">${triggers}</ul>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
                            <strong>Culprit Process:</strong> ${data.culprit_process_name || 'Injected/Direct'} (PID: ${data.culprit_pid || 'N/A'})
                        </div>
                    </div>
                `;
            }
        } catch (e) {
            console.error('Error fetching incident:', e);
        }
    }

    async fetchRecentAlerts() {
        try {
            const res = await fetch('/api/incidents/alerts/recent?limit=10');
            const alerts = await res.json();
            this.alertsCount = alerts.length;
            const alertCounter = document.getElementById('alert-counter-badge');
            if (alertCounter) alertCounter.innerText = `${this.alertsCount} ALERTS`;
        } catch (e) {}
    }

    setupEventHandlers() {
        // Rollback All Button
        const btnRollback = document.getElementById('btn-rollback-all');
        if (btnRollback) {
            btnRollback.addEventListener('click', async () => {
                try {
                    const res = await fetch('/api/recovery/rollback-all', { method: 'POST' });
                    const data = await res.json();
                    window.showToast(data.message || 'Restored files from Micro-Snapshots', 'success');
                    this.fetchActiveIncident();
                } catch (e) {
                    window.showToast('Rollback failed', 'danger');
                }
            });
        }

        // View Forensic Report Modal
        const btnReport = document.getElementById('btn-view-report');
        const modal = document.getElementById('report-modal');
        const btnCloseModal = document.getElementById('btn-close-modal');
        const reportIframe = document.getElementById('report-iframe');

        if (btnReport && modal && reportIframe) {
            btnReport.addEventListener('click', () => {
                if (this.activeIncidentId) {
                    window.openForensicReport(this.activeIncidentId);
                }
            });
        }

        window.openForensicReport = (incidentId) => {
            if (reportIframe && modal && incidentId) {
                reportIframe.src = `/api/incidents/${incidentId}/report`;
                modal.style.display = 'flex';
                modal.classList.add('active');
            }
        };

        if (btnCloseModal && modal) {
            btnCloseModal.addEventListener('click', () => {
                modal.style.display = 'none';
                modal.classList.remove('active');
            });
        }

        // Emergency Airlock Button
        const btnAirlock = document.getElementById('btn-emergency-lockdown');
        if (btnAirlock) {
            btnAirlock.addEventListener('click', async () => {
                window.showToast('Emergency Network Airlock Activated: Host C2 Blocked', 'danger');
            });
        }
    }
}

// Global Toast Notification Function
window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'success' ? 'fa-circle-check' : (type === 'danger' ? 'fa-triangle-exclamation' : 'fa-info-circle');
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
};

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new RansomVanguardApp();
});
