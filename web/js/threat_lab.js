/**
 * Threat Detonation & Ingestion Lab Controller
 * Handles custom file uploads, script payloads, preset detonation, and live 6-stage response animation.
 */

class ThreatDetonationLabUI {
    constructor() {
        this.selectedFile = null;
        this.presets = [];
        this.init();
    }

    async init() {
        this.setupTabs();
        this.setupDropzone();
        this.setupScriptEditor();
        this.setupDetonationModal();
        await this.loadPresets();
        await this.loadQuarantineVault();
    }

    setupTabs() {
        const tabBtns = document.querySelectorAll('.threat-lab-tab-btn');
        const tabPanes = document.querySelectorAll('.threat-lab-tab-pane');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.getAttribute('data-tab');
                tabBtns.forEach(b => b.classList.remove('active'));
                tabPanes.forEach(p => p.classList.remove('active'));

                btn.classList.add('active');
                const targetPane = document.getElementById(`tab-pane-${targetTab}`);
                if (targetPane) targetPane.classList.add('active');

                if (targetTab === 'quarantine') {
                    this.loadQuarantineVault();
                }
            });
        });
    }

    setupDropzone() {
        const dropzone = document.getElementById('threat-file-dropzone');
        const fileInput = document.getElementById('threat-file-input');
        const btnUploadDetonate = document.getElementById('btn-detonate-uploaded-file');
        const fileInfoCard = document.getElementById('selected-file-info');

        if (!dropzone || !fileInput) return;

        dropzone.addEventListener('click', () => fileInput.click());

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('drag-active');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('drag-active');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('drag-active');
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                this.handleFileSelected(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                this.handleFileSelected(e.target.files[0]);
            }
        });

        if (btnUploadDetonate) {
            btnUploadDetonate.addEventListener('click', async () => {
                if (!this.selectedFile) {
                    window.showToast('Please select or drop a file first.', 'warning');
                    return;
                }
                await this.detonateUploadedFile();
            });
        }
    }

    handleFileSelected(file) {
        this.selectedFile = file;
        const fileInfoCard = document.getElementById('selected-file-info');
        const fileNameEl = document.getElementById('selected-file-name');
        const fileSizeEl = document.getElementById('selected-file-size');
        const btnUploadDetonate = document.getElementById('btn-detonate-uploaded-file');

        if (fileInfoCard && fileNameEl && fileSizeEl) {
            fileNameEl.innerText = file.name;
            fileSizeEl.innerText = `${(file.size / 1024).toFixed(2)} KB`;
            fileInfoCard.style.display = 'flex';
        }
        if (btnUploadDetonate) {
            btnUploadDetonate.disabled = false;
        }
    }

    async detonateUploadedFile() {
        if (!this.selectedFile) return;

        const formData = new FormData();
        formData.append('file', this.selectedFile);
        formData.append('simulate_execution', 'true');

        const btn = document.getElementById('btn-detonate-uploaded-file');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting & Detonating...';
        }

        try {
            const res = await fetch('/api/threat-lab/upload-file', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            if (res.ok) {
                window.showToast(`Threat Ingestion Successful: ${data.threat_family}`, 'danger');
                this.showDetonationModal(data);
                this.loadQuarantineVault();
            } else {
                window.showToast(`Detonation Failed: ${data.detail || 'Error'}`, 'warning');
            }
        } catch (e) {
            window.showToast(`Request failed: ${e.message}`, 'warning');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-biohazard"></i> INGEST & TRIGGER 6-STAGE DEFENSE';
            }
        }
    }

    setupScriptEditor() {
        const btnDetonateScript = document.getElementById('btn-detonate-custom-script');
        const scriptInput = document.getElementById('custom-payload-code');
        const filenameInput = document.getElementById('custom-payload-filename');

        // Preset quick injection buttons
        const btnInsertVss = document.getElementById('btn-insert-preset-vss');
        const btnInsertLockbit = document.getElementById('btn-insert-preset-lockbit');
        const btnInsertEntropy = document.getElementById('btn-insert-preset-entropy');
        const btnInsertCanary = document.getElementById('btn-insert-preset-canary');

        if (btnInsertVss && scriptInput && filenameInput) {
            btnInsertVss.addEventListener('click', () => {
                filenameInput.value = "vss_shadow_wiper.bat";
                scriptInput.value = "@echo off\nrem T1490: Sabotage Volume Shadow Copies & Backups\nvssadmin delete shadows /all /quiet\nbcdedit /set {default} bootstatuspolicy ignoreallfailures\nbcdedit /set {default} recoveryenabled no\nwbadmin delete catalog -quiet";
            });
        }

        if (btnInsertLockbit && scriptInput && filenameInput) {
            btnInsertLockbit.addEventListener('click', () => {
                filenameInput.value = "lockbit_dropper.ps1";
                scriptInput.value = "# Simulated LockBit 3.0 Dropper\n$encBytes = [byte[]](1..4096 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })\n[System.IO.File]::WriteAllBytes('financial_records.xlsx.lockbit', $encBytes)\n[System.IO.File]::WriteAllText('lockbit_readme.txt', '=== YOUR NETWORK IS ENCRYPTED BY LOCKBIT 3.0 ===\\nContact Tor portal.')";
            });
        }

        if (btnInsertEntropy && scriptInput && filenameInput) {
            btnInsertEntropy.addEventListener('click', () => {
                filenameInput.value = "aes_crypter.py";
                scriptInput.value = "# High-Entropy AES Ciphertext Encryption\nimport secrets\nfor f in ['payroll.csv', 'database.sql', 'legal.docx']:\n    with open(f, 'wb') as fp:\n        fp.write(secrets.token_bytes(4096))";
            });
        }

        if (btnInsertCanary && scriptInput && filenameInput) {
            btnInsertCanary.addEventListener('click', () => {
                filenameInput.value = "canary_breacher.ps1";
                scriptInput.value = "# Canary Honeypot Breacher\n$target = '!00_financial_audit.xlsx'\n[System.IO.File]::WriteAllBytes($target, [byte[]](1..2048 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))";
            });
        }

        if (btnDetonateScript) {
            btnDetonateScript.addEventListener('click', async () => {
                const content = scriptInput ? scriptInput.value : '';
                const filename = filenameInput ? filenameInput.value : 'custom_threat.ps1';

                if (!content.trim()) {
                    window.showToast('Please enter script code or payload text.', 'warning');
                    return;
                }

                btnDetonateScript.disabled = true;
                btnDetonateScript.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting & Detonating...';

                try {
                    const res = await fetch('/api/threat-lab/insert-payload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            payload_type: 'script',
                            filename: filename,
                            content: content,
                            simulate_execution: true
                        })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        window.showToast(`Custom Payload Ingestion Complete: ${data.threat_family}`, 'danger');
                        this.showDetonationModal(data);
                        this.loadQuarantineVault();
                    } else {
                        window.showToast(`Detonation Failed: ${data.detail || 'Error'}`, 'warning');
                    }
                } catch (e) {
                    window.showToast(`Request failed: ${e.message}`, 'warning');
                } finally {
                    btnDetonateScript.disabled = false;
                    btnDetonateScript.innerHTML = '<i class="fa-solid fa-rocket"></i> DETONATE CUSTOM SCRIPT IN SANDBOX';
                }
            });
        }
    }

    async loadPresets() {
        const container = document.getElementById('threat-presets-grid');
        if (!container) return;

        try {
            const res = await fetch('/api/threat-lab/presets');
            const data = await res.json();
            if (data.status === 'SUCCESS' && data.presets) {
                this.presets = data.presets;
                this.renderPresets(data.presets);
            }
        } catch (e) {
            console.error('Failed to load presets:', e);
        }
    }

    renderPresets(presets) {
        const container = document.getElementById('threat-presets-grid');
        if (!container) return;

        container.innerHTML = presets.map(p => `
            <div class="threat-preset-card">
                <div class="preset-header">
                    <div class="preset-name"><i class="fa-solid fa-virus text-danger"></i> ${p.name}</div>
                    <span class="badge badge-${p.expected_severity.toLowerCase()}">${p.expected_severity}</span>
                </div>
                <div class="preset-desc">${p.description}</div>
                <div class="preset-meta">
                    <span><i class="fa-solid fa-file-code text-accent"></i> ${p.filename}</span>
                    <span><i class="fa-solid fa-shield-virus text-warning"></i> ${p.mitre_technique}</span>
                </div>
                <button class="btn btn-outline-danger btn-sm w-100 btn-detonate-preset" data-id="${p.preset_id}">
                    <i class="fa-solid fa-bolt"></i> Detonate in Sandbox
                </button>
            </div>
        `).join('');

        container.querySelectorAll('.btn-detonate-preset').forEach(btn => {
            btn.addEventListener('click', async () => {
                const presetId = btn.getAttribute('data-id');
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Detonating...';
                try {
                    const res = await fetch('/api/threat-lab/detonate-preset', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ preset_id: presetId, simulate_execution: true })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        window.showToast(`Preset Detonated: ${data.threat_family}`, 'danger');
                        this.showDetonationModal(data);
                        this.loadQuarantineVault();
                    } else {
                        window.showToast(`Detonation Failed: ${data.detail || 'Error'}`, 'warning');
                    }
                } catch (e) {
                    window.showToast(`Request failed: ${e.message}`, 'warning');
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Detonate in Sandbox';
                }
            });
        });
    }

    async loadQuarantineVault() {
        const tbody = document.getElementById('quarantine-vault-tbody');
        const badge = document.getElementById('quarantine-count-badge');
        if (!tbody) return;

        try {
            const res = await fetch('/api/threat-lab/quarantine-vault');
            const data = await res.json();
            if (data.status === 'SUCCESS' && data.items) {
                if (badge) badge.innerText = `${data.count} ISOLATED`;
                if (data.items.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Quarantine vault is empty. All threats neutralized.</td></tr>`;
                    return;
                }

                tbody.innerHTML = data.items.map(item => `
                    <tr>
                        <td><strong class="text-accent">${item.filename}</strong></td>
                        <td><span class="mono-tag">${item.sha256.substring(0, 16)}...</span></td>
                        <td>${(item.file_size / 1024).toFixed(1)} KB</td>
                        <td><span class="badge badge-critical">QUARANTINED</span></td>
                        <td><small class="text-muted">${item.reason}</small></td>
                    </tr>
                `).join('');
            }
        } catch (e) {
            console.error('Failed to load quarantine vault:', e);
        }
    }

    setupDetonationModal() {
        const modal = document.getElementById('detonation-result-modal');
        const btnClose = document.getElementById('btn-close-detonation-modal');

        if (btnClose && modal) {
            btnClose.addEventListener('click', () => {
                modal.classList.remove('active');
            });
        }
    }

    showDetonationModal(result) {
        const modal = document.getElementById('detonation-result-modal');
        if (!modal) return;

        // Populate summary values
        document.getElementById('det-modal-artifact').innerText = result.artifact_name;
        document.getElementById('det-modal-score').innerText = `${result.risk_score}/100 (${result.threat_level})`;
        document.getElementById('det-modal-family').innerText = result.threat_family;
        document.getElementById('det-modal-duration').innerText = `${result.total_duration_ms.toFixed(1)}ms`;
        document.getElementById('det-modal-restored').innerText = `${result.files_restored} Files Restored`;

        // Render 6 Stages
        const stagesList = document.getElementById('det-modal-stages-list');
        if (stagesList && result.stages) {
            stagesList.innerHTML = result.stages.map(s => `
                <div class="det-stage-item stage-${s.status.toLowerCase()}">
                    <div class="det-stage-number">STAGE 0${s.stage_number}</div>
                    <div class="det-stage-body">
                        <div class="det-stage-header">
                            <span class="det-stage-name">${s.stage_name}</span>
                            <span class="det-stage-time">${s.duration_ms.toFixed(2)}ms</span>
                        </div>
                        <div class="det-stage-headline">${s.headline}</div>
                        <div class="det-stage-detail">${s.detail}</div>
                    </div>
                </div>
            `).join('');
        }

        // Setup Post-Mortem Report Button
        const btnViewReport = document.getElementById('btn-modal-view-report');
        if (btnViewReport) {
            btnViewReport.onclick = () => {
                modal.classList.remove('active');
                if (window.openForensicReport) {
                    window.openForensicReport(result.incident_id);
                }
            };
        }

        modal.classList.add('active');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.threatDetonationLab = new ThreatDetonationLabUI();
});
