/**
 * Attack Simulator UI Handlers
 */
document.addEventListener('DOMContentLoaded', () => {
    const btnRepopulate = document.getElementById('btn-repopulate-sandbox');
    const btnCanary = document.getElementById('btn-sim-canary');
    const btnEntropy = document.getElementById('btn-sim-entropy');
    const btnMutation = document.getElementById('btn-sim-mutation');
    const btnNote = document.getElementById('btn-sim-note');
    const btnFull = document.getElementById('btn-sim-full');

    async function triggerAttack(endpoint, successMsg) {
        try {
            const res = await fetch(endpoint, { method: 'POST' });
            const data = await res.json();
            if (res.ok) {
                window.showToast(`${successMsg} (${data.duration_ms || 0}ms)`, 'danger');
            } else {
                window.showToast(`Simulation Error: ${data.detail || 'Failed'}`, 'warning');
            }
        } catch (e) {
            window.showToast(`Request failed: ${e.message}`, 'warning');
        }
    }

    if (btnRepopulate) {
        btnRepopulate.addEventListener('click', async () => {
            const res = await fetch('/api/simulator/populate', { method: 'POST' });
            const data = await res.json();
            window.showToast(data.message || 'Sandbox files re-armed', 'success');
        });
    }

    if (btnCanary) {
        btnCanary.addEventListener('click', () => {
            triggerAttack('/api/simulator/attack/canary-trip', 'Simulated Canary Honeypot Modification');
        });
    }

    if (btnEntropy) {
        btnEntropy.addEventListener('click', () => {
            triggerAttack('/api/simulator/attack/entropy-burst', 'Launched High-Entropy AES Encryption Burst');
        });
    }

    if (btnMutation) {
        btnMutation.addEventListener('click', () => {
            triggerAttack('/api/simulator/attack/extension-mutation', 'Simulated Mass Extension Mutation (.lockbit)');
        });
    }

    if (btnNote) {
        btnNote.addEventListener('click', () => {
            triggerAttack('/api/simulator/attack/ransom-note', 'Simulated Ransom Note Drop');
        });
    }

    if (btnFull) {
        btnFull.addEventListener('click', () => {
            triggerAttack('/api/simulator/attack/full-killchain', 'FULL 6-STAGE RANSOMWARE ATTACK SIMULATION LAUNCHED');
        });
    }
});
