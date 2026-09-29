/**
 * Real-Time Canvas Waveform Chart for Shannon Entropy
 */
class EntropyChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.maxPoints = 60;
        this.data = new Array(this.maxPoints).fill(3.2);
        this.threshold = 7.55;
        this.animationId = null;
        this.init();
    }

    init() {
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.render();
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width - 24;
        this.canvas.height = 110;
    }

    pushValue(val) {
        this.data.push(Math.min(8.0, Math.max(0.0, val)));
        if (this.data.length > this.maxPoints) {
            this.data.shift();
        }
        this.render();
    }

    render() {
        if (!this.ctx) return;
        const w = this.canvas.width;
        const h = this.canvas.height;
        const ctx = this.ctx;

        ctx.clearRect(0, 0, w, h);

        // Grid lines (Entropy 2, 4, 6, 8)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        for (let e = 2; e <= 8; e += 2) {
            const y = h - (e / 8.0) * (h - 20) - 10;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();

            ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
            ctx.font = '9px JetBrains Mono';
            ctx.fillText(e.toFixed(1), 4, y - 2);
        }

        // Critical Threshold Line (7.55)
        const threshY = h - (this.threshold / 8.0) * (h - 20) - 10;
        ctx.strokeStyle = 'rgba(255, 0, 85, 0.7)';
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(0, threshY);
        ctx.lineTo(w, threshY);
        ctx.stroke();
        ctx.setLineDash([]);

        // Plot Waveform
        const step = w / (this.maxPoints - 1);
        ctx.beginPath();

        this.data.forEach((val, i) => {
            const x = i * step;
            const y = h - (val / 8.0) * (h - 20) - 10;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        // Check if latest point breaches threshold
        const latest = this.data[this.data.length - 1];
        const isSpike = latest >= this.threshold;

        const grad = ctx.createLinearGradient(0, 0, 0, h);
        if (isSpike) {
            grad.addColorStop(0, 'rgba(255, 0, 85, 0.4)');
            grad.addColorStop(1, 'rgba(255, 0, 85, 0.0)');
            ctx.strokeStyle = '#ff0055';
        } else {
            grad.addColorStop(0, 'rgba(0, 240, 255, 0.3)');
            grad.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
            ctx.strokeStyle = '#00f0ff';
        }

        ctx.lineWidth = 2;
        ctx.stroke();

        // Fill area under curve
        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
    }
}

window.EntropyChart = EntropyChart;
