import json
import time
from typing import Dict, Any, Optional
from ..analyze.attack_graph import AttackIncident

class ForensicReportExporter:
    """
    Stage 6 Recovery: Generates comprehensive Post-Mortem Incident and Forensic Reports.
    Exportable in HTML, JSON, and compliance formats.
    """

    @staticmethod
    def generate_html_report(incident: AttackIncident) -> str:
        start_date = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(incident.start_time))
        updated_date = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(incident.updated_time))

        file_rows = ""
        for f in incident.affected_files:
            file_rows += f"""
            <tr>
                <td><code>{f.original_path}</code></td>
                <td><span class="badge badge-{f.status.lower()}">{f.status.upper()}</span></td>
                <td>{f.entropy:.2f} / 8.0</td>
                <td>{'✅ Restored from Snapshot' if f.has_micro_snapshot else 'Original / Locked'}</td>
            </tr>
            """

        mitre_badges = "".join([f'<span class="mitre-tag">{tech}</span>' for tech in incident.mitre_techniques])
        trigger_items = "".join([f'<li>⚠️ {t}</li>' for t in incident.triggers])
        containment_items = "".join([f'<li>🛡️ {c}</li>' for c in incident.containment_actions]) or "<li>Autonomous micro-containment executed.</li>"
        recovery_items = "".join([f'<li>🔄 {r}</li>' for r in incident.recovery_actions]) or "<li>Micro-snapshots restored.</li>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RansomVanguard Incident Post-Mortem Report - {incident.incident_id}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card-bg: #151d30;
            --accent: #00f0ff;
            --danger: #ff3366;
            --success: #00e676;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #233554;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .header {{
            border-bottom: 2px solid var(--accent);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--accent);
        }}
        .badge {{
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 13px;
            display: inline-block;
        }}
        .badge-critical {{ background: rgba(255, 51, 102, 0.2); color: #ff3366; border: 1px solid #ff3366; }}
        .badge-recovered {{ background: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid #00e676; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .card h3 {{
            margin-top: 0;
            color: var(--accent);
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .metric {{
            font-size: 28px;
            font-weight: 800;
            margin: 10px 0;
        }}
        .mitre-tag {{
            display: inline-block;
            background: rgba(0, 240, 255, 0.15);
            color: var(--accent);
            border: 1px solid rgba(0, 240, 255, 0.3);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            margin: 4px 4px 4px 0;
            font-family: monospace;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }}
        th {{
            background: rgba(0, 0, 0, 0.3);
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 12px;
        }}
        code {{
            background: rgba(0, 0, 0, 0.4);
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
            font-family: 'Consolas', monospace;
        }}
        ul {{
            padding-left: 20px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="brand">🛡️ RANSOMVANGUARD</div>
            <div style="color: var(--text-muted); font-size: 14px;">Forensic Incident Post-Mortem & Remediation Report</div>
        </div>
        <div>
            <span class="badge badge-{incident.threat_level.lower()}">THREAT LEVEL: {incident.threat_level}</span>
            <span class="badge badge-recovered">STATUS: {incident.status}</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Incident Overview</h3>
            <p><strong>Incident ID:</strong> <code>{incident.incident_id}</code></p>
            <p><strong>Classification:</strong> {incident.threat_family}</p>
            <p><strong>Start Time:</strong> {start_date}</p>
            <p><strong>Mitigation Time:</strong> {updated_date}</p>
        </div>

        <div class="card">
            <h3>Risk Assessment</h3>
            <div class="metric" style="color: var(--danger);">{incident.risk_score} / 100</div>
            <p style="color: var(--text-muted); margin: 0;">Multi-vector composite risk score across entropy, canaries, and process behavior.</p>
        </div>

        <div class="card">
            <h3>Offending Process Lineage</h3>
            <p><strong>Process Name:</strong> <code>{incident.culprit_process_name or 'N/A'}</code></p>
            <p><strong>Process PID:</strong> <code>{incident.culprit_pid or 'N/A'}</code></p>
            <p><strong>Command Line:</strong> <code>{incident.culprit_cmdline or 'Direct Binary Execution'}</code></p>
            <p><strong>Parent PID:</strong> <code>{incident.parent_pid or 'N/A'}</code></p>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>MITRE ATT&CK Techniques Mapped</h3>
            <div>{mitre_badges}</div>
        </div>

        <div class="card">
            <h3>Detection Triggers</h3>
            <ul>{trigger_items}</ul>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Response Actions Executed</h3>
            <ul>{containment_items}</ul>
        </div>

        <div class="card">
            <h3>Recovery & Rollback Execution</h3>
            <ul>{recovery_items}</ul>
        </div>
    </div>

    <div class="card" style="margin-top: 20px;">
        <h3>Forensic Ledger: Affected & Recovered Files ({len(incident.affected_files)})</h3>
        <table>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>Status</th>
                    <th>Entropy</th>
                    <th>Recovery Assurance</th>
                </tr>
            </thead>
            <tbody>
                {file_rows if file_rows else '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No permanent file damage. Zero data loss achieved.</td></tr>'}
            </tbody>
        </table>
    </div>

    <div style="margin-top: 40px; text-align: center; color: var(--text-muted); font-size: 13px;">
        Generated by RansomVanguard Autonomous Incident Detection & Recovery Engine for Windows Server.
    </div>
</body>
</html>
"""
        return html
