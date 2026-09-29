import os
import sys
import argparse
import uvicorn

def main():
    parser = argparse.ArgumentParser(description="RansomVanguard - Windows Ransomware Autonomous Detection & Recovery System")
    parser.add_argument("--host", default="127.0.0.1", help="Host address for SOC Web Dashboard (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8877, help="Port for SOC Web Dashboard (default: 8877)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload on code changes")
    args = parser.parse_args()

    print(r"""
  ____                                __     __                                    _ 
 |  _ \ __ _ _ __  ___  ___  _ __ ___ \ \   / /_ _ _ __   __ _ _   _  __ _ _ __ __| |
 | |_) / _` | '_ \/ __|/ _ \| '_ ` _ \ \ \ / / _` | '_ \ / _` | | | |/ _` | '__/ _` |
 |  _ < (_| | | | \__ \ (_) | | | | | | \ V / (_| | | | | (_| | |_| | (_| | | | (_| |
 |_| \_\__,_|_| |_|___/\___/|_| |_| |_|  \_/ \__,_|_| |_|\__, |\__,_|\__,_|_|  \__,_|
                                                          |___/                       
 Autonomous 6-Stage Detection & Instant Self-Healing Engine for Windows Server
 Pipeline: Monitor -> Detect -> Analyze -> Alert -> Respond -> Recover
    """)

    print(f"[*] Starting RansomVanguard Cyber SOC Console on http://{args.host}:{args.port}")
    print(f"[*] Monitored Sandbox: ./simulator/sandbox")
    print(f"[*] Canary Vault: ./canary_vault")
    print(f"[*] Zero-Loss Micro-Snapshots: ./recovery_snapshots")
    print("-" * 75)

    uvicorn.run("server.app:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
