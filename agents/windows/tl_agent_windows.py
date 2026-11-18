#!/usr/bin/env python3
"""
ThreatLocker Zero Trust — Cross-Platform Windows Python Agent (tl_agent_windows.py)
Works on Windows 10/11 & Windows Server (or in Wine/Cross-Platform Simulation Mode).
"""

import os
import sys
import json
import time
import socket
import hashlib
import platform
import urllib.request

CONTROL_PLANE_URL = os.environ.get("TL_SERVER_URL", "http://127.0.0.1:9443")
AGENT_VERSION = "2.6.0-ZT-WinPy"


def build_windows_telemetry():
    is_win = platform.system().lower() == "windows"
    hostname = socket.gethostname() if is_win else "WIN-SECOPS-WS01"
    ep_id = f"ep-win-{hostname.lower()}"

    sample_win_apps = [
        {
            "name": "powershell.exe",
            "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
            "publisher": "Microsoft Windows",
            "category": "Script Interpreter",
            "status": "ringfenced",
            "cmdline": "powershell.exe -NoProfile -ExecutionPolicy Bypass"
        },
        {
            "name": "chrome.exe",
            "exe_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "sha256": "a4971c226259e67a7e097408ff432f483e048b991e1a036c242797e8e210361a",
            "publisher": "Google LLC",
            "category": "Web Browser",
            "status": "ringfenced",
            "cmdline": r"C:\Program Files\Google\Chrome\Application\chrome.exe --type=renderer"
        },
        {
            "name": "svchost.exe",
            "exe_path": r"C:\Windows\System32\svchost.exe",
            "sha256": "5182e88e642663e22040a4f0c525e8bd6a8526a67c910a7716a9b6fb76f2a6c3",
            "publisher": "Microsoft Windows",
            "category": "Windows System Binary",
            "status": "allowed",
            "cmdline": r"C:\Windows\System32\svchost.exe -k netsvcs -p"
        },
    ]

    dac_checks = [
        {
            "benchmark_id": "WIN-DAC-001",
            "title": "Microsoft Defender Real-Time Protection & Tamper Guard",
            "category": "Windows Endpoint Defense",
            "status": "compliant",
            "current_value": "RealTimeProtectionEnabled = True, TamperProtection = Enabled",
            "expected_value": "RealTimeProtectionEnabled = True",
            "severity": "high",
            "remediation_cmd": "Set-MpPreference -DisableRealtimeMonitoring $false"
        },
        {
            "benchmark_id": "WIN-DAC-002",
            "title": "SMBv1 Legacy Protocol Disabled (Anti-WannaCry/Lateral Movement)",
            "category": "Windows Network Hardening",
            "status": "compliant",
            "current_value": "EnableSMB1Protocol = False",
            "expected_value": "EnableSMB1Protocol = False",
            "severity": "high",
            "remediation_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
        },
    ]

    return {
        "endpoint_id": ep_id,
        "hostname": hostname,
        "os_type": "windows",
        "os_version": "Microsoft Windows 11 Enterprise 24H2 (10.0.26100)",
        "ip_address": "192.168.1.105",
        "mac_address": "00:15:5D:8A:4C:19",
        "agent_version": AGENT_VERSION,
        "cpu_percent": 11.4,
        "mem_percent": 38.2,
        "applications": sample_win_apps,
        "dac_checks": dac_checks,
        "events": []
    }


def send_heartbeat():
    payload = build_windows_telemetry()
    req = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/api/agent/heartbeat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        print(f"[+] Windows Agent Heartbeat synced: endpoint={res.get('endpoint_id')} mode={res.get('mode')}")


if __name__ == "__main__":
    send_heartbeat()
