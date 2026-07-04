#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import socket
import json
import statistics
import argparse
from datetime import datetime

def ping_host(host, count=30):
    print(f"[*] Pinging {host} {count} times to measure raw latency, jitter, and packet loss...")
    pings = []
    lost = 0
    
    # Determine ping command based on OS
    param = '-n' if sys.platform.lower() == 'windows' else '-c'
    timeout_param = '-w' if sys.platform.lower() == 'windows' else '-W'
    timeout_val = '1000' if sys.platform.lower() == 'windows' else '1'
    
    for i in range(count):
        start = time.time()
        try:
            # Run ping command
            cmd = ['ping', param, '1', timeout_param, timeout_val, host]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            duration = (time.time() - start) * 1000  # ms
            
            if result.returncode == 0:
                rtt = duration
                for line in result.stdout.split('\n'):
                    if 'time=' in line:
                        try:
                            parts = line.split('time=')[1].split()[0]
                            parts = parts.replace('ms', '')
                            rtt = float(parts)
                        except:
                            pass
                pings.append(rtt)
            else:
                lost += 1
        except Exception as e:
            lost += 1
        time.sleep(0.05)
        
    loss_rate = (lost / count) * 100
    if pings:
        avg_ping = statistics.mean(pings)
        min_ping = min(pings)
        max_ping = max(pings)
        jitter = statistics.stdev(pings) if len(pings) > 1 else 0
    else:
        avg_ping, min_ping, max_ping, jitter = 0, 0, 0, 0
        
    return {
        "host": host,
        "loss_rate": loss_rate,
        "avg": avg_ping,
        "min": min_ping,
        "max": max_ping,
        "jitter": jitter,
        "pings": pings
    }

def test_tcp_port(host, port, count=10, timeout=2.0):
    latencies = []
    failed = 0
    
    for _ in range(count):
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            duration = (time.time() - start) * 1000  # ms
            latencies.append(duration)
            sock.close()
        except Exception as e:
            failed += 1
        time.sleep(0.05)
        
    fail_rate = (failed / count) * 100
    if latencies:
        avg_lat = statistics.mean(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        jitter = statistics.stdev(latencies) if len(latencies) > 1 else 0
    else:
        avg_lat, min_lat, max_lat, jitter = 0, 0, 0, 0
        
    return {
        "host": host,
        "port": port,
        "fail_rate": fail_rate,
        "avg": avg_lat,
        "min": min_lat,
        "max": max_lat,
        "jitter": jitter,
        "latencies": latencies
    }

def test_tunnel_end_to_end(tunnel_port):
    print(f"\n[*] Testing End-to-End Tunnel Quality via local port {tunnel_port}...")
    # Connect to 127.0.0.1:<tunnel_port> which routes through the tunnel
    res = test_tcp_port("127.0.0.1", tunnel_port, count=20, timeout=3.0)
    
    # Try to read SSH banner or check if connection is active
    banner = "No banner (expected for VMess/Trojan/VLESS protocols)"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect(("127.0.0.1", tunnel_port))
        # Read up to 100 bytes (e.g. SSH banner)
        data = sock.recv(100)
        if data:
            banner = data.decode('utf-8', errors='ignore').strip()
        sock.close()
    except Exception as e:
        # Many protocols are silent (don't send a banner), which is fine
        pass
        
    return res, banner

def main():
    parser = argparse.ArgumentParser(description="CheraghTunnel Diagnostics")
    parser.add_argument("--tunnel-port", type=int, help="The public port of the tunnel on Iran server to test end-to-end")
    args = parser.parse_args()
    
    print("==================================================")
    print("      CheraghTunnel Diagnostics & Quality Test")
    print("==================================================")
    
    iran_ip = "62.60.202.4"
    kharej_ip = "91.107.181.217"
    
    # 1. Test Raw Network Latency & Packet Loss
    iran_ping = ping_host(iran_ip)
    kharej_ping = ping_host(kharej_ip)
    
    # 2. Test Tunnel End-to-End if port is provided
    tunnel_res = None
    banner = None
    if args.tunnel_port:
        tunnel_res, banner = test_tunnel_end_to_end(args.tunnel_port)
    
    # Generate Markdown Report
    report_filename = "tunnel_diagnostics.md"
    
    report = f"""# CheraghTunnel Diagnostic Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 1. Raw Network Latency & Jitter Analysis (Ping)
This measures basic network route stability and packet loss.

| Host IP / Role | Packet Loss | Min Ping | Avg Ping | Max Ping | Jitter (Fluctuation) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **{iran_ip}** (Iran Server) | {iran_ping['loss_rate']:.1f}% | {iran_ping['min']:.1f}ms | {iran_ping['avg']:.1f}ms | {iran_ping['max']:.1f}ms | {iran_ping['jitter']:.1f}ms | {"🔴 Critical Loss" if iran_ping['loss_rate'] > 10 else "🟢 Stable"} |
| **{kharej_ip}** (Kharej Server) | {kharej_ping['loss_rate']:.1f}% | {kharej_ping['min']:.1f}ms | {kharej_ping['avg']:.1f}ms | {kharej_ping['max']:.1f}ms | {kharej_ping['jitter']:.1f}ms | {"🔴 Critical Loss" if kharej_ping['loss_rate'] > 10 else "🟢 Stable"} |
"""

    if tunnel_res:
        report += f"""
## 2. End-to-End Tunnel Performance (Port {args.tunnel_port})
This measures connection quality **through** the active CheraghTunnel to the Kharej backend.

* **Target Local Port:** `{args.tunnel_port}` (routes to Kharej backend)
* **Tunnel Connection Loss Rate:** `{tunnel_res['fail_rate']:.1f}%`
* **Avg Tunnel Connection Latency:** `{tunnel_res['avg']:.1f}ms`
* **Tunnel Jitter (Latency Fluctuation):** `{tunnel_res['jitter']:.1f}ms`
* **End-to-End Banner/Response:** `{banner}`
* **Tunnel Status:** {"🟢 Stable Connection" if tunnel_res['fail_rate'] == 0 else "🟡 Packet Drops / Instability" if tunnel_res['fail_rate'] < 50 else "🔴 Broken / Closed Tunnel"}

* **Individual Tunnel Latency Samples (ms):**
  `{", ".join([f"{p:.1f}" for p in tunnel_res['latencies']])}`
"""

    report += f"""
## 3. Raw Latency Jitter Histogram
Below are the individual ping RTT measurements to check for random spikes.

* **Iran Server RTTs (ms):**
  `{", ".join([f"{p:.1f}" for p in iran_ping['pings']])}`
  
* **Kharej Server RTTs (ms):**
  `{", ".join([f"{p:.1f}" for p in kharej_ping['pings']])}`

## 4. Diagnosis Summary & Recommendations
"""
    
    recommendations = []
    if iran_ping['loss_rate'] > 0 or kharej_ping['loss_rate'] > 0:
        recommendations.append("- **Network Packet Loss Detected:** ICMP packet loss exists between you and the servers. This is usually caused by ISP throttling or international network congestion in Iran.")
        
    if tunnel_res:
        if tunnel_res['fail_rate'] > 0:
            recommendations.append(f"- **Tunnel Packet Drops ({tunnel_res['fail_rate']:.1f}%):** Connections passing through the tunnel are dropping. Since FakeTCP/KCP recovers lost packets, this means the underlying packet loss between Iran and Kharej is extremely high, or the KCP buffer is getting overloaded.")
        if tunnel_res['jitter'] > 15:
            recommendations.append(f"- **High Tunnel Jitter ({tunnel_res['jitter']:.1f}ms):** Connection latency through the tunnel is unstable. Check CPU load on both servers or try adjusting the control port to bypass ISP rate limits.")
    else:
        recommendations.append("- **Note:** You did not specify a `--tunnel-port`, so end-to-end tunnel performance was not measured.")

    if not recommendations or (tunnel_res and tunnel_res['fail_rate'] == 0 and tunnel_res['jitter'] <= 15 and len(recommendations) == 1):
        recommendations = ["- **All tests green:** The tunnel connection is clean and stable. No routing or firewall blocks detected."]
        
    report += "\n".join(recommendations)
    report += "\n"
    
    with open(report_filename, "w") as f:
        f.write(report)
        
    print(f"\n[+] Diagnostics completed! Report written to: {report_filename}")
    print("==================================================")
    print("You can copy the contents of the report file and share them here.")

if __name__ == "__main__":
    main()
