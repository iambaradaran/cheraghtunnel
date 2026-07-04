#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import socket
import json
import statistics
from datetime import datetime

def ping_host(host, count=30):
    print(f"[*] Pinging {host} {count} times to measure latency, jitter, and packet loss...")
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
                # Parse output to find actual RTT if possible, otherwise use duration
                rtt = duration
                for line in result.stdout.split('\n'):
                    if 'time=' in line:
                        try:
                            # Extract time=XX ms
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

def test_tcp_port(host, port, count=10):
    print(f"[*] Testing TCP connection handshake latency to {host}:{port} {count} times...")
    latencies = []
    failed = 0
    
    for _ in range(count):
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            duration = (time.time() - start) * 1000  # ms
            latencies.append(duration)
            sock.close()
        except Exception as e:
            failed += 1
        time.sleep(0.1)
        
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
        "jitter": jitter
    }

def main():
    print("==================================================")
    print("      CheraghTunnel Diagnostics & Quality Test")
    print("==================================================")
    
    iran_ip = "62.60.202.4"
    kharej_ip = "91.107.181.217"
    control_port = 311  # Provided by the user
    
    # 1. Test Latency & Packet Loss
    iran_ping = ping_host(iran_ip)
    kharej_ping = ping_host(kharej_ip)
    
    # 2. Test Control Port TCP connectivity
    tcp_test = test_tcp_port(iran_ip, control_port)
    
    # Generate Markdown Report
    report_filename = "tunnel_diagnostics.md"
    
    report = f"""# CheraghTunnel Diagnostic Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 1. ICMP Latency & Jitter Analysis (Ping)
This measures basic network route stability and packet loss.

| Host IP / Role | Packet Loss | Min Ping | Avg Ping | Max Ping | Jitter (Fluctuation) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **{iran_ip}** (Iran Server) | {iran_ping['loss_rate']:.1f}% | {iran_ping['min']:.1f}ms | {iran_ping['avg']:.1f}ms | {iran_ping['max']:.1f}ms | {iran_ping['jitter']:.1f}ms | {"🔴 Critical Loss" if iran_ping['loss_rate'] > 10 else "🟢 Stable"} |
| **{kharej_ip}** (Kharej Server) | {kharej_ping['loss_rate']:.1f}% | {kharej_ping['min']:.1f}ms | {kharej_ping['avg']:.1f}ms | {kharej_ping['max']:.1f}ms | {kharej_ping['jitter']:.1f}ms | {"🔴 Critical Loss" if kharej_ping['loss_rate'] > 10 else "🟢 Stable"} |

## 2. Control Port TCP Connection Test (`{iran_ip}:{control_port}`)
This verifies if the port is fully open and measures TCP handshake latency.

* **Target Address:** `{iran_ip}:{control_port}`
* **Connection Failure Rate:** `{tcp_test['fail_rate']:.1f}%`
* **Avg TCP Handshake Time:** `{tcp_test['avg']:.2f}ms`
* **Handshake Jitter:** `{tcp_test['jitter']:.2f}ms`
* **Overall Port Status:** {"🔴 Closed / Blocked" if tcp_test['fail_rate'] == 100 else "🟡 Packet Drops" if tcp_test['fail_rate'] > 0 else "🟢 Fully Open"}

## 3. Raw Latency Jitter Histogram
Below are the individual ping RTT measurements to check for random spikes.

* **Iran Server RTTs (ms):**
  `{", ".join([f"{p:.1f}" for p in iran_ping['pings']])}`
  
* **Kharej Server RTTs (ms):**
  `{", ".join([f"{p:.1f}" for p in kharej_ping['pings']])}`

## 4. Diagnosis Summary & Recommendations
"""
    
    # Analyze results for automated recommendations
    recommendations = []
    if iran_ping['loss_rate'] > 0 or kharej_ping['loss_rate'] > 0:
        recommendations.append("- **Network Packet Loss Detected:** ICMP packet loss exists between you and the servers. This is usually caused by ISP throttling or international network congestion in Iran.")
    
    if tcp_test['fail_rate'] == 100:
        recommendations.append("- **Port Blocked:** TCP connections to port %d are failing completely. Make sure your server firewall (`ufw allow %d/tcp`) is open and that your cloud provider's external security group allows this port." % (control_port, control_port))
    elif tcp_test['fail_rate'] > 0:
        recommendations.append("- **TCP Handshake Instability:** Some TCP handshakes timed out. This suggests active filtering or severe congestion on this TCP port.")
        
    if iran_ping['jitter'] > 15 or kharej_ping['jitter'] > 15:
        recommendations.append("- **High Jitter (Fluctuation):** Latency is fluctuating heavily. For gaming, KCP (photon) protocol with increased window sizes (which we enabled in v1.6.18) should help smooth this out, but standard TCP protocols (like beam) will feel laggy.")

    if not recommendations:
        recommendations.append("- **All tests green:** The network connection is clean and stable. No routing or firewall blocks detected.")
        
    report += "\n".join(recommendations)
    report += "\n"
    
    with open(report_filename, "w") as f:
        f.write(report)
        
    print(f"\n[+] Diagnostics completed! Report written to: {report_filename}")
    print("==================================================")
    print("You can copy the contents of the report file and share them here.")

if __name__ == "__main__":
    main()
