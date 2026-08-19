# 📡 Real Live Packet Capture Module for SENTRY SIEM

This module replaces the simulated network traffic replay with **real, live packet sniffing** directly from your machine's physical network adapter using [Scapy](https://scapy.net/).

---

## 🛠️ 1. Windows Setup & Administrative Requirements

### Step 1: Install Npcap Packet Capture Driver (Required on Windows)
1. Download Npcap from the official website: [https://npcap.com/#download](https://npcap.com/#download)
2. Run the installer and ensure you check the box:
   - ✅ **"Install Npcap in WinPcap API-compatible Mode"**
3. Complete the installation.

### Step 2: Run Terminal as Administrator
On Windows, raw packet sniffing requires elevated system permissions:
1. Open PowerShell or Command Prompt as **Administrator** (*Right-click -> Run as Administrator*).
2. Navigate to your project directory:
   ```cmd
   cd c:\sentry-siem\backend
   ```

---

## ⚙️ 2. How to Toggle Live Capture vs. Simulated Replay

A global configuration flag `USE_LIVE_CAPTURE` allows seamless switching between modes without modifying code:

### 🔴 Mode A: Real Live Network Sniffing (Active Adapter)
```cmd
set USE_LIVE_CAPTURE=true
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### 🟢 Mode B: Simulated Replay (KDDTest Dataset - Default)
```cmd
set USE_LIVE_CAPTURE=false
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

---

## 🔍 3. Feature Extraction & Documented Limitations

### ✅ Features Extracted Live from Packets:
* `src_ip`: Real local/remote IP address of the transmitting host
* `dst_ip`: Real remote/local IP address of the receiving host
* `dst_port`: Real destination port number (e.g. 80, 443, 22, 53)
* `protocol_type`: `tcp`, `udp`, or `icmp`
* `service`: Mapped from destination port (`80` $\rightarrow$ `http`, `443` $\rightarrow$ `https`, `22` $\rightarrow$ `ssh`, `53` $\rightarrow$ `domain_u`)
* `duration`: Flow duration in seconds
* `src_bytes`: Sum of bytes sent by source
* `dst_bytes`: Sum of bytes returned by destination
* `count` & `srv_count`: Rolling 2-second connection window count per host/service
* `same_srv_rate` & `diff_srv_rate`: Ratio of same-service requests in recent window
* `flag`: Derived TCP connection state (`SF` = Normal Established, `S0` = SYN attempt without ACK, `REJ` = Connection Rejected)

### ⚠️ Features Set to Neutral Defaults (`0`):
> **Documented Limitation**: The following 16 host/application-level features cannot be derived from un-decrypted Layer-3 / Layer-4 network packet headers alone without local OS endpoint agents or audit logs:
> - `num_failed_logins`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `num_outbound_cmds`, `is_host_login`, `is_guest_login`, `land`, `wrong_fragment`, `urgent`, `hot`
>
> These are defaulted to neutral values (`0`) in `backend/live_capture.py` as per the NSL-KDD benchmark specification.

---

## 🎯 4. What to Expect (Live Capture vs. Simulated Replay)

1. **Benign Traffic Dominance**: During live capture on your personal Wi-Fi/Ethernet, **95%+ of traffic will classify as `Normal`**. This is expected and correct behavior for a clean network.
2. **Real IP Addresses**: The dashboard will display your machine's real IP (e.g. `192.168.29.x` or `10.x.x.x`) and the actual remote server IPs your computer communicates with (e.g. Google, Cloudflare, GitHub).
3. **How to Trigger Live Attack Alerts for Demo**:
   To test live threat detection safely with permission:
   - Run an `nmap` port scan against your local loopback or gateway:
     ```cmd
     nmap -sS 127.0.0.1
     ```
   - The ML model and rules engine will instantly detect the rapid SYN connection pattern, classify it as **`Port Scan`**, calculate MITRE ATT&CK technique **`T1595.002`**, and broadcast a live alert to your SIEM console!
