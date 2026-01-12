# 🌍 Advanced IP Intelligence & Network Forensics

## Geolocation • VPN Detection • OS Fingerprinting • Threat Intelligence

A lightweight Python-based IP intelligence and threat analysis tool for OSINT, incident response, SOC operations, and cybercrime investigations.
It enriches IP addresses with network metadata, abuse reputation, OS hints, and interactive maps.

## Built by Parikshit Singh Baghel

### ✨ Features

#### 🌐 IP geolocation with interactive maps

#### 🔐 VPN / Proxy / Hosting detection

#### 🧠 TTL-based OS fingerprinting

#### ⚠️ AbuseIPDB threat intelligence

#### 📂 Single & batch IP analysis

#### 📊 Risk scoring (Low / Medium / High)

### 🛠️ Tech Stack

#### Python 3.8+

#### ipinfo

#### requests

#### folium

📦 Installation
git clone https://github.com/parikshit-cyber/advance-ip-info.git

cd advance-ip-info

pip install ipinfo requests folium


Configure API keys inside the script:

IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"

ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"

### 🚀 Usage
#### python Ipscan.py

#### Modes

#### Single IP Scan → Generates map.html

#### Batch IP Scan → Generates batch_map.html

#### Open the HTML files in a browser to view results.

### 📊 Risk Logic

#### 🟢 Low – Clean IP

#### 🟠 Medium – Abuse score ≥ 20

#### 🔴 High – VPN detected or abuse score ≥ 50

### ⚖️ Disclaimer

#### For defensive security, OSINT, research, and incident response only.
Unauthorized or malicious use is strictly prohibited.

### ⭐ Author

#### Parikshit Singh Baghel
Cybersecurity • OSINT • DFIR • Threat Intelligence
