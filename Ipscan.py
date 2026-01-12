"""
╔══════════════════════════════════════════════════════════════╗
║        ADVANCED IP INTELLIGENCE & NETWORK FORENSICS          ║
║            Geolocation • VPN Detection • OS Hint             ║
║            Abuse Reputation • Batch Analysis                 ║
║                   BY PARIKSHIT                               ║
╚══════════════════════════════════════════════════════════════╝
"""

import folium
import ipinfo
import requests
import subprocess
import platform
import re

IPINFO_TOKEN = "(IPINFO TOKEN)"
ABUSEIPDB_API_KEY = "(ABUSE API KEY)"


# ---------------- UTILITY UI ---------------- #

def banner():
    print("""
╔══════════════════════════════════════════════════════╗
║   🌍 IP INTELLIGENCE & THREAT ANALYSIS CONSOLE 🌍    ║    
║                By Parikshit Singh Baghel             ║    
╚══════════════════════════════════════════════════════╝
    """)


def section(title):
    print(f"\n🔹 {title}")
    print("─" * 55)


# ---------------- NETWORK FUNCTIONS ---------------- #

def get_ttl(ip):
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", ip] if system == "windows" else ["ping", "-c", "1", ip]
    pattern = r"TTL=(\d+)" if system == "windows" else r"ttl=(\d+)"

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        match = re.search(pattern, output, re.IGNORECASE)
        return int(match.group(1)) if match else None
    except Exception:
        return None


def estimate_os_from_ttl(ttl):
    if ttl is None:
        return "Unavailable (ICMP Blocked 🚫)"
    if ttl <= 64:
        return "Linux / Network Device 🐧"
    if ttl <= 128:
        return "Windows System 🪟"
    return "Network Appliance 🌐"


# ---------------- IP INTELLIGENCE ---------------- #

def extract_asn_and_org(org):
    if not org:
        return "Unknown", "Unknown"
    parts = org.split(" ", 1)
    return parts[0] if parts[0].startswith("AS") else "Unknown", parts[1] if len(parts) > 1 else org


def detect_vpn(details, org):
    org = org.lower()
    vpn_terms = ["vpn", "proxy", "nord", "express", "surfshark", "proton"]
    hosting_terms = ["amazon", "aws", "google", "azure", "digitalocean", "linode", "ovh"]

    if any(t in org for t in vpn_terms):
        return True
    if any(t in org for t in hosting_terms):
        return True

    privacy = getattr(details, "privacy", None)
    if privacy and (privacy.get("vpn") or privacy.get("proxy")):
        return True

    return getattr(details, "anycast", False)


def detect_ip_type(vpn, org):
    org = org.lower()

    if vpn:
        return "🚨 VPN / Proxy Infrastructure"

    if any(k in org for k in ["airtel", "jio", "vodafone", "t-mobile", "verizon"]):
        return "📱 Mobile Network (CGNAT)"

    if any(k in org for k in ["hosting", "server", "cloud", "amazon", "azure"]):
        return "🌐 Server / Hosting Environment"

    return "🏠 Residential Network"


def abuseipdb_lookup(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if r.status_code != 200:
            return 0, 0
        data = r.json()["data"]
        return data["abuseConfidenceScore"], data["totalReports"]
    except Exception:
        return 0, 0


# ---------------- CORE ANALYSIS ---------------- #

def scan_ip(ip, map_obj=None):
    handler = ipinfo.getHandler(IPINFO_TOKEN)
    details = handler.getDetails(ip)

    if not details.loc:
        print(f"⚠️ Location unavailable for {ip}")
        return

    lat, lon = map(float, details.loc.split(","))
    asn, org = extract_asn_and_org(details.org)

    vpn = detect_vpn(details, org)
    ip_type = detect_ip_type(vpn, org)

    ttl = get_ttl(ip)
    os_hint = "Not Detectable (Mobile NAT 🔒)" if "Mobile" in ip_type else estimate_os_from_ttl(ttl)

    abuse_score, reports = abuseipdb_lookup(ip)
    risk = "🔴 HIGH" if vpn or abuse_score >= 50 else "🟠 MEDIUM" if abuse_score >= 20 else "🟢 LOW"

    section("TARGET PROFILE")
    print(f"""
🌐 IP Address     : {ip}
📍 Location       : {details.city}, {details.region}, {details.country}
🧭 Coordinates    : {lat}, {lon}
🏷️ ASN            : {asn}
🏢 Organization   : {org}
""")

    section("NETWORK CHARACTERISTICS")
    print(f"""
🔐 VPN Detected   : {'YES 🚨' if vpn else 'NO ✅'}
🧠 IP Type        : {ip_type}
📡 TTL Value      : {ttl if ttl else 'Unavailable'}
🖥️ OS Hint        : {os_hint}
""")

    section("THREAT INTELLIGENCE")
    print(f"""
⚠️ Abuse Score    : {abuse_score} %
📄 Reports Count  : {reports}
🚦 Risk Level     : {risk}
""")

    if map_obj:
        folium.Marker(
            [lat, lon],
            popup=f"""
            <b>IP:</b> {ip}<br>
            <b>Type:</b> {ip_type}<br>
            <b>Risk:</b> {risk}
            """
        ).add_to(map_obj)


# ---------------- ENTRY POINT ---------------- #

if __name__ == "__main__":
    banner()

    print("Select Mode:")
    print("  [1] 🔍 Single IP Analysis")
    print("  [2] 📂 Batch IP Scan")

    mode = input("\nEnter choice (1/2): ")

    if mode == "1":
        ip = input("\nEnter target IP: ")
        m = folium.Map(location=[0, 0], zoom_start=2)
        scan_ip(ip, m)
        m.save("map.html")
        print("\n✅ Visualization saved → map.html")

    elif mode == "2":
        file_path = input("\nEnter IP list file: ")
        with open(file_path) as f:
            ips = [i.strip() for i in f if i.strip()]

        m = folium.Map(location=[20, 0], zoom_start=2)
        for ip in ips:
            scan_ip(ip, m)

        m.save("batch_map.html")
        print("\n✅ Batch visualization saved → batch_map.html")

    else:
        print("\n❌ Invalid option selected.")
