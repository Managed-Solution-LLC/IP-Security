import requests
import os
from datetime import datetime

def fetch_feodo_tracker():
    """
    Fetch Feodo Tracker botnet C&C IPs from abuse.ch
    """
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        ips = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            ips.append(line)
        
        print(f"Feodo Tracker (Botnet C&C): {len(ips)} IPs")
        return ips
        
    except requests.RequestException as e:
        print(f"Error fetching Feodo Tracker data: {e}")
        return []

def fetch_blocklist_de(category):
    """
    Fetch IPs from blocklist.de by category
    Categories: ssh, mail, apache, bots, bruteforce, etc.
    """
    url = f"https://lists.blocklist.de/lists/{category}.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        ips = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            ips.append(line)
        
        print(f"Blocklist.de ({category}): {len(ips)} IPs")
        return ips
        
    except requests.RequestException as e:
        print(f"Error fetching blocklist.de {category} data: {e}")
        return []

def fetch_cinsscore_malware():
    """
    Fetch malware IPs from CINS Score
    """
    url = "http://cinsscore.com/list/ci-badguys.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        ips = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Skip if it looks like a header or non-IP
            if '.' in line and not line.startswith('http'):
                ips.append(line)
        
        print(f"CINS Score (Malware): {len(ips)} IPs")
        return ips
        
    except requests.RequestException as e:
        print(f"Error fetching CINS Score data: {e}")
        return []

def fetch_emerging_threats():
    """
    Fetch compromised IPs from Emerging Threats
    """
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        ips = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            ips.append(line)
        
        print(f"Emerging Threats (Compromised): {len(ips)} IPs")
        return ips
        
    except requests.RequestException as e:
        print(f"Error fetching Emerging Threats data: {e}")
        return []

def fetch_spamhaus_drop():
    """
    Fetch Spamhaus DROP list (hijacked/leased ranges)
    """
    url = "https://www.spamhaus.org/drop/drop.txt"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        ips = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            # Extract CIDR from format: "CIDR ; SBL123"
            parts = line.split(';')
            if parts:
                cidr = parts[0].strip()
                if cidr:
                    ips.append(cidr)
        
        print(f"Spamhaus DROP: {len(ips)} ranges")
        return ips
        
    except requests.RequestException as e:
        print(f"Error fetching Spamhaus DROP data: {e}")
        return []

def write_blocklist(filename, ips, title, description, sources):
    """
    Write a categorized blocklist file
    """
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'blocklists')
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, filename)
    
    # Deduplicate and sort
    unique_ips = sorted(set(ips))
    
    with open(output_file, 'w') as f:
        f.write(f"# {title}\n")
        f.write(f"# Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Description: {description}\n")
        f.write(f"# Format: One IP or CIDR range per line\n")
        f.write(f"# Sources: {sources}\n")
        f.write(f"# Total Unique Entries: {len(unique_ips)}\n")
        f.write(f"#\n\n")
        
        for ip in unique_ips:
            f.write(ip + '\n')
    
    print(f"✓ Created {filename} with {len(unique_ips)} entries")
    return unique_ips

def build_botnet_list():
    """
    Build botnet blocklist from various sources
    """
    print("\n=== Building Botnet Blocklist ===")
    
    all_ips = []
    
    # Feodo Tracker - botnet C&C
    all_ips.extend(fetch_feodo_tracker())
    
    # Blocklist.de bots category
    all_ips.extend(fetch_blocklist_de('bots'))
    
    write_blocklist(
        'botnet.txt',
        all_ips,
        'Botnet Command & Control Blocklist',
        'IP addresses of botnet C&C servers and known compromised hosts',
        'Feodo Tracker (abuse.ch), blocklist.de'
    )

def build_malware_list():
    """
    Build malware distribution blocklist
    """
    print("\n=== Building Malware Blocklist ===")
    
    all_ips = []
    
    # CINS Score malware IPs
    all_ips.extend(fetch_cinsscore_malware())
    
    # Emerging Threats compromised hosts
    all_ips.extend(fetch_emerging_threats())
    
    # Spamhaus DROP (hijacked/leased networks)
    all_ips.extend(fetch_spamhaus_drop())
    
    write_blocklist(
        'malware.txt',
        all_ips,
        'Malware Distribution IP Blocklist',
        'IP addresses known to distribute malware, ransomware, or other malicious software',
        'CINS Score, Emerging Threats, Spamhaus DROP'
    )

def build_abuse_list():
    """
    Build abuse/spam blocklist
    """
    print("\n=== Building Abuse & Spam Blocklist ===")
    
    all_ips = []
    
    # Blocklist.de various abuse categories
    all_ips.extend(fetch_blocklist_de('ssh'))
    all_ips.extend(fetch_blocklist_de('mail'))
    all_ips.extend(fetch_blocklist_de('apache'))
    all_ips.extend(fetch_blocklist_de('bruteforce'))
    
    write_blocklist(
        'abuse.txt',
        all_ips,
        'Abuse & Spam IP Blocklist',
        'IP addresses associated with spam, port scanning, brute force attacks, and general abuse',
        'blocklist.de (SSH, Mail, Apache, Bruteforce)'
    )

def main():
    """
    Build all categorized blocklists
    """
    print("Starting categorized blocklist generation...")
    print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
    
    build_botnet_list()
    build_malware_list()
    build_abuse_list()
    
    print("\n✅ All categorized blocklists have been updated!")

if __name__ == "__main__":
    main()
