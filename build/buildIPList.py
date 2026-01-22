import requests
import os
from datetime import datetime

def fetch_and_filter_ipsum():
    """
    Fetch IPsum threat intelligence data and filter IPs with 2 or more hits
    """
    url = "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
    
    try:
        # Fetch the data
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Parse and filter the data
        filtered_ips = []
        for line in response.text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse IP and hit count (format: "IP_ADDRESS    HIT_COUNT")
            parts = line.split()
            if len(parts) >= 2:
                ip_address = parts[0]
                try:
                    hit_count = int(parts[1])
                    if hit_count >= 2:
                        filtered_ips.append(ip_address)
                except ValueError:
                    continue
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(__file__), 'blocklists')
        os.makedirs(output_dir, exist_ok=True)
        
        # Write filtered IPs to file with header
        output_file = os.path.join(output_dir, 'IPsum_latest.txt')
        with open(output_file, 'w') as f:
            # Write header comments
            f.write(f"# Source: {url}\n")
            f.write(f"# Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            # Write IPs
            for ip in filtered_ips:
                f.write(ip + '\n')
        
        print(f"Successfully created {output_file}")
        print(f"Total IPs with 2+ hits: {len(filtered_ips)}")
        
        return filtered_ips
        
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return []
    except Exception as e:
        print(f"Error processing data: {e}")
        return []

def fetch_alienvault_reputation():
    """
    Fetch AlienVault OTX reputation data and extract IPs
    """
    url = "https://reputation.alienvault.com/reputation.generic"
    
    try:
        # Fetch the data
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Parse and extract IPs
        filtered_ips = []
        for line in response.text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Format: "IP # Reliability # Risk # Type # Country # Locale # Coords # x"
            parts = line.split('#')
            if len(parts) >= 1:
                ip_address = parts[0].strip()
                if ip_address:
                    filtered_ips.append(ip_address)
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(__file__), 'blocklists')
        os.makedirs(output_dir, exist_ok=True)
        
        # Write IPs to file with header
        output_file = os.path.join(output_dir, 'AlienVault_latest.txt')
        with open(output_file, 'w') as f:
            # Write header comments
            f.write(f"# Source: {url}\n")
            f.write(f"# Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            # Write IPs
            for ip in filtered_ips:
                f.write(ip + '\n')
        
        print(f"Successfully created {output_file}")
        print(f"Total IPs: {len(filtered_ips)}")
        
        return filtered_ips
        
    except requests.RequestException as e:
        print(f"Error fetching AlienVault data: {e}")
        return []
    except Exception as e:
        print(f"Error processing AlienVault data: {e}")
        return []

def create_master_list(ipsum_ips, alienvault_ips):
    """
    Merge all IP lists into a deduplicated master list in the root directory
    """
    try:
        # Combine all IPs and deduplicate
        all_ips = set(ipsum_ips + alienvault_ips)
        
        # Sort IPs for consistent output
        sorted_ips = sorted(all_ips)
        
        # Write master list to root directory
        root_dir = os.path.dirname(os.path.dirname(__file__))
        output_file = os.path.join(root_dir, 'primary_blocklist.txt')
        
        with open(output_file, 'w') as f:
            # Write header
            f.write(f"# Primary IP Blocklist\n")
            f.write(f"# Sources: IPsum (2+ hits), AlienVault OTX\n")
            f.write(f"# Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"# Total Unique IPs: {len(sorted_ips)}\n")
            # Write IPs
            for ip in sorted_ips:
                f.write(ip + '\n')
        
        print(f"\nSuccessfully created primary blocklist: {output_file}")
        print(f"Total unique IPs in primary list: {len(sorted_ips)}")
        print(f"  - IPsum: {len(ipsum_ips)}")
        print(f"  - AlienVault: {len(alienvault_ips)}")
        print(f"  - Duplicates removed: {len(ipsum_ips) + len(alienvault_ips) - len(sorted_ips)}")
        
    except Exception as e:
        print(f"Error creating primary list: {e}")

if __name__ == "__main__":
    ipsum_ips = fetch_and_filter_ipsum()
    alienvault_ips = fetch_alienvault_reputation()
    create_master_list(ipsum_ips, alienvault_ips)
