#!/usr/bin/env python3
"""
IP Blocklist Manager
Description: Python utility for managing and applying IP blocklists
Usage: python blocklist_manager.py [options]
"""

import ipaddress
import json
import sys
from pathlib import Path
from typing import Set, List, Tuple, Union
import argparse


class BlocklistManager:
    """Manage IP blocklists with validation and filtering capabilities."""
    
    def __init__(self, blocklist_dir: str = "../blocklists"):
        self.blocklist_dir = Path(blocklist_dir)
        self.blocked_ips: Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = set()
        
    def load_blocklist(self, filename: str) -> int:
        """Load IPs from a blocklist file."""
        filepath = self.blocklist_dir / filename
        
        if not filepath.exists():
            print(f"Error: Blocklist file not found: {filepath}")
            return 0
            
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse IP or network
                    network = ipaddress.ip_network(line, strict=False)
                    self.blocked_ips.add(network)
                    count += 1
                except ValueError as e:
                    print(f"Warning: Invalid IP at line {line_num}: {line} - {e}")
                    
        return count
    
    def load_all_blocklists(self) -> int:
        """Load all blocklist files from the blocklist directory."""
        total = 0
        
        for file in self.blocklist_dir.glob("*.txt"):
            print(f"Loading {file.name}...")
            count = self.load_blocklist(file.name)
            print(f"  Loaded {count} entries")
            total += count
            
        return total
    
    def is_blocked(self, ip_address: str) -> Tuple[bool, str]:
        """Check if an IP address is in the blocklist."""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for network in self.blocked_ips:
                if ip in network:
                    return True, str(network)
                    
            return False, ""
            
        except ValueError as e:
            return False, f"Invalid IP: {e}"
    
    def check_list(self, ip_list: List[str]) -> None:
        """Check a list of IPs against the blocklist."""
        print("\nChecking IP addresses against blocklist:")
        print("-" * 60)
        
        blocked_count = 0
        for ip in ip_list:
            is_blocked, reason = self.is_blocked(ip)
            status = "BLOCKED" if is_blocked else "ALLOWED"
            
            if is_blocked:
                blocked_count += 1
                print(f"{ip:40} {status:10} (matches {reason})")
            else:
                print(f"{ip:40} {status:10}")
                
        print("-" * 60)
        print(f"Total checked: {len(ip_list)}, Blocked: {blocked_count}, "
              f"Allowed: {len(ip_list) - blocked_count}")
    
    def _sort_networks(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Sort networks, separating IPv4 and IPv6."""
        ipv4_networks = sorted([n for n in self.blocked_ips if n.version == 4])
        ipv6_networks = sorted([n for n in self.blocked_ips if n.version == 6])
        return ipv4_networks + ipv6_networks
    
    def export_to_format(self, output_file: str, format_type: str = "plain") -> None:
        """Export blocklist to different formats."""
        sorted_networks = self._sort_networks()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if format_type == "plain":
                for network in sorted_networks:
                    f.write(f"{network}\n")
                    
            elif format_type == "iptables":
                f.write("#!/bin/bash\n")
                f.write("# Generated iptables rules\n\n")
                for network in sorted_networks:
                    f.write(f"iptables -A INPUT -s {network} -j DROP\n")
                    
            elif format_type == "nginx":
                f.write("# Generated nginx geo block\n")
                f.write("geo $blocked_ip {\n")
                f.write("    default 0;\n")
                for network in sorted_networks:
                    f.write(f"    {network} 1;\n")
                f.write("}\n")
                
            elif format_type == "apache":
                f.write("# Generated Apache blocklist\n")
                f.write("<RequireAll>\n")
                f.write("    Require all granted\n")
                for network in sorted_networks:
                    f.write(f"    Require not ip {network}\n")
                f.write("</RequireAll>\n")
                
            elif format_type == "json":
                data = {
                    "blocked_ips": [str(ip) for ip in sorted_networks],
                    "total_count": len(self.blocked_ips)
                }
                json.dump(data, f, indent=2)
                
        print(f"Exported {len(self.blocked_ips)} entries to {output_file} ({format_type} format)")
    
    def get_statistics(self) -> dict:
        """Get statistics about loaded blocklists."""
        ipv4_count = sum(1 for ip in self.blocked_ips if ip.version == 4)
        ipv6_count = sum(1 for ip in self.blocked_ips if ip.version == 6)
        
        return {
            "total": len(self.blocked_ips),
            "ipv4": ipv4_count,
            "ipv6": ipv6_count
        }


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="IP Blocklist Manager - Manage and apply IP security lists"
    )
    
    parser.add_argument(
        "--load",
        help="Load specific blocklist file (e.g., malware.txt)"
    )
    
    parser.add_argument(
        "--load-all",
        action="store_true",
        help="Load all blocklists from directory"
    )
    
    parser.add_argument(
        "--check",
        nargs="+",
        help="Check if IP addresses are blocked"
    )
    
    parser.add_argument(
        "--export",
        help="Export blocklist to file"
    )
    
    parser.add_argument(
        "--format",
        choices=["plain", "iptables", "nginx", "apache", "json"],
        default="plain",
        help="Export format (default: plain)"
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show blocklist statistics"
    )
    
    parser.add_argument(
        "--blocklist-dir",
        default="../blocklists",
        help="Path to blocklists directory (default: ../blocklists)"
    )
    
    args = parser.parse_args()
    
    # Create manager instance
    manager = BlocklistManager(args.blocklist_dir)
    
    # Load blocklists
    if args.load:
        count = manager.load_blocklist(args.load)
        print(f"Loaded {count} entries from {args.load}")
    elif args.load_all:
        count = manager.load_all_blocklists()
        print(f"\nTotal loaded: {count} entries")
    else:
        # Default: load all
        print("Loading all blocklists...")
        count = manager.load_all_blocklists()
        print(f"\nTotal loaded: {count} entries")
    
    # Execute commands
    if args.check:
        manager.check_list(args.check)
    
    if args.export:
        manager.export_to_format(args.export, args.format)
    
    if args.stats:
        stats = manager.get_statistics()
        print("\nBlocklist Statistics:")
        print(f"  Total entries: {stats['total']}")
        print(f"  IPv4 networks: {stats['ipv4']}")
        print(f"  IPv6 networks: {stats['ipv6']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
