# IP-Security

A curated collection of IP address lists for security filtering, threat prevention, and network protection.

## Overview

This repository provides an organized assortment of IP lists that can be used for:
- **Firewall rules** - Block malicious traffic at the network perimeter
- **WAF (Web Application Firewall)** - Enhance application-level security
- **IDS/IPS systems** - Improve intrusion detection and prevention
- **Proxy servers** - Filter traffic based on reputation
- **API rate limiting** - Protect services from abuse

## Repository Structure

```
IP-Security/
├── blocklists/          # IP addresses to block (threats, abuse sources)
│   ├── malware.txt      # Known malware distribution IPs
│   ├── botnet.txt       # Botnet command & control servers
│   ├── tor-exit.txt     # Tor exit nodes
│   └── abuse.txt        # IPs associated with abuse/spam
├── allowlists/          # Trusted IP addresses (CDNs, services)
│   ├── cdn.txt          # Content Delivery Network IPs
│   └── cloud.txt        # Cloud provider IP ranges
└── examples/            # Usage examples for various platforms
    └── iptables.sh      # Example iptables rules
```

## IP List Formats

All IP lists in this repository follow these conventions:

- **One IP address or CIDR range per line**
- **Comments** start with `#`
- **IPv4 and IPv6** support
- **CIDR notation** for ranges (e.g., 192.168.1.0/24)

Example:
```
# Example blocklist
192.0.2.1
198.51.100.0/24
2001:db8::/32  # IPv6 range
```

## Usage

### Basic Usage

1. **Download the lists you need:**
   ```bash
   wget https://raw.githubusercontent.com/Managed-Solution-LLC/IP-Security/main/blocklists/malware.txt
   ```

2. **Apply to your firewall/security tool** (see examples directory)

3. **Update regularly** - IP reputation changes frequently

### Integration Examples

#### iptables (Linux)
```bash
# Block IPs from malware.txt
while read ip; do
  [[ "$ip" =~ ^#.*$ ]] && continue  # Skip comments
  [[ -z "$ip" ]] && continue         # Skip empty lines
  iptables -A INPUT -s "$ip" -j DROP
done < blocklists/malware.txt
```

#### nginx
```nginx
# In your nginx.conf or site config
geo $block_ip {
    default 0;
    include /path/to/blocklists/abuse.txt;
}

server {
    if ($block_ip) {
        return 403;
    }
}
```

#### Apache
```apache
# In .htaccess or httpd.conf
<RequireAll>
    Require all granted
    Require not ip 192.0.2.1
    Require not ip 198.51.100.0/24
</RequireAll>
```

## List Categories

### Blocklists

- **malware.txt** - IPs known to distribute malware
- **botnet.txt** - Botnet C&C servers and compromised hosts
- **tor-exit.txt** - Tor exit node IPs (block if needed for your use case)
- **abuse.txt** - IPs associated with spam, scanning, or abuse

### Allowlists

- **cdn.txt** - Major CDN provider IP ranges (Cloudflare, Fastly, etc.)
- **cloud.txt** - Cloud provider IP ranges (AWS, Azure, GCP)

## Updating Lists

IP lists should be updated regularly as the threat landscape changes:

```bash
# Recommended: Update at least weekly
0 2 * * 0 /usr/local/bin/update-iplists.sh
```

## Contributing

To contribute new lists or updates:

1. Ensure IPs are verified and from reputable sources
2. Follow the format conventions
3. Include source/reason in comments
4. Submit a pull request with description

## Disclaimer

These IP lists are provided for security purposes. Please note:

- **Not comprehensive** - No blocklist is 100% complete
- **False positives possible** - Legitimate users may share IPs with threats
- **Regular updates needed** - IP reputation changes constantly
- **Test before production** - Always test in a non-production environment first
- **No warranty** - Use at your own risk

## Sources and Credits

Lists are compiled from:
- Public threat intelligence feeds
- Security research
- Community contributions
- Verified abuse reports

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please open an issue on GitHub.