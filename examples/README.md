# Examples Directory

This directory contains practical examples for using the IP-Security lists with various platforms and tools.

## Available Examples

### 1. iptables.sh
**Linux firewall management script**

- Interactive menu for applying blocklists
- Supports individual or all blocklists
- Includes logging and statistics
- Easy cleanup/removal

```bash
sudo ./iptables.sh                    # Interactive mode
sudo ./iptables.sh ../blocklists/malware.txt  # Apply specific list
```

**Requirements:**
- Linux system with iptables
- Root/sudo access
- bash shell

### 2. nginx.conf
**nginx web server configuration**

- Geo blocking configuration
- Map-based IP filtering
- Rate limiting examples
- Include file examples

**Usage:**
1. Copy relevant sections to your nginx config
2. Adjust paths and IPs as needed
3. Test: `nginx -t`
4. Reload: `nginx -s reload`

**Requirements:**
- nginx with geo and map modules
- Write access to nginx config directory

### 3. apache.conf
**Apache web server configuration**

- Multiple blocking methods (Require, SetEnvIf, Rewrite)
- Apache 2.2 and 2.4+ examples
- .htaccess examples
- VirtualHost configuration

**Usage:**
1. Copy relevant sections to httpd.conf or .htaccess
2. Adjust IPs and paths
3. Test: `apachectl configtest`
4. Reload: `systemctl reload apache2`

**Requirements:**
- Apache 2.2+ or 2.4+
- mod_authz_core (2.4+) or mod_authz_host (2.2)
- Optional: mod_rewrite, mod_setenvif

### 4. blocklist_manager.py
**Python utility for managing IP lists**

- Load and validate blocklists
- Check if IPs are blocked
- Export to multiple formats (iptables, nginx, apache, JSON)
- Statistics and reporting

```bash
# Check if IPs are blocked
./blocklist_manager.py --check 192.0.2.10 198.51.100.50

# Load specific list and show stats
./blocklist_manager.py --load malware.txt --stats

# Export to iptables format
./blocklist_manager.py --load-all --export rules.sh --format iptables

# Export to nginx format
./blocklist_manager.py --load-all --export blocklist.conf --format nginx
```

**Requirements:**
- Python 3.6+
- No external dependencies (uses stdlib only)

**Arguments:**
- `--load FILE`: Load specific blocklist file
- `--load-all`: Load all blocklists from directory
- `--check IP [IP...]`: Check if IPs are blocked
- `--export FILE`: Export to file
- `--format FORMAT`: Export format (plain, iptables, nginx, apache, json)
- `--stats`: Show blocklist statistics
- `--blocklist-dir DIR`: Path to blocklists directory

## Platform-Specific Notes

### Linux (iptables)
- Rules are not persistent by default
- Use `iptables-persistent` or save rules manually
- Consider performance with very large lists (10,000+ IPs)
- Use ipset for better performance with large lists

### nginx
- Geo module is efficient for large lists
- Reload is graceful (no dropped connections)
- Test configuration before applying
- Monitor error logs for false positives

### Apache
- Require directive (2.4+) is most efficient
- Large lists may impact performance
- Consider mod_security for advanced filtering
- Test with configtest before reload

### Python Script
- Cross-platform compatible
- Can be integrated into automation workflows
- Useful for CI/CD pipelines
- Easy to extend for custom formats

## Integration Workflows

### Automated Updates

**Cron job example:**
```bash
# Update lists daily at 2 AM
0 2 * * * cd /path/to/IP-Security && git pull && /path/to/apply-rules.sh
```

**Systemd timer example:**
```ini
[Unit]
Description=Update IP blocklists

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Validate IP Lists
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate IP formats
        run: python examples/blocklist_manager.py --load-all --stats
```

### Monitoring

**Log analysis:**
```bash
# Count blocked requests (nginx)
grep "403" /var/log/nginx/access.log | wc -l

# Show most blocked IPs (iptables)
iptables -L IP_BLOCKLIST -n -v | sort -k1 -nr | head
```

## Creating Custom Examples

To add your own example:

1. Create a new file in this directory
2. Include clear comments and documentation
3. Provide usage instructions
4. Test thoroughly
5. Submit a pull request

### Example Template

```bash
#!/bin/bash
# Tool Name Configuration Example
# Description: Brief description of what this example does
# Requirements: List any requirements
# Usage: Show how to use it

# Your configuration or script here
```

## Best Practices

1. **Test First**: Always test in non-production before deploying
2. **Monitor Logs**: Watch for false positives after deployment
3. **Update Regularly**: IP reputation changes frequently
4. **Layer Security**: Use multiple security layers, not just IP filtering
5. **Performance**: Consider impact on system performance
6. **Documentation**: Document your specific implementation
7. **Backup**: Keep backups of working configurations
8. **Gradual Rollout**: Deploy to small subset before full deployment

## Troubleshooting

### Common Issues

**iptables rules not persisting:**
- Install and configure iptables-persistent
- Or save rules manually: `iptables-save > /etc/iptables/rules.v4`

**nginx configuration errors:**
- Check syntax: `nginx -t`
- Verify file paths are correct
- Ensure proper permissions

**Apache not blocking:**
- Verify module is loaded: `apache2ctl -M`
- Check Apache version (2.2 vs 2.4 syntax differs)
- Review error logs

**Python script errors:**
- Verify Python version (3.6+)
- Check file paths are correct
- Ensure proper permissions to read blocklists

## Support

For questions about these examples:
- Check the main README.md
- Review the CONTRIBUTING.md guide
- Open an issue on GitHub

## License

These examples are provided under the GNU General Public License v3.0, same as the main project.
