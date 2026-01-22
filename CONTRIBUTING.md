# Contributing to IP-Security

Thank you for your interest in contributing to IP-Security! This document provides guidelines for contributing to this repository.

## How to Contribute

### Reporting Issues

If you find an issue with the IP lists or have suggestions:

1. Check if the issue already exists in the [Issues](https://github.com/Managed-Solution-LLC/IP-Security/issues) section
2. If not, create a new issue with:
   - Clear description of the problem
   - Steps to reproduce (if applicable)
   - Expected vs. actual behavior
   - Any relevant logs or examples

### Adding or Updating IP Lists

When contributing IP lists, please ensure:

#### Quality Standards

1. **Verified Sources**: Only include IPs from reputable, verified sources
2. **Documentation**: Include comments explaining the source and nature of IPs
3. **Current Data**: Ensure the list is up-to-date
4. **No False Positives**: Verify IPs are actually malicious/relevant

#### Format Requirements

All IP lists must follow these conventions:

```
# Comment lines start with hash
# Include source, date, and description

# Individual IPs
192.0.2.1

# CIDR notation for ranges
198.51.100.0/24

# IPv6 support
2001:db8::/32
```

**Requirements:**
- One IP address or CIDR range per line
- Comments use `#` prefix
- No trailing whitespace
- UTF-8 encoding
- Unix line endings (LF)

#### Pull Request Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/IP-Security.git
   cd IP-Security
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b add-new-blocklist
   ```

3. **Make your changes**
   - Add or update IP lists
   - Update documentation if needed
   - Follow format conventions

4. **Test your changes**
   ```bash
   # Validate IP format
   python examples/blocklist_manager.py --load your-list.txt --stats
   ```

5. **Commit with clear messages**
   ```bash
   git add blocklists/your-list.txt
   git commit -m "Add new blocklist for XYZ threats"
   ```

6. **Push and create Pull Request**
   ```bash
   git push origin add-new-blocklist
   ```
   
   Then create a PR on GitHub with:
   - Description of what you're adding/changing
   - Source of the IP data
   - Verification method used
   - Any relevant context

### List Categories

#### Blocklists
Should contain IPs that are:
- Actively malicious
- Confirmed threat sources
- Documented abuse sources
- From reputable threat intelligence

**Do NOT include:**
- Unverified IPs
- Personal vendettas
- Legitimate services (unless specific security reason)
- Entire ISP ranges without justification

#### Allowlists
Should contain IPs that are:
- Official CDN/cloud provider ranges
- Well-known trusted services
- Verified from official sources

### Adding Examples

When contributing usage examples:

1. **Support multiple platforms** where possible
2. **Include comments** explaining each section
3. **Provide error handling** in scripts
4. **Test thoroughly** before submitting
5. **Follow best practices** for the platform

### Documentation

When updating documentation:

1. Use clear, concise language
2. Include examples where helpful
3. Keep formatting consistent
4. Update table of contents if needed
5. Check for broken links

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Personal or political attacks
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## Review Process

1. **Automated Checks**: PR must pass any automated validation
2. **Peer Review**: Maintainers will review for quality and accuracy
3. **Testing**: Changes may be tested before merging
4. **Feedback**: Address any feedback or requested changes
5. **Merge**: Once approved, changes will be merged

## IP List Verification

Before adding IPs to blocklists, verify through:

### Recommended Sources

- **Malware**: abuse.ch, VirusTotal, Talos Intelligence
- **Botnets**: Spamhaus, Feodo Tracker
- **Abuse**: AbuseIPDB, StopForumSpam
- **Tor**: Official Tor Project lists

### Verification Methods

1. Check multiple threat intelligence sources
2. Verify IP reputation on VirusTotal
3. Check WHOIS information
4. Review recent activity logs
5. Confirm with abuse databases

### Source Attribution

Always include source information in comments:

```
# Source: abuse.ch Feodo Tracker
# Date: 2025-12-22
# Description: Dridex C2 servers
192.0.2.10
```

## Maintenance

### Regular Updates

IP lists should be updated regularly:

- **Critical threats**: Daily or as discovered
- **Malware/Botnets**: Weekly
- **Abuse lists**: Weekly to monthly
- **Allowlists**: As providers update

### Deprecation

Remove IPs when:
- No longer active threats
- False positive confirmed
- IP reassigned to legitimate use
- Source no longer maintained

### Version Control

- Use semantic versioning for major changes
- Tag releases for significant updates
- Maintain changelog

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Review closed issues for similar questions
3. Open a new issue with your question
4. Be patient and respectful

## License

By contributing to IP-Security, you agree that your contributions will be licensed under the GNU General Public License v3.0.

---

Thank you for helping make the internet safer! 🛡️
