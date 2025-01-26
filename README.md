# TechStack

Key Features:

1. **Technology Detection**:
   - Wappalyzer CLI for local analysis
   - BuiltWith API for comprehensive tech stack detection
   - JSON output merging and deduplication

2. **Version Analysis**:
   - Handles version detection from multiple sources
   - Normalizes unknown versions
   - Structured data processing with jq

3. **Vulnerability Correlation**:
   - NVD API integration for CVE lookup
   - Exploit-DB integration via searchsploit
   - Nuclei template matching
   - Automated CVE/exploit correlation

4. **Reporting**:
   - Markdown report generation
   - Consolidated findings from multiple sources
   - Prioritized high/medium severity findings
   - Cross-referenced vulnerability databases

Usage:
1. Install dependencies:
```bash
npm install -g wappalyzer
sudo apt install jq exploitdb
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

2. Get API keys from:
   - BuiltWith: https://builtwith.com
   - NVD: https://nvd.nist.gov/developers

3. Run the script:
```bash
./tech_auditor.sh example.com
```

Sample Report Output:
```
# Technology Audit Report for example.com

## Detected Technologies
- Nginx 1.18.0
- PHP 7.4.3
- WordPress 5.7.2

## Vulnerability Findings

### Nginx
**NVD CVEs (2):**
CVE-2021-23017
CVE-2020-12400

**Exploit-DB Entries (1):**
/usr/share/exploitdb/exploits/linux/dos/48130.c

### PHP
**NVD CVEs (3):**
CVE-2021-21703
CVE-2020-7064
CVE-2020-7059

**Nuclei Findings:**
[php-version] [http] [info] https://example.com
```

This script provides a comprehensive approach to:
1. Identify technologies and versions
2. Cross-reference with multiple vulnerability databases
3. Generate actionable security reports
4. Prioritize findings based on exploit availability and severity

Note: Always comply with target website's robots.txt and terms of service. Use API keys responsibly and respect rate limits.