# Recon-AI

A streamlined attack surface and subdomain enumeration script for pentesters, powered by tools like Subfinder, Nuclei, httpx, and an AI assistant (Mistral via Ollama).

[![asciicast](https://asciinema.org/a/730482.svg)](https://asciinema.org/a/730482)

## Features

- Subdomain enumeration with Subfinder
- Technology fingerprinting using httpx
- Nuclei vulnerability scanning (with optional -code support)
- Shodan integration (optional)
- LLM-assisted analysis via Mistral/Ollama

## Requirements

### Core Dependencies
```bash
# Install Go-based security tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install system utilities
sudo apt update && sudo apt install -y curl git unzip jq dig
```

### AI/LLM Setup
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull Mistral model (or any other model)
ollama pull mistral
```

## Configuration

### Optional: Shodan Integration
To enable IP intelligence gathering via Shodan:

1. Get your API key from [https://account.shodan.io/](https://account.shodan.io/)
2. Export it as an environment variable:

```bash
export SHODAN_API_KEY="your-api-key-here"
```

Or add it to your shell profile:
```bash
echo 'export SHODAN_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### Nuclei Templates
Update Nuclei templates before first use:
```bash
nuclei -ut
```

## Usage

### Basic Scan
```bash
./recon-ai.sh target-domain.com
```

### With Shodan Integration
```bash
export SHODAN_API_KEY="your-api-key"
./recon-ai.sh target-domain.com
```

### What the Script Does

The script performs the following steps automatically:

1. **Domain Validation** - Validates input format to prevent command injection
2. **Subdomain Enumeration** - Discovers subdomains using Subfinder (timeout: 5 min)
3. **Active Host Filtering** - Tests which subdomains are actually alive (2-3x performance boost)
4. **Technology Fingerprinting** - Detects web technologies, frameworks, and versions
5. **HTTP Headers Collection** - Gathers security headers and server information
6. **Vulnerability Scanning** - Runs Nuclei templates against active hosts (timeout: 10 min)
7. **IP Deduplication & Shodan** - Queries unique IPs for additional intelligence (if configured)
8. **AI Analysis** - Sends data to LLM for structured security analysis
9. **Report Generation** - Creates JSON report with findings and recommendations

### Security Features

- ✅ Domain input validation (prevents command injection)
- ✅ SSL certificate verification enabled
- ✅ Restrictive file permissions (600/700) on all outputs
- ✅ Timeout protection on all external commands
- ✅ Automatic deduplication to minimize API usage

## Output Structure

After a successful scan, results are organized in `data/target-domain.com/`:

```
data/
└── target-domain.com/
    ├── subdomains_raw.txt          # All discovered subdomains
    ├── subdomains.txt              # Cleaned/validated subdomains
    ├── alive_subdomains.txt        # Active hosts only
    ├── alive_urls.txt              # Full URLs of active hosts
    ├── unique_ips.txt              # Deduplicated IP addresses
    ├── tech.txt                    # Technology detection (JSON)
    ├── tech_summary.tsv            # Technology summary (TSV)
    ├── headers_summary.txt         # Security headers summary
    ├── analysis.txt                # LLM analysis (raw output)
    ├── analysis.json               # Structured JSON report
    ├── prompt.txt                  # LLM prompt used
    ├── headers/
    │   └── *.txt                   # Individual host headers
    ├── nuclei/
    │   └── output.txt              # Nuclei vulnerability findings
    └── shodan/                     # (if configured)
        └── *.json                  # Shodan data per IP
```

### Key Files

| File | Description | Format |
|------|-------------|--------|
| `analysis.json` | **Main Report** - Structured security analysis with risk scores, findings, and recommendations | JSON |
| `nuclei/output.txt` | Vulnerability scan results with severity levels | Text |
| `alive_subdomains.txt` | List of responsive subdomains (useful for further testing) | Text |
| `tech.txt` | Detailed technology fingerprinting data | JSONL |
| `unique_ips.txt` | Deduplicated IPs (useful for network-level scanning) | Text |

## Example Output

### Console Output (Summary Metrics)

```
==========================================
           SCAN SUMMARY METRICS
==========================================
Domain: example.com
Scan Date: 2025-10-27 15:30:42
------------------------------------------
Subdomains discovered: 124
Active subdomains: 45
Inactive subdomains: 79
Unique IP addresses: 12
------------------------------------------
Nuclei Findings:
  Critical: 3
  High: 8
  Medium: 15
  Low: 22
  Total: 48
------------------------------------------
Technologies detected: 23
==========================================
[+] Full results in: data/example.com/
[+] Analysis report: data/example.com/analysis.txt
```

### JSON Analysis Report Structure

The `analysis.json` file contains a structured report:

```json
{
  "executive_summary": "The target shows moderate security posture with several high-priority vulnerabilities...",
  "risk_score": 7.5,
  "critical_findings": [
    {
      "title": "Exposed Admin Panel",
      "severity": "critical",
      "description": "Admin interface accessible without authentication",
      "affected_hosts": ["admin.example.com"],
      "exploitation_difficulty": "easy",
      "recommended_action": "Implement authentication and restrict access by IP"
    }
  ],
  "attack_vectors": [
    {
      "vector": "Web Application Vulnerabilities",
      "priority": 9,
      "entry_points": ["admin.example.com", "api.example.com"],
      "prerequisites": "Network access to target",
      "impact": "Full system compromise possible"
    }
  ],
  "technology_risks": {
    "outdated_technologies": ["Apache 2.4.29", "PHP 7.2"],
    "misconfigured_services": ["Missing HSTS", "Weak TLS configuration"],
    "missing_security_headers": ["www.example.com: CSP", "api.example.com: X-Frame-Options"]
  },
  "manual_verification_steps": [
    "1. Manually test admin panel authentication bypass",
    "2. Check for SQL injection in search parameters",
    "3. Verify API endpoints for broken access control"
  ],
  "next_actions": {
    "immediate": [
      "Secure admin panel with strong authentication",
      "Patch critical Apache vulnerabilities"
    ],
    "short_term": [
      "Implement security headers across all subdomains",
      "Update PHP to supported version"
    ],
    "long_term": [
      "Implement WAF for additional protection",
      "Establish vulnerability management program"
    ]
  }
}
```

### During Execution

```
[*] Enumerating subdomains with subfinder...
[*] Filtering active subdomains...
[+] Found 45 active subdomains out of 124 total
[*] Fingerprinting technologies with httpx...
[*] Collecting HTTP headers in parallel...
[*] Running Nuclei scan...
[*] Resolving IPs and deduplicating...
[+] Querying Shodan for 12 unique IPs...
[*] Creating LLM prompt...
[*] Sending prompt to mistral via Ollama...
[*] Securing sensitive files...
[+] JSON analysis validated and formatted
```
