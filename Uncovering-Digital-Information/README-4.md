# Uncovering-Digital-Information-for-Security-Analysis-Using-Footprinting-Reconnaissance-and-Scanning

# A systematic OSINT and reconnaissance workflow to gather critical information about a simulated target for pre-exploitation analysis.
Overview
This project focuses on performing structured footprinting and reconnaissance against a simulated target environment. The goal was to gather actionable intelligence, map the attack surface, and prepare for deeper penetration testing.
The assessment mirrors early-stage workflows used by red teams, penetration testers, and threat actors when profiling an organization.

# Objectives
• Perform passive and active reconnaissance
• Identify exposed services, technologies, and metadata
• Analyze server fingerprints and OS information
• Conduct network scanning using industry tools
• Build an intelligence profile of the target
• Document findings that would drive exploitation strategy

# Environment
• Windows or macOS host
• Kali Linux (optional)
• Browser
• Target website provided by the school
• Tools: Netcraft, Nmap, Whois, DNS lookup, header analyzers

# Tools Used
• Netcraft
• Nmap
• WHOIS lookup
• dig / nslookup
• HTTP header analyzers
• Shodan (optional)
• Subdomain enumeration tools (optional)

# Methodology

# 1. Passive Reconnaissance
Collected non-intrusive information:
• Domain ownership and WHOIS records
• Nameserver details
• DNS records (A, AAAA, MX, NS)
• Server technology stack via HTTP headers
• SSL certificate metadata
• CDN or hosting provider information
• Netcraft fingerprinting results

# 2. Active Reconnaissance
Performed selective, controlled scanning to map the target:
• Port scanning with Nmap
• Service enumeration
• Version detection (-sV)
• OS detection (-O)
• Traceroute analysis
• Identifying open, filtered, and closed ports

# 3. Attack Surface Mapping
Built an understanding of:
• Running services (HTTP, HTTPS, SSH, etc.)
• Exposed versions and potential CVEs
• Webserver technology (Apache, NGINX, IIS)
• CMS or framework indicators
• Directory structures
• Hidden endpoints exposed through headers or error messages

# 4. OS Fingerprinting
Used a combination of:
• TCP/IP fingerprinting via Nmap
• HTTP header metadata
• SSL certificate fields
• Netcraft results when available
Some targets intentionally obfuscated their OS, which reflects realistic hardened environments.

# 5. Documentation of Findings
Captured all results in structured form:
• Domain + hosting details
• Open ports and services
• Possible vulnerabilities based on versioning
• OS fingerprint confidence
• Network topology indicators

# Key Findings
WHOIS records revealed hosting provider and registrar
DNS enumeration exposed multiple subdomains
Port scanning identified open web services
HTTP header analysis revealed server type and framework
Partial OS fingerprinting achieved via Nmap
Server misconfigurations exposed internal directory structure
SSL metadata disclosed certificate chain and CA

# Recommendations
• Harden server configuration to limit fingerprinting
• Remove unnecessary headers (Server, X-Powered-By)
• Implement strict TLS configurations
• Restrict unnecessary open ports
• Use CDN or WAF to obfuscate backend infrastructure
• Monitor DNS records for unauthorized changes

/Footprinting-Recon-Scanning
│
├── reconnaissance/
│   ├── whois.txt
│   ├── headers.txt
│   ├── dns-records.txt
│   └── netcraft-report.txt
│
├── scanning/
│   ├── nmap-basic.txt
│   ├── nmap-version.txt
│   └── nmap-os-detection.txt
│
└── README.md

# Author
Developed by Gresa Hisa (@gresium)
AI & Cybersecurity Engineer | AI & Machine Learning Specialist
GitHub: https://github.com/gresium
