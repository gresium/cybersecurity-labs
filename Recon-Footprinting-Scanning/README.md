# Ethical Hacking: Reconnaissance, Footprinting & Scanning
Target: securedefense.ch

# Objective
Perform a structured reconnaissance and early-stage penetration test against a legally owned target (securedefense.ch). The goal is to map the attack surface using WHOIS, DNS enumeration, OSINT, subdomain discovery, and Nmap scanning. All tests were performed against the student-owned domain.
Scope

# Activities included:
• WHOIS profiling
• DNS and DNSSEC validation
• OSINT dorking
• Subdomain enumeration
• Recon-ng automation
• Nmap TCP/Version scanning
• Attack surface analysis

# 1. WHOIS Intelligence
Command:
whois securedefense.ch
Findings:
• Registrar: Hostpoint AG (CH)
• Nameservers: Cloudflare (gracie, ed)
• DNSSEC: Not enabled
• First Registration: 18 Nov 2025
Interpretation:
Cloudflare is correctly masking origin infrastructure. No registry-level leaks.

# 2. DNS Enumeration
A/AAAA Records
nslookup securedefense.ch
Returned Cloudflare IPv4 + IPv6 edge proxies.
No backend IP leakage.
ANY Lookup
dig securedefense.ch ANY
Only NS and A records. No misconfigured zones.
AXFR Attempt
dig AXFR securedefense.ch @ed.ns.cloudflare.com
Zone transfer correctly blocked.

# 3. OSINT Exposure Check
Google dorks used:
site:securedefense.ch
site:securedefense.ch inurl:login
site:securedefense.ch "index of"
site:securedefense.ch ext:sql
site:securedefense.ch ext:env
"@securedefense.ch"
Result: No exposed admin panels, no sensitive files, no email leaks.
Attack surface extremely minimal.

# 4. Subdomain Enumeration
Using nslookup, dig, Cloudflare DNS, and recon-ng.
Recon-ng module:
recon/domains-hosts/google_site_web
Result: Zero public subdomains.
Clean domain. No shadow assets.

# 5. Nmap Scanning
Command:
nmap 104.21.89.140
Open Ports:
• 80 (HTTP) – Cloudflare proxy
• 443 (HTTPS) – Cloudflare TLS termination
• 8080, 8443 – Alternative Cloudflare HTTP/S endpoints
Aggressive Scan (nmap -A securedefense.ch):
• OS detection impossible behind Cloudflare
• Traceroute terminates at Cloudflare edge
• No origin fingerprinting possible
Interpretation:
Origin server is fully shielded. Correct security posture.

# 6. Security Assessment Summary
Strengths
✔ Cloudflare WAF, proxy, and DDoS protection
✔ No OSINT exposure
✔ No exposed subdomains
✔ DNS zone transfer blocked
✔ Standard ports only
✔ Origin IP hidden
✔ Clean, low-risk footprint

# Weaknesses / Improvements
• DNSSEC is disabled (enable it for integrity validation)
• Add missing security headers (HSTS, CSP, X-Frame-Options)
• Enable Cloudflare features:
Bot Fight Mode
Rate limiting
WAF rules
Zero Trust policies

# Conclusion
The recon assessment confirms that securedefense.ch is hardened, minimal, and well-protected. The domain sits behind Cloudflare, exposes only edge nodes, leaks no sensitive OSINT, blocks DNS zone transfers, and maintains an extremely small attack surface.
This project demonstrates proficiency in:
• Footprinting and OSINT
• DNS and WHOIS intelligence
• Subdomain enumeration
• Nmap network scanning
• Recon-ng automation
• Attack surface analysis

# Author
Developed by Gresa Hisa (@gresium)
AI & Cybersecurity Engineer | AI & Machine Learning Specialist
GitHub: https://github.com/gresium
