# Securing-the-Digital-Marketplace-Strengthening-Security-for-a-Vulnerable-E-Commerce-Website

# A full security assessment of a simulated online marketplace, identifying critical flaws and implementing strategic mitigation recommendations.
Overview
This project focuses on analyzing and securing a deliberately vulnerable e-commerce website mimicking real-world retail platforms. The environment exposes common weaknesses found in modern web applications, enabling hands-on security testing and remediation planning.

# The assessment followed a structured VAPT methodology: reconnaissance, vulnerability discovery, exploitation validation, and security hardening recommendations.

# Objectives
• Evaluate the security posture of a vulnerable digital marketplace
• Identify misconfigurations and insecure coding practices
• Validate flaws through controlled exploitation
• Document vulnerabilities aligned with OWASP Top 10
• Produce actionable recommendations to strengthen platform security

# Environment
• Vulnerable E-Commerce VM (OVA imported locally)
• Web browser
• Burp Suite
• Kali Linux (optional for deeper enumeration)
• NAT networking

# Tools Used
• Burp Suite Community
• Nmap
• Gobuster / directory brute-forcing
• Browser DevTools
• Parameter tampering tools
• Wordlists

# Methodology

# 1. Surface Mapping
• Identified storefront, login, signup, and cart APIs
• Enumerated product endpoints
• Located hidden admin features
• Mapped HTTP request flows used for checkout

# 2. Vulnerability Discovery
Observed multiple weaknesses including:
• Weak authentication mechanisms
• Missing CSRF protection
• Exposed admin directories
• Price manipulation vulnerabilities in API requests
• Insecure session management
• Verbose server error messages
• Hardcoded API keys in client-side scripts

# 3. Exploitation & Validation
Executed controlled exploitation to validate risks:
• Modified cart price values via Burp
• Forced browsing into admin-only sections
• Manipulated user IDs and product IDs (IDOR)
• Changed request parameters to bypass role restrictions
• Accessed unprotected API endpoints returning sensitive data

# 4. Flag Discovery
Several flags were embedded through insecure endpoints, misconfigured routes, and predictable directory names.
Retrieved flags through:
• API response inspection
• Hidden directories
• Broken access control
• Burp request replay
• Front-end script analysis
5. Security Hardening Recommendations

# High-priority remediation steps:
• Implement strong server-side validation for all fields
• Enforce RBAC and strict access controls
• Remove debugging endpoints from production builds
• Hash and store credentials securely
• Implement CSRF tokens for all state-changing requests
• Use secure cookies with HttpOnly and Secure flags
• Disable directory listing
• Minimize client-side exposure of secrets

# Key Findings
Critical: Price manipulation via modified API parameters
Critical: IDOR allowing access to other customer data
High: Unprotected admin panel with predictable URL
High: Weak session tokens
Medium: Verbose error messages leaking system details
Low: Outdated JavaScript libraries with known CVEs

Author
Developed by Gresa Hisa (@gresium)
AI & Cybersecurity Engineer
GitHub: https://github.com/gresium
