# Implementing-Enumeration-for-Network-and-User-Discovery

A comprehensive enumeration engagement using industry-standard tools to identify network
services, system users, exposed shares, and potential attack vectors.

# Overview
This project focuses on active enumeration, the critical phase that bridges reconnaissance and exploitation. Enumeration reveals detailed information about systems, users, services, and configurations that attackers can leverage for privilege escalation or lateral movement.
You executed targeted enumeration against a simulated environment, uncovering services, users, shares, and system details in preparation for exploitation.

# Objectives
• Enumerate open ports and service versions
• Identify exposed network services and their configurations
• Extract user information where available
• Discover network shares and accessible resources
• Build a complete system profile for exploitation readiness
• Document actionable findings

# Environment
• Kali Linux or Windows host
• Simulated lab environment/VM
• Tools: Nmap, enum4linux, SMB utilities, SNMP enumeration tools

# Tools Used
• Nmap (service enumeration, scripts)
• enum4linux / enum4linux-ng
• SMBclient
• SNMPwalk (optional)
• Netcat
• RPCClient
• Netdiscover
• Linux built-ins (ping, traceroute, dig)

# Methodology

# 1. Host Discovery
• Identified active hosts on the local subnet
• Used ARP-based scanning and ICMP probes
• Verified target accessibility for deeper enumeration

# 2. Port & Service Enumeration
Performed detailed Nmap enumeration:
• Port scanning (TCP/UDP)
• Service detection (-sV)
• OS fingerprinting attempts (-O)
• Nmap scripting engine (NSE) for authentication and SMB checks
Captured key exposed services:
• HTTP/HTTPS
• SSH
• SMB
• RPC
• Additional ports depending on the VM configuration

# 3. SMB & RPC Enumeration
Querying SMB services to extract system and domain data:
• Enumerated users (RID cycling)
• Enumerated groups
• Identified shared folders
• Accessed unprotected shares
• Investigated share permissions
• Queried RPC endpoints for machine details

# 4. SNMP Enumeration (If Enabled)
Used SNMPwalk to extract:
• System information
• Installed software
• Network interface lists
• Potential credentials or misconfigurations

# 5. Service Misconfiguration Analysis
Examined all discovered services for weaknesses such as:
• Anonymous SMB access
• Default credentials
• Outdated software with known CVEs
• Verbose SSH banners
• Visible directory listings in HTTP

# 6. Attack Surface Mapping
Consolidated all enumeration results into a structured profile:
• Identified which services are exploitable
• Prioritized ports for exploitation
• Confirmed which misconfigurations enable privilege escalation

# Key Findings
SMB allowed partial anonymous enumeration
User accounts could be enumerated via RID cycling
RPC endpoints leaked system metadata
Several open ports revealed outdated service versions
Webserver exposed directories and sensitive metadata
OS fingerprinting possible through Nmap and SMB responses

# Recommendations
• Disable anonymous SMB access
• Implement strict share permissions
• Hide or restrict RPC endpoint data
• Update outdated services
• Sanitize banners and server headers
• Implement segmentation to limit enumeration exposure

# Project Structure
/Network-User-Enumeration
│
├── host-discovery/
│   ├── netdiscover.txt
│   └── ping-sweep.txt
│
├── nmap/
│   ├── basic-scan.txt
│   ├── service-scan.txt
│   ├── os-scan.txt
│   └── nse-scripts.txt
│
├── smb/
│   ├── enum4linux-output.txt
│   ├── shares.txt
│   └── users.txt
│
├── rpc/
│   ├── rpc-info.txt
│   └── rpc-enumeration-results.txt
│
└── README.md


# Author
Developed by Gresa Hisa (@gresium)
AI & Cybersecurity Engineer
GitHub: https://github.com/gresium
