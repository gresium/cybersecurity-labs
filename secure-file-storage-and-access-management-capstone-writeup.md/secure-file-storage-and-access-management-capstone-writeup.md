# Secure File Storage and Access Management for Project Teams

**Course-end Project (Capstone)**  
**Domain:** Cybersecurity / Linux Security  
**Category:** Access Control · Auditing · Monitoring  
**Environment:** Linux (Kali / Debian-based)

---

## Project Information

| Attribute | Details |
|---------|---------|
| Project Name | Secure File Storage and Access Management |
| Organization | Globex Financial |
| Focus Area | RBAC, ACLs, Auditing, Monitoring |
| Tools Used | Linux ACLs, auditd, rsyslog, Apache, PHP |
| Status | Fully Implemented & Verified |

---

## Table of Contents

1. Overview
2. Architecture & Design
3. User & Access Control Configuration
4. Command History Management
5. Auditing & Security Logging
6. Web-Based Monitoring Dashboard
7. Persistence & Reboot Verification
8. Security Outcomes & Takeaways

---

## 1. Overview

Globex Financial experienced a security incident involving unauthorized access to confidential financial files. This project implements a secure file storage and access management system to prevent unauthorized modifications, enforce accountability, and provide real-time monitoring of security violations.

The solution is built entirely on Linux using native security controls and follows industry best practices for enterprise IT and financial environments.

---

## 2. Architecture & Design

**Core Components:**
- Role-Based Access Control (RBAC) using Linux users and groups
- Access Control Lists (ACLs) for fine-grained file permissions
- Command history enforcement for audit compliance
- `auditd` for monitoring unauthorized access attempts
- `rsyslog` for centralized security logging
- Apache + PHP dashboard for real-time visibility

**Protected Resources:**
- `/data/projectA`
- `/data/projectB`

---

## 3. User & Access Control Configuration

### Directory Permissions

Project directories were configured so that:
- File owners have full control
- Authorized users have read-only access
- Unauthorized users are denied access

```bash
setfacl -m g:projectA:r-- /data/projectA
setfacl -m g:projectB:r-- /data/projectB
```

Default ACLs ensure new files inherit the same security policy.

---

## 4. Command History Management

To support auditing and compliance requirements, command history limits were enforced:

- **Senior analysts:** last 10 commands
- **Other users:** last 50 commands

```bash
export HISTSIZE=10
export HISTFILESIZE=10
```

These settings are applied per user and persist across reboots.

---

## 5. Auditing & Security Logging

### Audit Rules

Unauthorized write and attribute-change attempts on protected directories are monitored using `auditd`:

```bash
auditctl -w /data/projectA -p wa -k project_access
auditctl -w /data/projectB -p wa -k project_access
```

### Centralized Logging

Audit events are forwarded to a dedicated log file using `rsyslog`:

```
/var/log/security_violations.log
```

This enables forensic analysis and long-term retention for IT security teams.

---

## 6. Web-Based Monitoring Dashboard

A lightweight monitoring dashboard was developed using **Apache** and **PHP**.

### Features
- Displays security violations in real time
- Read-only access to logs
- Minimal attack surface

```php
<?php
echo "<h2>Globex Financial - Security Violations</h2>";
echo "<pre>";
system("cat /var/log/security_violations.log");
echo "</pre>";
?>
```

Dashboard URL:
```
http://localhost/security.php
```

---

## 7. Persistence & Reboot Verification

All configurations were verified to persist after system reboots:

- Apache enabled and running
- Audit rules reloaded
- ACLs retained
- Dashboard accessible

```bash
systemctl status apache2
auditctl -l
```

---

## 8. Security Outcomes & Takeaways

- Fine-grained ACLs effectively prevent unauthorized file modifications
- Audit logging provides accountability and traceability
- Centralized logs simplify incident response and compliance
- Web-based dashboards improve operational visibility

---

## Conclusion

This project demonstrates a practical, enterprise-ready approach to secure file management using native Linux security mechanisms. The solution addresses real-world threats in financial environments by combining prevention, detection, and monitoring into a cohesive security architecture.

---

**Author**  
Developed by Gresa Hisa (@gresium) — AI & Cybersecurity Engineer | AI & Machine Learning Specialist  
GitHub: https://github.com/gresium

